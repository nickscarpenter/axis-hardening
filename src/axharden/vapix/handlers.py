"""Handler-based controls (non-param reads). Read-only in phase 1.

Every network read goes through ctx.probe(key, fn) so it is recorded in the run snapshot
and can be replayed in --simulate mode.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Callable

from ..catalog import Control
from ..evaluate import (COMPLIANT, ERROR, INFO, NA, NON_COMPLIANT, NOT_SUPPORTED, AuditContext,
                        ControlResult)
from ..version import v
from .client import CameraError

Handler = Callable[[Control, AuditContext], ControlResult]
HANDLERS: dict[str, Handler] = {}


def handler(name: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        HANDLERS[name] = fn
        return fn
    return deco


# ---------------------------------------------------------------- probe helpers

def http_get(ctx: AuditContext, path: str) -> dict:
    """Authenticated GET that records status + body. Non-200 statuses are data, not errors."""
    def live() -> dict:
        try:
            r = ctx.client.get(path, ok_statuses=(200, 204, 400, 404, 405, 500, 501))
            return {"status": r.status_code, "text": r.text[:200_000]}
        except CameraError as e:
            if e.code == "AUTH_FAILED":
                raise
            return {"status": getattr(e, "status", None), "error": str(e)}
    return ctx.probe(f"GET {path}", live)


def _pwdgrp(ctx: AuditContext) -> dict[str, list[str]]:
    res = http_get(ctx, "/axis-cgi/pwdgrp.cgi?action=get")
    if res.get("status") != 200:
        raise CameraError(f"pwdgrp.cgi returned {res.get('status')}")
    groups: dict[str, list[str]] = {}
    for line in res["text"].splitlines():
        m = re.match(r'^\s*([\w-]+)="(.*)"\s*$', line)
        if m:
            groups[m.group(1)] = [x for x in m.group(2).split(",") if x]
    return groups


def _https_only(ctx: AuditContext) -> bool:
    vals = [ctx.params.get(f"root.System.BoaGroupPolicy.{g}") for g in ("admin", "operator", "viewer")]
    return all(x is not None and x.lower() == "https" for x in vals)


# ---------------------------------------------------------------- APPLY-control readers

@handler("applications_config")
def applications_config(ctl: Control, ctx: AuditContext) -> ControlResult:
    name = ctl.handler_args["name"]
    want = str(ctl.handler_args.get("hardened", "false")).lower()
    res = http_get(ctx, f"/axis-cgi/applications/config.cgi?action=get&name={name}")
    status = res.get("status")
    if status in (404, 501):
        return ControlResult(ctl.id, NOT_SUPPORTED, {name: None},
                             "applications/config.cgi not available on this firmware.")
    if status != 200:
        return ControlResult(ctl.id, ERROR, {name: None}, f"HTTP {status}: {res.get('error', '')}".strip(": "))
    text = res["text"]
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), text, re.I) or \
        re.search(r'%s\s*=\s*"?(\w+)' % re.escape(name), text, re.I)
    if not m:
        return ControlResult(ctl.id, ERROR, {name: None}, f"Could not parse reply: {text[:120]!r}")
    value = m.group(1)
    ok = value.lower() == want
    return ControlResult(ctl.id, COMPLIANT if ok else NON_COMPLIANT, {name: value},
                         "" if ok else f"{name}={value} (want {want})")


@handler("network_ports")
def network_ports(ctl: Control, ctx: AuditContext) -> ControlResult:
    if not ctx.camera.ports:
        return ControlResult(ctl.id, NA, {}, "No unused network ports listed for this camera in the inventory.")
    return ControlResult(ctl.id, INFO, {"ports": ctx.camera.ports},
                         "Port controls are evaluated in phase 3; ports listed: "
                         + ", ".join(map(str, ctx.camera.ports)))


@handler("sd_disk")
def sd_disk(ctl: Control, ctx: AuditContext) -> ControlResult:
    want = str(ctl.handler_args.get("hardened", "no")).lower()
    # Prefer an explicit SDDiskEnabled param if the firmware has one.
    explicit = list(ctx.params.match("root.Storage.*SDDiskEnabled"))
    if explicit:
        bad = [f"{k}={val}" for k, val in explicit if val.lower() != want]
        return ControlResult(ctl.id, NON_COMPLIANT if bad else COMPLIANT, dict(explicit), "; ".join(bad))
    observed: dict[str, Any] = {}
    for key, disk_id in ctx.params.match("root.Storage.S*.DiskID"):
        if disk_id.upper() == "SD_DISK":
            en_key = key.rsplit(".", 1)[0] + ".Enabled"
            observed[en_key] = ctx.params.get(en_key)
    if not observed:
        return ControlResult(ctl.id, NA, {}, "No SD card slot found.")
    bad = [f"{k}={val}" for k, val in observed.items() if (val or "").lower() != want]
    return ControlResult(ctl.id, NON_COMPLIANT if bad else COMPLIANT, observed,
                         ("SD card slot enabled: " + "; ".join(bad)) if bad else "")


@handler("anon_device_info")
def anon_device_info(ctl: Control, ctx: AuditContext) -> ControlResult:
    res = http_get(ctx, "/config/rest/basic-device-info/v2beta/allowAnonymous")
    if res.get("status") in (404, 501):
        return ControlResult(ctl.id, NOT_SUPPORTED, {}, "basic-device-info v2beta API not available.")
    if res.get("status") != 200:
        return ControlResult(ctl.id, ERROR, {}, f"HTTP {res.get('status')}")
    import json
    try:
        value = json.loads(res["text"]).get("data")
    except ValueError:
        return ControlResult(ctl.id, ERROR, {}, "Unparseable JSON reply")
    return ControlResult(ctl.id, COMPLIANT if value is False else NON_COMPLIANT, {"allowAnonymous": value},
                         "" if value is False else f"allowAnonymous={value}")


# ---------------------------------------------------------------- CHECK controls

@handler("os_version")
def os_version(ctl: Control, ctx: AuditContext) -> ControlResult:
    ver = ctx.version
    if ver is None:
        return ControlResult(ctl.id, ERROR, {}, "Could not read AXIS OS version.")
    minimum = v(str(ctl.handler_args.get("min_axis_os", "10.0")))
    observed = {"version": str(ver), "track": ver.track, "minimum": str(minimum)}
    if ver < minimum:
        return ControlResult(ctl.id, NON_COMPLIANT, observed, f"AXIS OS {ver} is below the site minimum {minimum}.")
    return ControlResult(ctl.id, INFO, observed,
                         f"AXIS OS {ver} ({ver.track} track). Confirm it is the latest LTS/active release offline.")


@handler("auth_policy")
def auth_policy(ctl: Control, ctx: AuditContext) -> ControlResult:
    policy = ctx.params.get("root.Network.HTTP.AuthenticationPolicy")
    https_only = _https_only(ctx)
    observed = {"AuthenticationPolicy": policy, "https_only": https_only}
    if policy is None:
        return ControlResult(ctl.id, NOT_SUPPORTED, observed, "AuthenticationPolicy parameter not present.")
    p = policy.lower()
    if "basic" in p and not https_only:
        return ControlResult(ctl.id, NON_COMPLIANT, observed,
                             f"Policy '{policy}' allows Basic auth while plain HTTP is enabled (guide p.5).")
    return ControlResult(ctl.id, COMPLIANT, observed,
                         "Digest authentication." if p == "digest" else f"Policy '{policy}' with HTTPS only.")


@handler("http_redirect")
def http_redirect(ctl: Control, ctx: AuditContext) -> ControlResult:
    def live() -> dict:
        return ctx.client.http80()

    res = ctx.probe("HTTP80 /", live)
    status, loc = res.get("status"), (res.get("location") or "")
    if status is None:
        return ControlResult(ctl.id, COMPLIANT, res, "Plain HTTP is not reachable.")
    if status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        return ControlResult(ctl.id, COMPLIANT, res, "Plain HTTP redirects to HTTPS.")
    return ControlResult(ctl.id, NON_COMPLIANT, res, f"Plain HTTP answered with HTTP {status}.")


@handler("certificate")
def certificate(ctl: Control, ctx: AuditContext) -> ControlResult:
    res = ctx.probe("TLS cert", lambda: ctx.client.fetch_cert())
    if "error" in res:
        return ControlResult(ctl.id, ERROR, res, f"TLS handshake failed: {res['error']}")
    issuer, subject = res.get("issuer", {}), res.get("subject", {})
    issuer_text = ", ".join(f"{k}={val}" for k, val in issuer.items())
    observed = {"issuer": issuer_text, "notAfter": res.get("notAfter"), "tls_version": res.get("tls_version")}
    org = (issuer.get("organizationName", "") + " " + issuer.get("commonName", "")).lower()
    if issuer == subject:
        return ControlResult(ctl.id, NON_COMPLIANT, observed, "Self-signed certificate. Replace with a CA-signed one (p.24).")
    if "axis" in org:
        return ControlResult(ctl.id, INFO, observed,
                             "Axis-issued certificate (802.1AR device ID). Acceptable; a site CA-signed certificate is best (p.24).")
    return ControlResult(ctl.id, COMPLIANT, observed, "CA-signed certificate.")


@handler("ntp")
def ntp(ctl: Control, ctx: AuditContext) -> ControlResult:
    p = ctx.params
    servers = [s for key, s in p.match("root.Time.NTP.*Server*") if s and s not in ("0.0.0.0", "::")]
    dhcp_time = (p.get("root.Time.ObtainFromDHCP") or "").lower() == "yes"
    dhcp_net = (p.get("root.Network.BootProto") or "").lower() == "dhcp"
    nts = [f"{k}={val}" for k, val in p.match("root.Time.*NTS*")]
    observed = {"servers": servers, "ObtainFromDHCP": p.get("root.Time.ObtainFromDHCP"),
                "BootProto": p.get("root.Network.BootProto"), "SyncSource": p.get("root.Time.SyncSource")}
    if nts:
        observed["nts"] = nts
    if not p.group("root.Time"):
        return ControlResult(ctl.id, NOT_SUPPORTED, observed, "No Time parameters; check the time API manually.")
    if servers:
        note = "" if len(set(servers)) >= 2 else " Guide recommends at least two time servers."
        return ControlResult(ctl.id, COMPLIANT, observed, f"{len(set(servers))} NTP server(s) configured.{note}")
    if dhcp_time and dhcp_net:
        return ControlResult(ctl.id, INFO, observed, "Time server comes from DHCP; confirm the DHCP server supplies one.")
    if dhcp_time and not dhcp_net:
        return ControlResult(ctl.id, NON_COMPLIANT, observed,
                             "Set to take NTP from DHCP, but the camera has a static IP, so no time server is configured.")
    return ControlResult(ctl.id, NON_COMPLIANT, observed, "No NTP server configured.")


@handler("syslog")
def syslog(ctl: Control, ctx: AuditContext) -> ControlResult:
    params = ctx.params.group("root.RemoteSyslog")
    if params:
        enabled = any(k.lower().endswith("enabled") and val.lower() == "yes" for k, val in params.items())
        return ControlResult(ctl.id, COMPLIANT if enabled else NON_COMPLIANT, params,
                             "" if enabled else "Remote syslog not enabled.")
    if "remote-syslog" in ctx.api_ids:
        return ControlResult(ctl.id, INFO, {"api": "remote-syslog"},
                             "Remote syslog API present; check the target and TLS setting manually (System > Logs).")
    return ControlResult(ctl.id, INFO, {}, "Remote syslog configuration could not be read; check manually.")


@handler("snmp")
def snmp(ctl: Control, ctx: AuditContext) -> ControlResult:
    p = ctx.params
    enabled = p.get("root.SNMP.Enabled")
    observed = {k: p.get(f"root.SNMP.{k}") for k in ("Enabled", "V1", "V2c", "V3")}
    if enabled is None:
        return ControlResult(ctl.id, NOT_SUPPORTED, observed, "No SNMP parameters.")
    if enabled.lower() != "yes":
        return ControlResult(ctl.id, COMPLIANT, observed, "SNMP disabled.")
    weak = [k for k in ("V1", "V2c") if (observed.get(k) or "").lower() == "yes"]
    if weak:
        return ControlResult(ctl.id, NON_COMPLIANT, observed, f"Insecure SNMP versions enabled: {', '.join(weak)} (p.25).")
    return ControlResult(ctl.id, COMPLIANT, observed, "SNMPv3 only.")


@handler("rtsps")
def rtsps(ctl: Control, ctx: AuditContext) -> ControlResult:
    val = ctx.params.get("root.Network.RTSPS.Enabled")
    if val is None:
        return ControlResult(ctl.id, NOT_SUPPORTED, {}, "RTSPS parameter not present.")
    if val.lower() == "yes":
        return ControlResult(ctl.id, COMPLIANT, {"RTSPS.Enabled": val})
    return ControlResult(ctl.id, INFO, {"RTSPS.Enabled": val},
                         "RTSPS/SRTP disabled. Enable it if the VMS supports it (advisory, p.25).")


@handler("network_filter")
def network_filter(ctl: Control, ctx: AuditContext) -> ControlResult:
    ver = ctx.version
    if ver is not None and ver >= v("11.9"):
        return ControlResult(ctl.id, INFO, {}, "AXIS OS 11.9+: check the host firewall manually (System > Security > "
                             "Firewall): default policy Drop with VMS and admin clients allowed. Never changed by this tool.")
    p = ctx.params
    observed = {"Enabled": p.get("root.Network.Filter.Enabled"), "Policy": p.get("root.Network.Filter.Input.Policy"),
                "AcceptAddresses": p.get("root.Network.Filter.Input.AcceptAddresses")}
    if observed["Enabled"] is None:
        return ControlResult(ctl.id, NOT_SUPPORTED, observed, "IP filter parameters not present.")
    if observed["Enabled"].lower() != "yes":
        return ControlResult(ctl.id, NON_COMPLIANT, observed, "IP address filter disabled. Never changed by this tool (lock-out risk).")
    if (observed["Policy"] or "").lower() == "allow" and not observed["AcceptAddresses"]:
        return ControlResult(ctl.id, NON_COMPLIANT, observed, "Filter enabled but has no address list.")
    return ControlResult(ctl.id, COMPLIANT, observed, "IP address filter enabled.")


@handler("dot1x")
def dot1x(ctl: Control, ctx: AuditContext) -> ControlResult:
    found = {k: val for k, val in ctx.params.match("root.Network.*dot1x*.Enabled")}
    found.update({k: val for k, val in ctx.params.match("root.Network.*IEEE8021X*.Enabled")})
    if not found:
        return ControlResult(ctl.id, INFO, {}, "802.1X settings not in the parameter tree; check System > Security > IEEE 802.1X.")
    on = any(val.lower() == "yes" for val in found.values())
    status = {k: val for k, val in ctx.params.match("root.Network.*dot1x.Status")}
    found.update(status)
    detail = f"802.1X {'enabled' if on else 'disabled'} (report only)."
    if on and status:
        detail += " Port status: " + ", ".join(status.values()) + "."
    return ControlResult(ctl.id, INFO, found, detail)


@handler("signed_video")
def signed_video(ctl: Control, ctx: AuditContext) -> ControlResult:
    found = dict(ctx.params.match("root.Image.I*.SignedVideo.Enabled"))
    if found:
        off = [k for k, val in found.items() if val.lower() != "yes"]
        return ControlResult(ctl.id, NON_COMPLIANT if off else COMPLIANT, found,
                             ("Signed video off: " + ", ".join(off)) if off else "")
    if "signed-video" in ctx.api_ids:
        return ControlResult(ctl.id, INFO, {"api": "signed-video"},
                             "Signed video API present but not in the parameter tree; check Plain config > Image manually.")
    return ControlResult(ctl.id, NOT_SUPPORTED, {}, "Signed video not supported on this device.")


@handler("sd_encryption")
def sd_encryption(ctl: Control, ctx: AuditContext) -> ControlResult:
    sd_keys = [k.rsplit(".", 1)[0] for k, did in ctx.params.match("root.Storage.S*.DiskID") if did.upper() == "SD_DISK"]
    if not sd_keys:
        return ControlResult(ctl.id, NA, {}, "No SD card slot.")
    enc = {k: val for base in sd_keys for k, val in ctx.params.match(base + ".*Encrypt*")}
    if enc:
        return ControlResult(ctl.id, INFO, enc, "Encryption settings found; confirm encryption is active if a card is used.")
    return ControlResult(ctl.id, INFO, {}, "Check System > Storage: if an SD card is used it should be encrypted (p.17).")


@handler("applications")
def applications(ctl: Control, ctx: AuditContext) -> ControlResult:
    res = http_get(ctx, "/axis-cgi/applications/list.cgi")
    if res.get("status") != 200:
        return ControlResult(ctl.id, ERROR, {}, f"applications/list.cgi returned {res.get('status')}")
    try:
        root = ET.fromstring(res["text"])
    except ET.ParseError as e:
        return ControlResult(ctl.id, ERROR, {}, f"Unparseable reply: {e}")
    apps = [{"name": a.get("NiceName") or a.get("Name"), "vendor": a.get("Vendor", ""),
             "version": a.get("Version", ""), "status": a.get("Status", "")} for a in root.iter("application")]
    third = [a["name"] for a in apps if "axis communications" not in a["vendor"].lower()]
    idle = [a["name"] for a in apps if a["status"].lower() != "running"]
    notes = [f"{len(apps)} application(s) installed."]
    if third:
        notes.append("Third-party: " + ", ".join(third) + " (ask the vendor for security proof points, p.6).")
    if idle:
        notes.append("Not running (remove if unused): " + ", ".join(idle) + ".")
    return ControlResult(ctl.id, INFO, {"applications": apps}, " ".join(notes))


@handler("users")
def users(ctl: Control, ctx: AuditContext) -> ControlResult:
    groups = _pwdgrp(ctx)
    accounts = groups.get("digusers") or groups.get("users") or []
    role = {}
    for acct in accounts:
        if acct in groups.get("admin", []):
            role[acct] = "admin"
        elif acct in groups.get("operator", []):
            role[acct] = "operator"
        elif acct in groups.get("viewer", []):
            role[acct] = "viewer"
        else:
            role[acct] = "unknown"
    observed = {"accounts": role, "anonymous_group": groups.get("anonymous", [])}
    if not accounts:
        return ControlResult(ctl.id, ERROR, observed, "Could not determine user accounts.")
    non_admin = [a for a, r in role.items() if r in ("operator", "viewer")]
    summary = ", ".join(f"{a} ({r})" for a, r in role.items())
    if not non_admin:
        return ControlResult(ctl.id, NON_COMPLIANT, observed,
                             f"Only administrator accounts: {summary}. Create a limited operator/viewer account for daily use (p.16).")
    return ControlResult(ctl.id, COMPLIANT, observed, f"Accounts: {summary}.")


@handler("lldp")
def lldp(ctl: Control, ctx: AuditContext) -> ControlResult:
    found = {k: val for k, val in ctx.params.match("root.Network.LLDP.*")}
    found.update({k: val for k, val in ctx.params.match("root.Network.CDP.*")})
    if not found:
        return ControlResult(ctl.id, INFO, {}, "LLDP/CDP settings not in the parameter tree (report only).")
    return ControlResult(ctl.id, INFO, found, "Report only. Disabling LLDP/CDP may affect PoE negotiation (p.19).")


@handler("passwords")
def passwords(ctl: Control, ctx: AuditContext) -> ControlResult:
    shared, weak = ctx.passwords.for_camera(ctx.camera.label)
    observed = {"shared_with_other_cameras": shared, "shorter_than_8": weak}
    problems = []
    if shared:
        group = next(g for g in ctx.passwords.shared_groups if ctx.camera.label in g)
        problems.append(f"Same password as {len(group) - 1} other camera(s) in this inventory")
    if weak:
        problems.append("Password shorter than 8 characters")
    if problems:
        return ControlResult(ctl.id, NON_COMPLIANT, observed, "; ".join(problems) + " (pp.16, 31).")
    return ControlResult(ctl.id, COMPLIANT, observed, "Unique within this inventory and at least 8 characters.")


@handler("manual")
def manual(ctl: Control, ctx: AuditContext) -> ControlResult:
    intro = ctl.handler_args.get("introduced_in")
    if intro and ctx.version and ctx.version < v(str(intro)):
        return ControlResult(ctl.id, NOT_SUPPORTED, {}, f"Needs AXIS OS {intro} or later.")
    return ControlResult(ctl.id, INFO, {}, ctl.handler_args.get("note", "Check manually."))
