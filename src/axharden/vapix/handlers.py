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
                         "")


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
        return ControlResult(ctl.id, COMPLIANT, observed,
                             "Axis-issued certificate (802.1AR device ID): acceptable. A certificate from your own CA is "
                             "best (p.24).")
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
    observed["raw"] = _raw(p, TIME_PARAMS)
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


TIME_PARAMS = ("root.Time.NTP.Server", "root.Time.ObtainFromDHCP", "root.Time.SyncSource", "root.Time.POSIXTimeZone",
               "root.Time.TimeZone")
NAME_DNS_PARAMS = ("root.Network.HostName", "root.Network.VolatileHostName.ObtainFromDHCP",
                   "root.Network.Resolver.ObtainFromDHCP", "root.Network.Resolver.NameServer1",
                   "root.Network.Resolver.NameServer2")


def _raw(p, names) -> dict[str, str]:
    """{camera's own spelling: value} for the names that exist (used by Fix problems to plan writes)."""
    out = {}
    for n in names:
        actual = p.actual_name(n)
        if actual is not None:
            out[actual] = p.values[actual]
    return out


NETSET_PATH = "/axis-cgi/network_settings.cgi"
RESOLVER_KEYS = ("useDhcpResolverInfo", "staticNameServers", "staticSearchDomains", "staticDomainName")


def http_post_json(ctx: AuditContext, path: str, payload: dict) -> dict:
    """Authenticated JSON POST that records status + body (replayed in simulate mode)."""
    def live() -> dict:
        try:
            r = ctx.client.post_json(path, payload, ok_statuses=(200, 400, 404, 405, 500, 501))
            return {"status": r.status_code, "text": r.text[:200_000]}
        except CameraError as e:
            if e.code == "AUTH_FAILED":
                raise
            return {"status": getattr(e, "status", None), "error": str(e)}
    return ctx.probe(f"POST {path} {payload.get('method')}", live)


def network_resolver(ctx: AuditContext) -> tuple[dict | None, str]:
    """(system.resolver from the Network settings API, apiVersion) or (None, '') if the API is not there.
    AXIS OS 10.12 refuses DNS writes through param.cgi (401), so DNS is read and set through this API."""
    import json
    if "network-settings" not in ctx.api_ids:
        return None, ""
    res = http_post_json(ctx, NETSET_PATH, {"apiVersion": "1.0", "method": "getSupportedVersions"})
    try:
        versions = json.loads(res.get("text") or "{}").get("data", {}).get("apiVersions") or []
    except ValueError:
        versions = []
    ver = max((x for x in versions if str(x).startswith("1.")), key=lambda x: [int(n) for n in str(x).split(".")],
              default="1.0")
    res = http_post_json(ctx, NETSET_PATH, {"apiVersion": ver, "method": "getNetworkInfo", "params": {}})
    if res.get("status") != 200:
        return None, ""
    try:
        data = json.loads(res["text"]).get("data") or {}
    except ValueError:
        return None, ""
    resolver = (data.get("system") or {}).get("resolver")
    return (resolver, ver) if isinstance(resolver, dict) else (None, "")


@handler("name_dns")
def name_dns(ctl: Control, ctx: AuditContext) -> ControlResult:
    p = ctx.params
    raw = _raw(p, NAME_DNS_PARAMS)
    resolver, ver = network_resolver(ctx)
    if not raw and resolver is None:
        return ControlResult(ctl.id, NOT_SUPPORTED, {}, "No host name / DNS settings found.")
    if resolver is not None:
        dhcp = bool(resolver.get("useDhcpResolverInfo"))
        servers = list(resolver.get("nameServers") or resolver.get("staticNameServers") or [])
    else:
        servers = [v for k, v in raw.items() if "NameServer" in k and v and v not in ("0.0.0.0", "::")]
        dhcp = (p.get("root.Network.Resolver.ObtainFromDHCP") or "").lower() == "yes"
    host = p.get("root.Network.HostName") or "(not set)"
    dns = ("from DHCP" if dhcp else ", ".join(servers) or "none configured")
    observed = {"hostname": host, "dns_servers": servers, "dns_from_dhcp": dhcp, "raw": raw}
    if resolver is not None:
        observed["resolver"] = {k: resolver.get(k) for k in RESOLVER_KEYS}
        observed["netset_version"] = ver
    return ControlResult(ctl.id, INFO, observed, f"Host name {host}; DNS {dns}.")


def _syslog_target(server: Any) -> str:
    """Best-effort 'address[:port]' from one entry of the Remote Syslog status reply."""
    if not isinstance(server, dict):
        return str(server)
    inner = server.get("server")
    addr = (inner.get("address") or inner.get("host")) if isinstance(inner, dict) else inner
    addr = addr or server.get("address") or server.get("host") or "?"
    port = server.get("port")
    return f"{addr}:{port}" if port else str(addr)


@handler("syslog")
def syslog(ctl: Control, ctx: AuditContext) -> ControlResult:
    params = ctx.params.group("root.RemoteSyslog")
    if params:
        enabled = any(k.lower().endswith("enabled") and val.lower() == "yes" for k, val in params.items())
        return ControlResult(ctl.id, COMPLIANT if enabled else NON_COMPLIANT, params,
                             "" if enabled else "Remote syslog not enabled.")
    if "remote-syslog" in ctx.api_ids:
        # Remote Syslog API, method "status" (confirmed on M4216-LV 10.12.252): {"data": {"enabled":.., "servers":[..]}}
        import json
        res = http_post_json(ctx, "/axis-cgi/remotesyslog.cgi", {"apiVersion": "1.0", "method": "status"})
        try:
            data = json.loads(res.get("text") or "{}").get("data") if res.get("status") == 200 else None
        except ValueError:
            data = None
        if isinstance(data, dict):
            servers = data.get("servers") or []
            enabled = bool(data.get("enabled"))
            observed = {"enabled": enabled, "servers": servers}
            if not enabled or not servers:
                return ControlResult(ctl.id, NON_COMPLIANT, observed,
                                     "Remote syslog is disabled: logs stay on the camera only (p.25).")
            text = json.dumps(servers).lower()
            tls = "tls" in text
            names = [_syslog_target(s) for s in servers]
            detail = f"Sending to {', '.join(names) or len(servers)}" + ("" if tls else "; not over TLS (TLS recommended).")
            return ControlResult(ctl.id, COMPLIANT, observed, detail.rstrip(".") + ".")
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
    return ControlResult(ctl.id, NON_COMPLIANT, {"RTSPS.Enabled": val},
                         "RTSPS/SRTP is disabled, so video is streamed unencrypted. Enable it in the camera and the VMS "
                         "(p.25).")


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
    if not on:
        return ControlResult(ctl.id, NON_COMPLIANT, found,
                             "802.1X is disabled: the switch port does not check the camera's identity (p.8).")
    states = [s for s in status.values() if s]
    if states and not all(s.lower() == "authorized" for s in states):
        return ControlResult(ctl.id, NON_COMPLIANT, found,
                             f"802.1X is enabled but the port is {', '.join(states)}: check the certificate and the "
                             "RADIUS/switch setup.")
    return ControlResult(ctl.id, COMPLIANT, found,
                         "802.1X is enabled" + (f" and the port is {states[0]}." if states else "."))


@handler("signed_video")
def signed_video(ctl: Control, ctx: AuditContext) -> ControlResult:
    found = dict(ctx.params.match("root.Image.I*.SignedVideo.Enabled"))
    if found:
        off = [k for k, val in found.items() if val.lower() != "yes"]
        return ControlResult(ctl.id, NON_COMPLIANT if off else COMPLIANT, found,
                             (f"Signed video is disabled on {len(off)} of {len(found)} video channel(s).") if off else "")
    if "signed-video" in ctx.api_ids:
        return ControlResult(ctl.id, INFO, {"api": "signed-video"},
                             "Signed video API present but not in the parameter tree; check Plain config > Image manually.")
    return ControlResult(ctl.id, NOT_SUPPORTED, {}, "Signed video not supported on this device.")


@handler("sd_encryption")
def sd_encryption(ctl: Control, ctx: AuditContext) -> ControlResult:
    sd_keys = [k.rsplit(".", 1)[0] for k, did in ctx.params.match("root.Storage.S*.DiskID") if did.upper() == "SD_DISK"]
    if not sd_keys:
        return ControlResult(ctl.id, NA, {}, "No SD card slot.")
    # Disk management API (confirmed on M4216-LV 10.12.252): <disk diskid="SD_DISK" status=".." diskencrypted=".."/>
    if "disk-management" in ctx.api_ids:
        res = http_get(ctx, "/axis-cgi/disks/list.cgi?diskid=all")
        disk = None
        if res.get("status") == 200:
            m = re.search(r'<disk\s[^>]*diskid="SD_DISK"[^>]*/?>', res.get("text") or "")
            if m:
                disk = dict(re.findall(r'(\w+)="([^"]*)"', m.group(0)))
        if disk is not None:
            observed = {k: disk.get(k) for k in ("status", "encryptionenabled", "diskencrypted", "filesystem")}
            status = (disk.get("status") or "").lower()
            encrypted = (disk.get("diskencrypted") or "").lower() == "true"
            if status in ("disconnected", "missing", ""):
                return ControlResult(ctl.id, NA, observed, "No SD card inserted.")
            if encrypted:
                return ControlResult(ctl.id, COMPLIANT, observed, "SD card is encrypted.")
            return ControlResult(ctl.id, NON_COMPLIANT, observed,
                                 f"SD card ({status}) is not encrypted. Encrypt it under System > Storage (p.17).")
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
    from .users import roles_from_groups
    groups = _pwdgrp(ctx)
    found = roles_from_groups(groups)
    accounts = list(found)
    role = {a: v["role"] + ("+ptz" if v["ptz"] else "") for a, v in found.items()}
    observed = {"accounts": role, "anonymous_group": groups.get("anonymous", [])}
    if not accounts:
        return ControlResult(ctl.id, ERROR, observed, "Could not determine user accounts.")
    non_admin = [a for a, v in found.items() if v["role"] in ("operator", "viewer")]
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
