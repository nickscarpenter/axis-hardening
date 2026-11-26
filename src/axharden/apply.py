"""Plan, apply (with read-back verification) and roll back hardening changes (CLAUDE.md §7.2, §7.3).

Write order per camera (one group at a time):
  1  ordinary param changes, batched into one param.cgi update
  2  handler changes (ACAP config, REST)
  3  TLS cipher list (AX-B-011; takes effect after an HTTPS restart/reboot)
  4  HTTPS only (AX-B-009): prove HTTPS works first, write, reconnect over HTTPS
  5  web interface off (AX-B-016): then confirm VAPIX still answers
  (6 network ports: phase 3)
If a camera stops answering after a disruptive step, work on that camera stops (no retry loop).
Every write and verification is recorded in the hash-chained audit log.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .audit import (AuditSettings, CameraResult, ClientFactory, base_meta, finish_meta, load_run, make_run_dir,
                    now_iso, read_camera, run_parallel, safe_name, write_private)
from .auditlog import AuditLog
from .catalog import Catalog, Control, Profile, default_for
from .evaluate import COMPLIANT, ERROR, NA, NON_COMPLIANT, NOT_SUPPORTED, ControlResult
from .version import AxisVersion, v as parse_version
from .inventory import Camera, PasswordFindings
from .vapix import params as vparams
from .vapix.client import CameraError

log = logging.getLogger(__name__)

G_PARAMS, G_HANDLERS, G_CIPHERS, G_HTTPS_ONLY, G_WEBUI, G_FIREWALL, G_DOT1X = 1, 2, 3, 4, 5, 6, 7
DOT1X_WATCH = 30.0            # seconds to keep checking the camera still answers after an 802.1X change
DOT1X_POLL = 5.0
FIREWALL_PATH = "/config/rest/firewall/v1"
FIREWALL_FALLBACK = 60        # seconds before the camera reverts untested firewall rules on its own
FIREWALL_SETTLE = 3.0         # wait after setting rules before testing that the camera still answers
SPECIAL_GROUP = {"AX-B-011": G_CIPHERS, "AX-B-009": G_HTTPS_ONLY, "AX-B-016": G_WEBUI}
GROUP_NAME = {G_PARAMS: "settings", G_HANDLERS: "ACAP/REST settings", G_CIPHERS: "TLS ciphers",
              G_HTTPS_ONLY: "HTTPS only", G_WEBUI: "web interface"}
ANON_PATH = "/config/rest/basic-device-info/v2beta/allowAnonymous"
NETSET_PATH = "/axis-cgi/network_settings.cgi"


@dataclass
class Write:
    name: str          # param name, "app:<Name>" or "rest:allowAnonymous"
    old: str | None
    new: str


@dataclass
class Change:
    camera: str
    control_id: str
    title: str
    group: int
    kind: str                      # param | app_config | rest_anon
    writes: list[Write]
    disruptive: bool = False
    requires_reboot: bool = False
    warning: str = ""
    status: str = "planned"        # planned | applied | verified | failed | skipped | not_needed
    detail: str = ""
    revert: bool = False           # True: puts a setting back to its firmware default (not in the profile)
    now_label: str = ""            # plain words for people, e.g. "Enabled" -> "Disabled" (raw values stay in writes)
    new_label: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Change":
        d = dict(d)
        d["writes"] = [Write(**w) for w in d.get("writes") or []]
        known = cls.__dataclass_fields__
        return cls(**{k: val for k, val in d.items() if k in known})


@dataclass
class CameraPlan:
    camera: Camera
    before: CameraResult
    changes: list[Change] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (control id or "*", reason)


# ---------------------------------------------------------------- planning

def _match_case(current: str | None, new: str) -> str:
    """Write 'No' where the device uses 'Yes', 'on' where it uses 'off'."""
    if current and new and new.isalpha() and current[:1].isupper() and new[:1].islower():
        return new.capitalize()
    return new


def _eq(a: str | None, b: str) -> bool:
    return a is not None and a.strip().lower() == b.strip().lower()


EMPTY_ADDRESSES = {"", "0.0.0.0", "::"}   # "no server": AXIS OS 10.12 stores 0.0.0.0 written to NTP.Server as ""


def _same(a: str | None, b: str) -> bool:
    """Read-back comparison: case-insensitive, and the 'no address' spellings count as equal."""
    return _eq(a, b) or (a is not None and a.strip() in EMPTY_ADDRESSES and b.strip() in EMPTY_ADDRESSES)


def changes_for(ctl: Control, result: ControlResult, host: str) -> tuple[list[Change], str | None]:
    """Changes needed to harden one control, or (no changes, reason it can't be done)."""
    if ctl.kind != "apply" or result.status != NON_COMPLIANT:
        return [], None
    writes: list[Write] = []
    kind = "param"
    if ctl.method == "param":
        obs = result.observed
        for spec in ctl.params:
            pattern = vparams.normalise(spec.name).lower()
            items = [(k, val) for k, val in obs.items()
                     if (fnmatch.fnmatchcase(k.lower(), pattern) if "*" in spec.name else k.lower() == pattern)]
            for actual, val in items:
                if val is None:
                    continue
                if ctl.compare == "subset":
                    allowed = {x.upper() for x in spec.hardened.split(":")}
                    current = [x for x in val.split(":") if x]
                    if not current or any(x.upper() not in allowed for x in current):
                        writes.append(Write(actual, val, spec.hardened))
                elif not _eq(val, spec.hardened):
                    writes.append(Write(actual, val, _match_case(val, spec.hardened)))
    elif ctl.handler == "applications_config":
        name = ctl.handler_args["name"]
        kind = "app_config"
        writes.append(Write(f"app:{name}", result.observed.get(name), str(ctl.handler_args.get("hardened", "false"))))
    elif ctl.handler == "sd_disk":
        want = str(ctl.handler_args.get("hardened", "no"))
        for k, val in result.observed.items():
            if not _eq(val, want):
                writes.append(Write(k, val, _match_case(val, want)))
    elif ctl.handler == "anon_device_info":
        kind = "rest_anon"
        writes.append(Write("rest:allowAnonymous", str(result.observed.get("allowAnonymous")), "false"))
    elif ctl.handler == "rest_property":
        kind = "rest_prop"
        path, prop = ctl.handler_args["path"], ctl.handler_args["property"]
        writes.append(Write(f"rest:{path}#{prop}", json.dumps(result.observed.get(prop)),
                            json.dumps(ctl.handler_args.get("hardened"))))
    elif ctl.handler == "network_ports":
        return [], "Network port controls arrive in phase 3."
    else:
        return [], "This control is not writable by the tool."
    if not writes:
        return [], "Nothing to write."
    group = SPECIAL_GROUP.get(ctl.id, G_HANDLERS if kind != "param" else G_PARAMS)
    return [Change(camera=host, control_id=ctl.id, title=ctl.title, group=group, kind=kind, writes=writes,
                   disruptive=ctl.disruptive, requires_reboot=ctl.requires_reboot, warning=ctl.warning or "",
                   now_label=ctl.state_word("unhardened"), new_label=ctl.state_word("hardened"))], None


def _hardened_value(ctl: Control, w: Write) -> bool:
    """Is the value being replaced the hardened one? (Used to describe a revert in plain words.)"""
    old = "" if w.old is None else str(w.old)
    if ctl.method == "param":
        for spec in ctl.params:
            pattern = vparams.normalise(spec.name).lower()
            if fnmatch.fnmatchcase(w.name.lower(), pattern) if "*" in spec.name else w.name.lower() == pattern:
                if ctl.compare == "subset":
                    allowed = {x.upper() for x in spec.hardened.split(":")}
                    return bool(old) and all(x.upper() in allowed for x in old.split(":") if x)
                return _eq(old, spec.hardened)
        return False
    if ctl.handler == "anon_device_info":
        return old.lower() == "false"
    return _eq(old, str(ctl.handler_args.get("hardened", "")))


REVERT_PREFIX = "back to factory default"


def _device_version(result: CameraResult) -> AxisVersion | None:
    try:
        return parse_version(str(result.device.get("Version") or ""))
    except ValueError:
        return None


def default_changes_for(ctl: Control, result: ControlResult, host: str,
                        version: AxisVersion | None) -> tuple[list[Change], str | None]:
    """Changes that put one control back to its factory default for this AXIS OS version."""
    if ctl.kind != "apply" or result.status in (NOT_SUPPORTED, NA, ERROR):
        return [], None
    writes: list[Write] = []
    kind = "param"
    obs = result.observed
    if ctl.method == "param":
        for spec in ctl.params:
            want = default_for(spec.default, spec.default_from, version)
            if want is None:
                continue
            pattern = vparams.normalise(spec.name).lower()
            for actual, val in obs.items():
                hit = fnmatch.fnmatchcase(actual.lower(), pattern) if "*" in spec.name else actual.lower() == pattern
                if hit and val is not None and not _eq(val, want):
                    writes.append(Write(actual, val, _match_case(val, want)))
    else:
        want = default_for(None if ctl.handler_args.get("default") is None else str(ctl.handler_args["default"]),
                           tuple((parse_version(str(k)), str(x)) for k, x in
                                 (ctl.handler_args.get("default_from") or {}).items()), version)
        if want is None:
            return [], None
        if ctl.handler == "applications_config":
            kind, name = "app_config", ctl.handler_args["name"]
            if obs.get(name) is not None and not _eq(str(obs.get(name)), want):
                writes.append(Write(f"app:{name}", obs.get(name), want))
        elif ctl.handler == "sd_disk":
            writes += [Write(k, val, _match_case(val, want)) for k, val in obs.items()
                       if val is not None and not _eq(val, want)]
        elif ctl.handler == "anon_device_info":
            kind = "rest_anon"
            cur = obs.get("allowAnonymous")
            if cur is not None and str(cur).lower() != want.lower():
                writes.append(Write("rest:allowAnonymous", str(cur), want))
    if not writes:
        return [], None
    group = SPECIAL_GROUP.get(ctl.id, G_HANDLERS if kind != "param" else G_PARAMS)
    now = ctl.state_word("hardened") if all(_hardened_value(ctl, w) for w in writes) else "Custom setting"
    return [Change(camera=host, control_id=ctl.id, title=f"{ctl.feature or ctl.title}: {REVERT_PREFIX}",
                   group=group, kind=kind, writes=writes, disruptive=False, requires_reboot=ctl.requires_reboot,
                   warning="Not in this profile: goes back to the AXIS OS factory default (less secure).",
                   revert=True, now_label=now, new_label=f"{ctl.state_word('unhardened')} (factory)")], None


# ---------------------------------------------------------------- camera settings from the camera list
# hostname / dns / ntp / timezone columns: site-specific values the operator chose, set whatever the profile.
SET_HOSTNAME, SET_DNS, SET_NTP, SET_TZ, SET_SYSLOG = "SET-HOSTNAME", "SET-DNS", "SET-NTP", "SET-TZ", "SET-SYSLOG"
SET_FIREWALL, SET_DOT1X = "SET-FIREWALL", "SET-DOT1X"
SETTING_IDS = (SET_HOSTNAME, SET_DNS, SET_NTP, SET_TZ, SET_SYSLOG, SET_FIREWALL, SET_DOT1X)


def local_ip_for(host: str) -> str | None:
    """The address this PC uses to reach a camera (a UDP 'connect' sends nothing). None if it cannot be worked out."""
    import socket
    try:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def firewall_rule(entry: str) -> dict:
    """allow-list entry -> firewall Rule (FILTER / ACCEPT) for the Device Configuration firewall API."""
    if "-" in entry:
        start, end = entry.split("-", 1)
        return {"ruleType": "FILTER", "ipRange": {"start": start, "end": end}, "filter": {"policy": "ACCEPT"}}
    return {"ruleType": "FILTER", "ip": entry, "filter": {"policy": "ACCEPT"}}


def _rule_key(rule: dict) -> str:
    if rule.get("ip"):
        return str(rule["ip"])
    r = rule.get("ipRange") or {}
    return f"{r.get('start')}-{r.get('end')}" if r else json.dumps(rule, sort_keys=True)


def _allowed(ip: str, entries: list[str]) -> bool:
    import ipaddress
    addr = ipaddress.ip_address(ip)
    for e in entries:
        if "-" in e:
            lo, hi = (ipaddress.ip_address(x) for x in e.split("-", 1))
            if lo.version == addr.version and lo <= addr <= hi:
                return True
        elif addr in ipaddress.ip_network(e, strict=False):
            return True
    return False
SYSLOG_PATH = "/axis-cgi/remotesyslog.cgi"


def _syslog_key(servers) -> list[tuple]:
    return [(str(s.get("address", "")).lower(), int(s.get("port") or 0), str(s.get("protocol", "")).upper())
            for s in servers or [] if isinstance(s, dict)]


def _observed(before: CameraResult, control_id: str) -> dict:
    r = next((x for x in before.results if x.id == control_id), None)
    return dict(r.observed or {}) if r else {}


def _raw_values(before: CameraResult, control_id: str) -> dict[str, str]:
    r = next((x for x in before.results if x.id == control_id), None)
    return dict((r.observed or {}).get("raw") or {}) if r else {}


def _setting(host: str, cid: str, title: str, raw: dict[str, str], wanted: dict[str, str], now: str, new: str,
             required: str) -> tuple[list[Change], list[tuple[str, str]]]:
    low = {k.lower(): k for k in raw}
    if required.lower() not in low:
        return [], [(cid, f"{title}: this camera has no {required.replace('root.', '')} parameter.")]
    writes = []
    for name, value in wanted.items():
        actual = low.get(name.lower())
        if actual is not None and not _same(raw[actual], value):
            keep = _match_case(raw[actual], value) if value.lower() in ("yes", "no", "on", "off") else value
            writes.append(Write(actual, raw[actual], keep))
    if not writes:
        return [], []
    return [Change(camera=host, control_id=cid, title=title, group=G_PARAMS, kind="param", writes=writes,
                   now_label=now, new_label=new)], []


def setting_changes(cam: Camera, before: CameraResult) -> tuple[list[Change], list[tuple[str, str]]]:
    """Changes that set the host name, DNS servers, NTP server and time zone from the camera list."""
    from .timezones import name_for, resolve
    changes: list[Change] = []
    notes: list[tuple[str, str]] = []

    def add(result):
        changes.extend(result[0])
        notes.extend(result[1])

    nd = _raw_values(before, "AX-C-020")
    tm = _raw_values(before, "AX-C-005")
    get = lambda raw, n: next((v for k, v in raw.items() if k.lower() == n.lower()), "")   # noqa: E731
    if cam.hostname:
        add(_setting(cam.host, SET_HOSTNAME, "Set host name", nd,
                     {"root.Network.HostName": cam.hostname, "root.Network.VolatileHostName.ObtainFromDHCP": "no"},
                     get(nd, "root.Network.HostName") or "(not set)", cam.hostname, "root.Network.HostName"))
    nd_obs = _observed(before, "AX-C-020")
    if cam.dns and nd_obs.get("resolver") is not None:
        # Network settings API (AXIS OS 10.12 refuses DNS writes via param.cgi with 401)
        cur = dict(nd_obs["resolver"])
        new = dict(cur, useDhcpResolverInfo=False, staticNameServers=list(cam.dns))
        old_set = {k: cur.get(k) for k in ("useDhcpResolverInfo", "staticNameServers")}
        if old_set != {"useDhcpResolverInfo": False, "staticNameServers": list(cam.dns)}:
            now = ("From DHCP" if cur.get("useDhcpResolverInfo")
                   else ", ".join(nd_obs.get("dns_servers") or cur.get("staticNameServers") or []) or "None")
            changes.append(Change(camera=cam.host, control_id=SET_DNS, title="Set DNS servers", group=G_HANDLERS,
                                  kind="net_resolver",
                                  writes=[Write(f"network:resolver@{nd_obs.get('netset_version') or '1.0'}",
                                                json.dumps(cur, sort_keys=True), json.dumps(new, sort_keys=True))],
                                  now_label=now, new_label=", ".join(cam.dns)))
    elif cam.dns:
        servers = (cam.dns + [""])[:2]
        cur = [get(nd, f"root.Network.Resolver.NameServer{i}") for i in (1, 2)]
        now = ("From DHCP" if get(nd, "root.Network.Resolver.ObtainFromDHCP").lower() == "yes"
               else ", ".join(x for x in cur if x and x != "0.0.0.0") or "None")
        add(_setting(cam.host, SET_DNS, "Set DNS servers", nd,
                     {"root.Network.Resolver.ObtainFromDHCP": "no", "root.Network.Resolver.NameServer1": servers[0],
                      "root.Network.Resolver.NameServer2": servers[1]},
                     now, ", ".join(cam.dns), "root.Network.Resolver.NameServer1"))
    if cam.ntp:
        cur = get(tm, "root.Time.NTP.Server")
        now = ("From DHCP" if get(tm, "root.Time.ObtainFromDHCP").lower() == "yes"
               else (cur if cur and cur != "0.0.0.0" else "None"))
        add(_setting(cam.host, SET_NTP, "Set time server (NTP)", tm,
                     {"root.Time.ObtainFromDHCP": "no", "root.Time.SyncSource": "NTP", "root.Time.NTP.Server": cam.ntp},
                     now, cam.ntp, "root.Time.NTP.Server"))
    dx = _observed(before, "AX-C-010")
    if cam.dot1x or cam.dot1x_identity:
        en_keys = [k for k in dx if k.lower().endswith("dot1x.enabled")]
        id_keys = [k for k in dx if k.lower().endswith("dot1x.eaptls.identity")]
        if not en_keys:
            notes.append((SET_DOT1X, "802.1X: this camera has no 802.1X settings."))
        else:
            writes = []
            if cam.dot1x:
                want = "yes" if cam.dot1x == "on" else "no"
                writes += [Write(k, dx[k], _match_case(dx[k], want)) for k in en_keys if not _eq(dx[k], want)]
            if cam.dot1x_identity:
                writes += [Write(k, dx[k], cam.dot1x_identity) for k in id_keys if dx[k] != cam.dot1x_identity]
            if writes:
                on_now = any(_eq(dx[k], "yes") for k in en_keys)
                turning_on = cam.dot1x == "on" and not on_now
                changes.append(Change(
                    camera=cam.host, control_id=SET_DOT1X, title="Set IEEE 802.1X", group=G_DOT1X, kind="param",
                    writes=writes, disruptive=True,
                    now_label=("Enabled" if on_now else "Disabled"),
                    new_label=("Enabled" if (cam.dot1x or ("on" if on_now else "off")) == "on" else "Disabled") +
                              (f", identity {cam.dot1x_identity}" if cam.dot1x_identity else ""),
                    warning=("If the switch port enforces 802.1X and RADIUS does not accept the camera's certificate, "
                             "the camera drops off the network. There is NO automatic undo: the switch port or RADIUS "
                             "then has to be fixed (or 802.1X disabled on the port) on site." if turning_on else
                             "The switch port must allow the camera without 802.1X, or it can drop off the network.")))
    fw = _observed(before, "AX-C-009")
    if cam.allow and "activated" in fw:
        me = local_ip_for(cam.host)
        if me is None:
            notes.append((SET_FIREWALL, "Firewall: could not work out this PC's address, so the firewall is not "
                                        "changed (it could lock the tool out)."))
        else:
            entries = list(cam.allow) + ([] if _allowed(me, cam.allow) else [me])
            cur = {"activated": bool(fw["activated"]), "defaultPolicy": fw.get("defaultPolicy") or "ACCEPT",
                   "rules": list(fw.get("rules") or [])}
            new = {"activated": True, "defaultPolicy": "DROP", "rules": [firewall_rule(e) for e in entries]}
            if not (cur["activated"] and cur["defaultPolicy"] == "DROP"
                    and sorted(map(_rule_key, cur["rules"])) == sorted(map(_rule_key, new["rules"]))):
                now = ("Disabled" if not cur["activated"] else
                       f"Enabled, default {cur['defaultPolicy']}, {len(cur['rules'])} rule(s)")
                changes.append(Change(
                    camera=cam.host, control_id=SET_FIREWALL, title="Set firewall (block all except allow list)",
                    group=G_FIREWALL, kind="firewall",
                    writes=[Write("firewall:rules", json.dumps(cur, sort_keys=True), json.dumps(new, sort_keys=True))],
                    disruptive=True, now_label=now,
                    new_label=f"Block all except {', '.join(entries)}",
                    warning=(f"Everything not in the allow list loses access to the camera (VMS, other PCs). This PC "
                             f"({me}) is always allowed. The camera reverts automatically within {FIREWALL_FALLBACK} s "
                             "if the tool cannot reach it afterwards.")))
    elif cam.allow:
        notes.append((SET_FIREWALL, "Firewall: needs AXIS OS 11.9 or later (the older IP filter is not changed by "
                                    "this tool)."))
    sl = _observed(before, "AX-C-006")
    if cam.syslog and "servers" in sl:
        cur = {"enabled": bool(sl.get("enabled")), "servers": list(sl.get("servers") or [])}
        new = {"enabled": True, "servers": [dict(s) for s in cam.syslog]}
        if not (cur["enabled"] and _syslog_key(cur["servers"]) == _syslog_key(new["servers"])):
            now = (", ".join(f"{a}:{p}/{pr}" for a, p, pr in _syslog_key(cur["servers"])) or "None") + \
                ("" if cur["enabled"] else " (disabled)")
            changes.append(Change(camera=cam.host, control_id=SET_SYSLOG, title="Set remote syslog servers",
                                  group=G_HANDLERS, kind="syslog",
                                  writes=[Write("syslog:servers", json.dumps(cur, sort_keys=True),
                                                json.dumps(new, sort_keys=True))],
                                  now_label="Disabled" if not cur["enabled"] else now,
                                  new_label=", ".join(f"{s['address']}:{s['port']}/{s['protocol']}" for s in cam.syslog)))
    elif cam.syslog:
        notes.append((SET_SYSLOG, "Set remote syslog servers: this camera has no Remote Syslog API."))
    if cam.timezone:
        iana, posix = resolve(cam.timezone)
        wanted = {"root.Time.POSIXTimeZone": posix}
        if iana and get(tm, "root.Time.TimeZone"):
            wanted["root.Time.TimeZone"] = iana
        add(_setting(cam.host, SET_TZ, "Set time zone", tm, wanted, name_for(get(tm, "root.Time.POSIXTimeZone")),
                     iana or posix, "root.Time.POSIXTimeZone"))
    return changes, notes


def make_plan(audits: list[CameraResult], cameras: list[Camera], catalog: Catalog, profile: Profile,
              profile_loader: Callable[[str], Profile] | None = None,
              controls: list[str] | None = None) -> list[CameraPlan]:
    by_host = {c.host: c for c in cameras}
    plans = []
    for before in audits:
        cam = by_host[before.camera["host"]]
        plan = CameraPlan(camera=cam, before=before)
        plans.append(plan)
        if before.status != "OK":
            plan.skipped.append(("*", f"{before.status}: {before.error or 'not checked'}"))
            continue
        ids = profile.control_ids
        if cam.profile and profile_loader and not controls:
            ids = profile_loader(cam.profile).control_ids
        if controls:
            ids = controls
        wanted = set(ids)
        # A profile is the complete wanted state: settings it leaves out go back to the firmware default.
        # Not when only some controls were asked for (--controls), or for read-only profiles.
        revert_others = not controls and profile.revert_others
        version = _device_version(before)
        for r in before.results:
            if r.id not in wanted:
                if revert_others:
                    chs, _ = default_changes_for(catalog.get(r.id), r, cam.host, version)
                    plan.changes.extend(chs)
                continue
            chs, reason = changes_for(catalog.get(r.id), r, cam.host)
            plan.changes.extend(chs)
            if reason:
                plan.skipped.append((r.id, reason))
        if not controls or any(c in SETTING_IDS for c in controls):
            chs, notes = setting_changes(cam, before)
            plan.changes.extend(c for c in chs if not controls or c.control_id in controls)
            plan.skipped.extend(notes)
        plan.changes.sort(key=lambda c: (c.group, c.control_id))
    return plans


def plan_rows(plans: list[CameraPlan]) -> list[dict]:
    rows = []
    for p in plans:
        for ch in p.changes:
            for w in ch.writes:
                rows.append({"camera": p.camera.label, "host": p.camera.host, "control": ch.control_id,
                             "title": ch.title, "setting": w.name.replace("root.", ""), "current": w.old,
                             "new": w.new, "disruptive": ch.disruptive, "reboot": ch.requires_reboot,
                             "warning": ch.warning, "revert": ch.revert})
    return rows


# ---------------------------------------------------------------- execution

class LostContact(Exception):
    pass


class Executor:
    """Runs ordered change groups on one camera, logging every write."""

    def __init__(self, camera: Camera, factory: ClientFactory, alog: AuditLog, run_id: str, kind: str):
        self.camera = camera
        self.factory = factory
        self.alog = alog
        self.run_id = run_id
        self.kind = kind            # apply | rollback
        self.client: Any = None

    def connect(self, scheme: str | None = None) -> None:
        self.client = self.factory(self.camera, scheme=scheme)
        self.client.negotiate()

    def _log_write(self, ch: Change, w: Write, result: str, detail: str = "") -> None:
        self.alog.append("write", run_id=self.run_id, run_kind=self.kind, camera=self.camera.host,
                         camera_name=self.camera.name, control=ch.control_id, setting=w.name, old=w.old, new=w.new,
                         result=result, detail=detail)

    # --- primitive writes
    def param_update(self, writes: list[Write]) -> dict[str, str | None]:
        """Batch update; on any error retry one by one to attribute it. Returns name -> error or None."""
        if not writes:
            return {}
        resp = self.client.get("/axis-cgi/param.cgi", params={"action": "update", **{w.name: w.new for w in writes}})
        text = resp.text.strip()
        if text.upper().startswith("OK") and "# error" not in text.lower():
            return {w.name: None for w in writes}
        if len(writes) == 1:
            return {writes[0].name: text[:200] or "camera refused the change"}
        out: dict[str, str | None] = {}
        for w in writes:
            out.update(self.param_update([w]))
        return out

    def handler_write(self, ch: Change, w: Write) -> str | None:
        if ch.kind == "app_config":
            name = w.name.split(":", 1)[1]
            r = self.client.get("/axis-cgi/applications/config.cgi",
                                params={"action": "set", "name": name, "value": w.new}, ok_statuses=(200, 400, 404))
            if r.status_code != 200 or 'result="ok"' not in r.text.lower().replace("'", '"'):
                return f"HTTP {r.status_code}: {r.text.strip()[:120]}"
            return None
        if ch.kind == "net_resolver":
            ver = w.name.split("@", 1)[1] if "@" in w.name else "1.0"
            want = json.loads(w.new)
            params = {k: want[k] for k in ("useDhcpResolverInfo", "staticNameServers", "staticSearchDomains",
                                           "staticDomainName") if k in want and want[k] is not None}
            r = self.client.post_json(NETSET_PATH, {"apiVersion": ver, "method": "setResolverConfiguration",
                                                    "params": params}, ok_statuses=(200, 400, 404, 500))
            try:
                err = r.json().get("error") if r.status_code == 200 else None
            except ValueError:
                err = None
            if r.status_code != 200 or err:
                return f"HTTP {r.status_code}: {err or r.text.strip()[:160]}"
            return None
        if ch.kind == "syslog":
            # Remote Syslog API: setup (server list, max 2) then enable/disable. Errors come back as HTTP 200 + "error".
            want = json.loads(w.new)
            servers = [{k: s[k] for k in ("address", "port", "protocol", "syslogFormat", "severity", "type") if k in s}
                       for s in want.get("servers") or []]
            for method, params in (("setup", {"servers": servers}),
                                   ("enable" if want.get("enabled") and servers else "disable", None)):
                body = {"apiVersion": "1.0", "method": method, **({"params": params} if params is not None else {})}
                r = self.client.post_json(SYSLOG_PATH, body, ok_statuses=(200, 400, 404, 500))
                try:
                    err = r.json().get("error") if r.status_code == 200 else None
                except ValueError:
                    err = None
                if r.status_code != 200 or err:
                    return f"{method}: HTTP {r.status_code}: {err or r.text.strip()[:160]}"
            return None
        if ch.kind == "rest_prop":
            # Device Configuration API: PATCH <path>/<property> {"data": value}
            path, prop = w.name.split(":", 1)[1].split("#", 1)
            r = self.client.patch_json(f"{path}/{prop}", {"data": json.loads(w.new)}, ok_statuses=(200, 204, 400, 404))
            if r.status_code not in (200, 204):
                return f"HTTP {r.status_code}: {r.text.strip()[:160]}"
            return None
        if ch.kind == "rest_anon":
            value = str(w.new).strip().lower() == "true"
            r = self.client.patch_json(ANON_PATH, {"data": value}, ok_statuses=(200, 204, 400, 404))
            if r.status_code not in (200, 204):
                return f"HTTP {r.status_code}"
            return None
        return f"unknown change kind {ch.kind}"

    def still_answers(self, client: Any | None = None) -> bool:
        try:
            (client or self.client).get("/axis-cgi/param.cgi?action=list&group=root.Brand.Brand")
            return True
        except CameraError:
            return False

    # --- groups
    def run_params(self, changes: list[Change]) -> None:
        writes = [w for ch in changes for w in ch.writes]
        errors = self.param_update(writes)
        for ch in changes:
            failed = [f"{w.name}: {errors[w.name]}" for w in ch.writes if errors.get(w.name)]
            for w in ch.writes:
                self._log_write(ch, w, "error" if errors.get(w.name) else "ok", errors.get(w.name) or "")
            ch.status = "failed" if failed else "applied"
            ch.detail = "; ".join(failed)

    def run_handlers(self, changes: list[Change]) -> None:
        for ch in changes:
            errs = []
            for w in ch.writes:
                err = self.handler_write(ch, w)
                self._log_write(ch, w, "error" if err else "ok", err or "")
                if err:
                    errs.append(err)
            ch.status = "failed" if errs else "applied"
            ch.detail = "; ".join(errs)

    def run_https_only(self, changes: list[Change], enabling: bool) -> None:
        https = self.client
        if enabling and self.client.scheme != "https":
            # Prove HTTPS works before turning HTTP off.
            try:
                https = self.factory(self.camera, scheme="https")
                https.negotiate()
                if not self.still_answers(https):
                    raise CameraError("no answer over HTTPS")
            except CameraError as e:
                for ch in changes:
                    ch.status, ch.detail = "failed", f"Not enabled: HTTPS does not work on this camera ({e})."
                    for w in ch.writes:
                        self._log_write(ch, w, "skipped", ch.detail)
                return
        self.run_params(changes)
        if all(ch.status == "failed" for ch in changes):
            return
        if enabling:
            # Reconnect over HTTPS and check the camera still answers.
            try:
                fresh = self.factory(self.camera, scheme="https")
                fresh.negotiate()
                ok = self.still_answers(fresh)
            except CameraError:
                ok = False
            if not ok:
                raise LostContact("Camera stopped answering after HTTPS-only was enabled.")
            self.client = fresh

    # --- firewall (Device Configuration API, AXIS OS 11.9+)
    def _fw_call(self, method: str, sub: str, data: Any = None) -> None:
        path = f"{FIREWALL_PATH}/{sub}"
        if method == "PATCH":
            r = self.client.patch_json(path, {"data": data}, ok_statuses=(200, 204, 400, 404, 500))
        else:
            r = self.client.post_json(path, {"data": data}, ok_statuses=(200, 204, 400, 404, 500))
        try:
            ok = r.status_code in (200, 204) and (r.status_code == 204 or r.json().get("status") == "success")
        except ValueError:
            ok = False
        if not ok:
            raise CameraError(f"firewall {sub}: HTTP {r.status_code}: {r.text.strip()[:160]}")

    def _fw_set(self, policy: str, rules: list, test: bool) -> None:
        """test=False: only while the firewall is OFF (nothing enforced): set the rules directly (fallbackTime 0; the
        camera refuses to test rules while inactive). test=True: only while ON: set them with the camera's fallback
        timer, prove on a fresh connection that the tool can still reach the camera, then confirm. If the camera no
        longer answers, the rules are not confirmed and the camera reverts by itself."""
        clean = [{k: v for k, v in r.items() if v is not None} for r in rules]   # the camera reports unset fields as null
        self._fw_call("POST", "conf/setRules", {"defaultPolicy": policy,
                                                "fallbackTime": FIREWALL_FALLBACK if test else 0, "rules": clean})
        if not test:
            return
        time.sleep(FIREWALL_SETTLE)
        try:
            fresh = self.factory(self.camera, scheme=self.client.scheme)
            fresh.negotiate()
            ok = self.still_answers(fresh)
        except CameraError:
            ok = False
        if not ok:
            raise LostContact(f"The camera stopped answering after the firewall rules were set. They were NOT "
                              f"confirmed: the camera puts the previous rules back by itself within "
                              f"{FIREWALL_FALLBACK} s. Check the allow list.")
        self.client = fresh
        self._fw_call("POST", "conf/confirmRules", None)

    def run_dot1x(self, changes: list[Change]) -> None:
        """Write the 802.1X settings, then keep checking (on fresh connections) that the camera still answers while
        the switch port re-authenticates. No automatic undo exists if it does not."""
        self.run_params(changes)
        if all(ch.status == "failed" for ch in changes):
            return
        waited = 0.0
        while True:
            time.sleep(DOT1X_POLL)
            waited += DOT1X_POLL
            try:
                fresh = self.factory(self.camera, scheme=self.client.scheme)
                fresh.negotiate()
                ok = self.still_answers(fresh)
            except CameraError:
                ok = False
            if not ok:
                raise LostContact("The camera stopped answering after the 802.1X change. The switch port is probably "
                                  "blocking it: fix the RADIUS/switch setup or disable 802.1X on that port. This "
                                  "change cannot be undone remotely.")
            self.client = fresh
            if waited >= DOT1X_WATCH:
                return

    def run_firewall(self, changes: list[Change]) -> None:
        for ch in changes:
            w = ch.writes[0]
            want = json.loads(w.new)
            try:
                r = self.client.get(FIREWALL_PATH)
                active = bool((r.json().get("data") or {}).get("activated"))
                if want.get("activated"):
                    if not active:          # switch on with an accept-all rule set first: nothing is blocked yet
                        self._fw_set("ACCEPT", [], test=False)
                        self._fw_call("PATCH", "activated", True)
                    self._fw_set(want["defaultPolicy"], want["rules"], test=True)
                else:
                    if active:              # switch off first, so restoring old rules can never block anything
                        self._fw_call("PATCH", "activated", False)
                    self._fw_set(want["defaultPolicy"], want["rules"], test=False)
            except LostContact as e:
                self._log_write(ch, w, "error", str(e))
                ch.status, ch.detail = "failed", str(e)
                raise
            except (CameraError, ValueError) as e:
                self._log_write(ch, w, "error", str(e))
                ch.status, ch.detail = "failed", str(e)
                continue
            self._log_write(ch, w, "ok")
            ch.status, ch.detail = "applied", ""

    def run_webui(self, changes: list[Change]) -> None:
        self.run_params(changes)
        if not self.still_answers():
            raise LostContact("Camera API stopped answering after the web interface setting changed.")

    def execute(self, changes: list[Change], reverse: bool = False) -> None:
        groups = sorted({c.group for c in changes}, reverse=reverse)
        for g in groups:
            chs = [c for c in changes if c.group == g and c.status == "planned"]
            if not chs:
                continue
            if g in (G_PARAMS, G_CIPHERS):
                self.run_params(chs)
            elif g == G_HANDLERS:
                self.run_handlers(chs)
            elif g == G_HTTPS_ONLY:
                enabling = any(w.new.lower() == "https" for ch in chs for w in ch.writes)
                self.run_https_only(chs, enabling)
            elif g == G_WEBUI:
                self.run_webui(chs)
            elif g == G_FIREWALL:
                self.run_firewall(chs)
            elif g == G_DOT1X:
                self.run_dot1x(chs)


def verify_changes(changes: list[Change], tree: vparams.ParamTree, after: list[ControlResult],
                   alog: AuditLog, run_id: str, host: str) -> None:
    after_by_id = {r.id: r for r in after}
    for ch in changes:
        if ch.status != "applied":
            continue
        problems = []
        if ch.kind == "param":
            for w in ch.writes:
                now = tree.get(w.name)
                if not _same(now, w.new):
                    problems.append(f"{w.name} reads back as {now!r}, expected {w.new!r}")
        elif ch.kind == "firewall":
            r = after_by_id.get("AX-C-009")
            got = (r.observed or {}) if r else {}
            want = json.loads(ch.writes[0].new)
            if bool(got.get("activated")) != bool(want.get("activated")):
                problems.append(f"firewall activated reads back as {got.get('activated')!r}")
            if got.get("defaultPolicy") != want.get("defaultPolicy"):
                problems.append(f"default policy reads back as {got.get('defaultPolicy')!r}")
            if sorted(map(_rule_key, got.get("rules") or [])) != sorted(map(_rule_key, want.get("rules") or [])):
                problems.append(f"rules read back as {sorted(map(_rule_key, got.get('rules') or []))}")
        elif ch.kind == "syslog":
            r = after_by_id.get("AX-C-006")
            got = (r.observed or {}) if r else {}
            want = json.loads(ch.writes[0].new)
            if bool(got.get("enabled")) != bool(want.get("enabled") and want.get("servers")):
                problems.append(f"syslog enabled reads back as {got.get('enabled')!r}")
            if _syslog_key(got.get("servers")) != _syslog_key(want.get("servers")):
                problems.append(f"syslog servers read back as {_syslog_key(got.get('servers'))}")
        elif ch.kind == "rest_prop":
            r = after_by_id.get(ch.control_id)
            prop = ch.writes[0].name.split("#", 1)[1]
            got = (r.observed or {}).get(prop) if r else None
            if got != json.loads(ch.writes[0].new):
                problems.append(f"{prop} reads back as {got!r}, expected {json.loads(ch.writes[0].new)!r}")
        elif ch.kind == "net_resolver":
            r = after_by_id.get("AX-C-020")
            got = ((r.observed or {}).get("resolver") or {}) if r else {}
            want = json.loads(ch.writes[0].new)
            for k in ("useDhcpResolverInfo", "staticNameServers"):
                if got.get(k) != want.get(k):
                    problems.append(f"DNS {k} reads back as {got.get(k)!r}, expected {want.get(k)!r}")
        else:
            r = after_by_id.get(ch.control_id)
            want_compliant = all(str(w.new).lower() in ("false", "no") for w in ch.writes)
            if r is not None and want_compliant and r.status != COMPLIANT:
                problems.append(f"control still {r.status}: {r.detail}")
        ch.status = "failed" if problems else "verified"
        ch.detail = "; ".join(problems) if problems else (
            "Verified. Takes effect after the camera's HTTPS service restarts (reboot)." if ch.requires_reboot else "Verified.")
        alog.append("verify", run_id=run_id, camera=host, control=ch.control_id,
                    result="ok" if not problems else "mismatch", detail=ch.detail)


def apply_camera(plan: CameraPlan, catalog: Catalog, settings: AuditSettings, factory: ClientFactory,
                 alog: AuditLog, run_id: str, run_dir: Path, passwords: PasswordFindings, kind: str = "apply",
                 reverse: bool = False, scheme: str | None = None) -> CameraResult:
    cam = plan.camera
    before = plan.before
    res = CameraResult(camera=cam.public_dict(), status=before.status, error=before.error, device=before.device,
                       results=before.results, auth_scheme=before.auth_scheme, scheme=scheme or cam.protocol,
                       started=now_iso())
    changes = plan.changes
    snapshot: dict[str, Any] = {}
    if before.status == "OK" and changes:
        ex = Executor(cam, factory, alog, run_id, kind)
        try:
            ex.connect(scheme)
            ex.execute(changes, reverse=reverse)
            read = read_camera(ex.client, cam, catalog, [r.id for r in before.results], passwords, settings.min_axis_os)
            res.after, res.device = read.results, read.info
            res.scheme = ex.client.scheme
            verify_changes(changes, read.tree, read.results, alog, run_id, cam.host)
            snapshot["params_after"] = read.tree.to_dict()
        except LostContact as e:
            res.status, res.error = "LOST_CONTACT", f"{e} Work on this camera stopped; check it manually."
            alog.append("camera_stopped", run_id=run_id, camera=cam.host, detail=res.error)
            for ch in changes:
                if ch.status == "planned":
                    ch.status, ch.detail = "skipped", "Not attempted: camera stopped answering."
        except CameraError as e:
            res.status, res.error = e.code, str(e)
            alog.append("camera_error", run_id=run_id, camera=cam.host, detail=f"{e.code}: {e}")
            for ch in changes:
                if ch.status == "planned":
                    ch.status, ch.detail = "skipped", f"Not attempted: {e.code}."
        finally:
            if ex.client is not None:
                res.requests = ex.client.request_count
                ex.client.close()
    for cid, reason in plan.skipped:
        changes_note = {"control_id": cid, "status": "not_planned", "detail": reason}
        res.changes.append(changes_note)
    res.changes = [c.to_dict() for c in changes] + res.changes
    res.finished = now_iso()
    snapshot.update(res.to_dict())
    write_private(run_dir / "cameras" / f"{safe_name(cam.host)}.json", json.dumps(snapshot, indent=1, default=str))
    return res


def run_apply(plans: list[CameraPlan], catalog: Catalog, profile: Profile, settings: AuditSettings,
              passwords: PasswordFindings, output_dir: Path, confirmed_by: str, audit_run: str,
              client_factory: ClientFactory | None = None, progress: Callable[[CameraResult], None] | None = None,
              simulated: bool = False) -> tuple[str, Path, list[CameraResult]]:
    factory = client_factory or settings.live_factory()
    run_id, run_dir = make_run_dir(output_dir)
    cams = [p.camera for p in plans]
    meta = base_meta(run_id, "apply", catalog, profile, settings, passwords, cams, simulated)
    from .audit import set_baseline
    set_baseline(meta, profile)
    meta.update(audit_run=audit_run, confirmed_by=confirmed_by,
                planned_changes=sum(len(p.changes) for p in plans))
    alog = AuditLog(output_dir / "audit_log.jsonl", operator=settings.operator)
    alog.append("run_start", run_id=run_id, run_kind="apply", profile=profile.name, audit_run=audit_run,
                cameras=len(cams), planned_changes=meta["planned_changes"], confirmed_by=confirmed_by,
                simulated=simulated)
    t0 = time.monotonic()
    by_host = {p.camera.host: p for p in plans}
    results = run_parallel(cams, settings.workers,
                           lambda cam: apply_camera(by_host[cam.host], catalog, settings, factory, alog, run_id,
                                                    run_dir, passwords), progress)
    finish_meta(meta, results, t0, run_dir)
    meta["change_summary"] = change_summary(results)
    write_private(run_dir / "run.json", json.dumps(meta, indent=1, default=str))
    alog.append("run_end", run_id=run_id, run_kind="apply", summary=meta["change_summary"])
    return run_id, run_dir, results


def change_summary(results: list[CameraResult]) -> dict:
    counts = {"verified": 0, "failed": 0, "skipped": 0}
    for r in results:
        for ch in r.changes:
            st = ch.get("status")
            if st in counts:
                counts[st] += 1
    return counts


# ---------------------------------------------------------------- rollback

def build_rollback(run_dir: Path, cameras: list[Camera], only_host: str | None = None,
                   only_controls: list[str] | None = None) -> tuple[dict, list[CameraPlan]]:
    """Plans that restore the 'old' values of every write attempted in an apply run."""
    meta, results = load_run(run_dir)
    if meta.get("kind") != "apply":
        raise ValueError(f"Run {meta.get('run_id')} is a {meta.get('kind')} run; only apply runs can be rolled back.")
    by_host = {c.host: c for c in cameras}
    plans = []
    for r in results:
        host = r.camera["host"]
        if only_host and host != only_host:
            continue
        if host not in by_host:
            raise ValueError(f"{host} is not in the inventory, so its credentials are unknown.")
        undo = []
        for d in r.changes:
            if d.get("status") not in ("applied", "verified", "failed") or not d.get("writes"):
                continue
            ch = Change.from_dict(d)
            if only_controls and ch.control_id not in only_controls:
                continue
            if any(w.old is None for w in ch.writes):
                continue
            ch.writes = [Write(w.name, w.new, w.old) for w in ch.writes]
            ch.now_label, ch.new_label = ch.new_label, ch.now_label
            ch.status, ch.detail = "planned", ""
            ch.title = f"Undo: {ch.title}"
            undo.append(ch)
        if undo:
            before = CameraResult(camera=r.camera, status="OK", device=r.device, results=r.after or r.results)
            plans.append(CameraPlan(camera=by_host[host], before=before, changes=undo))
    return meta, plans


def run_rollback(apply_run_dir: Path, plans: list[CameraPlan], catalog: Catalog, settings: AuditSettings,
                 output_dir: Path, confirmed_by: str, client_factory: ClientFactory | None = None,
                 progress: Callable[[CameraResult], None] | None = None,
                 simulated: bool = False) -> tuple[str, Path, list[CameraResult]]:
    from .catalog import Profile as _P
    factory = client_factory or settings.live_factory()
    apply_meta = json.loads((apply_run_dir / "run.json").read_text(encoding="utf-8"))
    run_id, run_dir = make_run_dir(output_dir)
    cams = [p.camera for p in plans]
    profile = _P(name=f"rollback of {apply_meta['run_id']}", description="", control_ids=apply_meta.get("control_ids", []))
    meta = base_meta(run_id, "rollback", catalog, profile, settings, PasswordFindings(), cams, simulated)
    meta.update(rollback_of=apply_meta["run_id"], confirmed_by=confirmed_by)
    alog = AuditLog(output_dir / "audit_log.jsonl", operator=settings.operator)
    alog.append("run_start", run_id=run_id, run_kind="rollback", rollback_of=apply_meta["run_id"],
                cameras=len(cams), confirmed_by=confirmed_by, simulated=simulated)
    t0 = time.monotonic()
    by_host = {p.camera.host: p for p in plans}

    def one(cam: Camera) -> CameraResult:
        plan = by_host[cam.host]
        # If HTTPS-only was switched on by the apply run, HTTP no longer works: talk HTTPS.
        https_on = any(ch.control_id == "AX-B-009" for ch in plan.changes)
        return apply_camera(plan, catalog, settings, factory, alog, run_id, run_dir, PasswordFindings(),
                            kind="rollback", reverse=True, scheme="https" if https_on else None)

    results = run_parallel(cams, settings.workers, one, progress)
    finish_meta(meta, results, t0, run_dir)
    meta["change_summary"] = change_summary(results)
    write_private(run_dir / "run.json", json.dumps(meta, indent=1, default=str))
    alog.append("run_end", run_id=run_id, run_kind="rollback", summary=meta["change_summary"])
    return run_id, run_dir, results
