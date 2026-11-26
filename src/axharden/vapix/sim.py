"""Simulated camera for --simulate, the GUI demo and tests.

A SimDevice holds one camera's state, seeded from a recorded snapshot/fixture (params, apis, device info
and recorded probe replies). SimClient speaks the same interface as CameraClient, so audit and apply run
unchanged. Writes change the in-memory state, so read-back and re-audit see them. Nothing touches the network.
"""

from __future__ import annotations

import copy
import json
import re
import threading
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ..inventory import Camera
from .client import AuthFailed, Unreachable, VapixHTTPError


class SimResponse:
    def __init__(self, status: int, text: str = "", headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def json(self) -> Any:
        return json.loads(self.text)


class SimDevice:
    def __init__(self, snapshot: dict):
        snap = copy.deepcopy(snapshot)
        self.params: dict[str, str] = dict(snap.get("params") or {})
        self.apis: list = list(snap.get("apis") or [])
        self.device: dict = dict(snap.get("device") or {})
        self.probes: dict = dict(snap.get("probes") or {})
        self.auth_scheme: str = snap.get("auth_scheme") or "digest"
        self.lock = threading.Lock()
        self.reachable = True
        self.reject_auth = False
        self.write_log: list[tuple[str, str]] = []   # (name, value) for tests
        self.app_config: dict[str, str] = {}
        self.allow_anonymous: Any = True
        self.reject_params: set[str] = set()          # names whose writes the "camera" refuses (tests)
        self.ignore_params: set[str] = set()          # names accepted but not changed (read-back mismatch tests)
        self.after_write_hook = None                  # callable(name, value) -> None, for tests
        self._groups: dict[str, list[str]] | None = None
        self.passwords: dict[str, str] = {}           # accounts created in the simulation
        self.reject_accounts = False                  # pwdgrp add/remove answers with an error (tests)
        self.removed: set[str] = set()                # accounts removed in the simulation (can no longer log in)
        self.protected_accounts: set[str] = set()     # names the "camera" refuses to remove, e.g. {"root"} (tests)
        self.restarts = 0                             # restart.cgi calls
        self.restart_down_checks = 2                  # connection attempts that fail after a restart
        self.down_checks = 0
        self.stays_down = False                       # never comes back after a restart (tests)
        self.client_ip: str | None = None             # address the "camera" sees the tool coming from (firewall)
        self.fw_prev: tuple | None = None             # (policy, rules) to fall back to while new rules are unconfirmed

    def groups(self) -> dict[str, list[str]]:
        """User groups, seeded from the recorded pwdgrp.cgi reply."""
        if self._groups is None:
            from .users import parse_pwdgrp
            rec = self.recorded("/axis-cgi/pwdgrp.cgi?action=get")
            self._groups = parse_pwdgrp(rec.get("text", "")) if rec else {}
            if not self._groups.get("digusers"):
                self._groups.update(digusers=["root"], admin=["root"], operator=["root"], viewer=["root"],
                                    ptz=["root"])
        return self._groups

    # --- helpers
    def actual(self, name: str) -> str | None:
        low = name.lower()
        for k in self.params:
            if k.lower() == low:
                return k
        return None

    def recorded(self, path: str) -> dict | None:
        return self.probes.get(f"GET {path}")


class SimClient:
    """Drop-in for CameraClient backed by a SimDevice."""

    def __init__(self, device: SimDevice, camera: Camera, scheme: str | None = None, **_: Any):
        self.dev = device
        self.camera = camera
        self.scheme = (scheme or camera.protocol or "https").lower()
        self.auth_scheme: str | None = None
        self.request_count = 0
        self.tls = None

    def __enter__(self) -> "SimClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        pass

    def _check(self) -> None:
        self.request_count += 1
        if not self.dev.reachable:
            raise Unreachable("Connection failed: simulated camera unreachable")
        if self.dev.down_checks > 0 or (self.dev.stays_down and self.dev.restarts):
            self.dev.down_checks -= 1
            raise Unreachable("Connection failed: simulated camera is restarting")
        if self._fw_blocked():
            if self.dev.fw_prev is not None:          # unconfirmed rules: the camera's fallback timer puts them back
                self.dev.fw["conf"]["rules"]["activeDefaultPolicy"], self.dev.fw["conf"]["rules"]["activeRules"] = \
                    self.dev.fw_prev
                self.dev.fw_prev = None
            raise Unreachable("Connection failed: simulated firewall drops this PC")
        if self.scheme == "http" and self._https_only():
            raise Unreachable("Connection failed: simulated camera only accepts HTTPS")

    def _fw_state(self) -> dict | None:
        d = self.dev
        if not hasattr(d, "fw"):
            rec = d.recorded("/config/rest/firewall/v1")
            d.fw = (json.loads(rec["text"]) or {}).get("data") if rec and rec.get("status") == 200 else None
        return d.fw

    def _fw_blocked(self) -> bool:
        fw = self._fw_state()
        if not fw or not fw.get("activated"):
            return False
        rules = fw["conf"]["rules"]
        if rules.get("activeDefaultPolicy") != "DROP":
            return False
        from ..apply import _allowed, _rule_key, local_ip_for
        ip = self.dev.client_ip or local_ip_for(self.camera.host) or "127.0.0.1"
        return not _allowed(ip, [_rule_key(r) for r in rules.get("activeRules") or []])

    def _firewall(self, method: str, path: str, body: dict | None) -> SimResponse:
        fw = self._fw_state()
        if fw is None:
            return SimResponse(404, "")
        d, rules, data = self.dev, fw["conf"]["rules"], (body or {}).get("data")
        ok = SimResponse(200, json_dumps({"status": "success"}))
        if method == "GET":
            rules["testTimeLeft"] = 60 if d.fw_prev is not None else 0
            return SimResponse(200, json_dumps({"status": "success", "data": fw}))
        if method == "PATCH" and path.endswith("/activated"):
            fw["activated"] = bool(data)
            d.write_log.append(("firewall:activated", str(fw["activated"])))
            return ok
        if path.endswith("/conf/setRules"):
            if data.get("fallbackTime") and not fw.get("activated"):   # as the real camera (12.11)
                return SimResponse(400, json_dumps({"status": "error", "error": {
                    "code": 103, "message": "Backend defined error: Can not test rules while firewall is inactive"}}))
            d.fw_prev = (rules["activeDefaultPolicy"], list(rules["activeRules"])) if data.get("fallbackTime") else None
            rules["activeDefaultPolicy"], rules["activeRules"] = data["defaultPolicy"], list(data["rules"])
            d.write_log.append(("firewall:setRules", json_dumps(data)))
            return ok
        if path.endswith("/conf/confirmRules"):
            d.fw_prev = None
            return ok
        if path.endswith("/conf/clearPendingRules"):
            if d.fw_prev is not None:
                rules["activeDefaultPolicy"], rules["activeRules"] = d.fw_prev
                d.fw_prev = None
            return ok
        return SimResponse(400, json_dumps({"status": "error", "error": {"message": "unknown"}}))

    def _https_only(self) -> bool:
        vals = [self.dev.params.get(f"root.System.BoaGroupPolicy.{g}", "") for g in ("admin", "operator", "viewer")]
        return all(v.lower() == "https" for v in vals)

    def _creds_ok(self) -> bool:
        cred = self.camera.credential
        if cred.username in self.dev.removed:
            return False
        known = self.dev.passwords.get(cred.username)
        if known is not None:
            return known == cred.password
        return True   # accounts from the recording (e.g. root): the simulated password is random, accept it

    def negotiate(self) -> str:
        self._check()
        if self.dev.reject_auth or not self._creds_ok():
            raise AuthFailed("HTTP 401: credentials rejected or account lacks rights")
        self.auth_scheme = self.dev.auth_scheme
        return self.auth_scheme

    # --- requests
    def request(self, method: str, path: str, *, ok_statuses: tuple[int, ...] = (200,), params: dict | None = None,
                json: dict | None = None, data: Any = None, **_: Any) -> SimResponse:
        self._check()
        if self.dev.reject_auth or not self._creds_ok():
            raise AuthFailed("HTTP 401: credentials rejected or account lacks rights")
        merged = dict(params or {})
        if isinstance(data, dict):
            merged.update(data)
        with self.dev.lock:
            resp = self._route(method.upper(), path, merged, json)
        if resp.status_code not in ok_statuses:
            raise VapixHTTPError(f"HTTP {resp.status_code} for {path.split('?')[0]}", resp.status_code)
        return resp

    def get(self, path: str, **kw: Any) -> SimResponse:
        return self.request("GET", path, **kw)

    def post_json(self, path: str, payload: dict, **kw: Any) -> SimResponse:
        return self.request("POST", path, json=payload, **kw)

    def patch_json(self, path: str, payload: dict, **kw: Any) -> SimResponse:
        return self.request("PATCH", path, json=payload, **kw)

    def http80(self) -> dict:
        if not self.dev.reachable:
            return {"status": None, "error": "UNREACHABLE"}
        if self._https_only():
            return {"status": 301, "location": f"https://{self.camera.host}/"}
        return self.dev.probes.get("HTTP80 /") or {"status": 200, "location": ""}

    def fetch_cert(self) -> dict:
        return self.dev.probes.get("TLS cert") or {"issuer": {"organizationName": "Axis Communications AB",
                                                              "commonName": "Axis device ID intermediate"},
                                                   "subject": {"commonName": self.camera.host},
                                                   "notAfter": "Jan 19 03:14:07 2038 GMT", "tls_version": "TLSv1.3"}

    # --- routing
    def _route(self, method: str, path: str, params: dict, body: dict | None) -> SimResponse:
        split = urlsplit(path)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        query.update(params)
        p = split.path
        d = self.dev

        if p == "/axis-cgi/param.cgi":
            action = query.pop("action", "")
            if action == "list":
                group = query.get("group", "")
                groups = [g.strip().lower() for g in group.split(",") if g.strip()]
                lines = [f"{k}={v}" for k, v in d.params.items()
                         if not groups or any(k.lower() == g or k.lower().startswith(g + ".") for g in groups)]
                return SimResponse(200, "\n".join(lines) + "\n")
            if action == "update":
                errors = []
                for name, value in query.items():
                    full = name if name.lower().startswith("root.") else "root." + name
                    actual = d.actual(full)
                    if actual is None or actual in d.reject_params:
                        errors.append(f"# Error: Error setting '{name}' to '{value}'!")
                        continue
                    if actual not in d.ignore_params:
                        d.params[actual] = value
                    d.write_log.append((actual, value))
                    if d.after_write_hook:
                        d.after_write_hook(actual, value)
                return SimResponse(200, "\n".join(errors) + "\n" if errors else "OK\n")
            return SimResponse(200, "# Error: unknown action\n")

        if p == "/axis-cgi/network_settings.cgi" and any(a.get("id") == "network-settings" for a in d.apis):
            return self._netset(body or {})

        if p == "/axis-cgi/restart.cgi":
            d.restarts += 1
            d.down_checks = d.restart_down_checks      # the next N connection attempts fail while it restarts
            d.write_log.append(("restart", str(d.restarts)))
            return SimResponse(200, "<html><body>Restarting.</body></html>")

        if p == "/axis-cgi/pwdgrp.cgi":
            return self._pwdgrp(method, query)

        if p == "/axis-cgi/basicdeviceinfo.cgi":
            return SimResponse(200, json_dumps({"apiVersion": "1.3", "data": {"propertyList": d.device}}))
        if p == "/axis-cgi/apidiscovery.cgi":
            return SimResponse(200, json_dumps({"apiVersion": "1.0", "data": {"apiList": d.apis}}))

        if p == "/axis-cgi/applications/config.cgi":
            name = query.get("name", "")
            rec = d.recorded(f"/axis-cgi/applications/config.cgi?action=get&name={name}")
            if rec is not None and rec.get("status") in (400, 404, 501):
                return SimResponse(rec["status"], rec.get("text", ""))
            if name not in d.app_config:
                m = re.search(r'value="([^"]*)"', (rec or {}).get("text", "")) if rec else None
                d.app_config[name] = m.group(1) if m else "true"
            if query.get("action") == "set":
                d.app_config[name] = query.get("value", "")
                d.write_log.append((f"app:{name}", d.app_config[name]))
                return SimResponse(200, '<reply result="ok"/>')
            return SimResponse(200, f'<reply result="ok"><param name="{name}" value="{d.app_config[name]}"/></reply>')

        if p == "/config/rest/basic-device-info/v2beta/allowAnonymous":
            rec = d.recorded(p)
            ver = (d.device.get("Version") or "0").split(".")
            if (rec and rec.get("status") == 404) or (not rec and (int(ver[0]), int(ver[1] if len(ver) > 1 else 0)) < (11, 11)):
                return SimResponse(404, "")
            if method == "PATCH":
                d.allow_anonymous = (body or {}).get("data")
                d.write_log.append(("rest:allowAnonymous", str(d.allow_anonymous)))
                return SimResponse(200, json_dumps({"status": "success"}))
            return SimResponse(200, json_dumps({"status": "success", "data": d.allow_anonymous}))

        if p.startswith("/config/rest/firewall/v1"):
            return self._firewall(method, p, body)

        if p.startswith("/config/rest/") and p != "/config/rest/basic-device-info/v2beta/allowAnonymous":
            return self._rest(method, p, body)

        if p == "/axis-cgi/remotesyslog.cgi" and d.probes.get("POST /axis-cgi/remotesyslog.cgi status"):
            return self._syslog(body or {})

        if method == "POST" and isinstance(body, dict):
            rec = d.probes.get(f"POST {p} {body.get('method')}")
            if rec is not None:
                return SimResponse(rec.get("status") or 500, rec.get("text", ""))
        rec = d.recorded(path)
        if rec is not None:
            return SimResponse(rec.get("status") or 500, rec.get("text", ""))
        return SimResponse(404, "")


    def _syslog(self, body: dict) -> SimResponse:
        """Remote Syslog API (status / setup / enable / disable), seeded from the recorded status reply."""
        d = self.dev
        if not hasattr(d, "syslog"):
            rec = d.probes["POST /axis-cgi/remotesyslog.cgi status"]
            d.syslog = (json.loads(rec["text"]) or {}).get("data") or {"enabled": False, "servers": []}
        method = body.get("method")

        def reply(**kw):
            return SimResponse(200, json_dumps({"apiVersion": "1.0", "method": method, **kw}))
        if method == "status":
            return reply(data=d.syslog)
        if method == "setup":
            servers = list((body.get("params") or {}).get("servers") or [])
            if len(servers) > 2:
                return reply(error={"code": 2203, "message": "Too many servers specified"})
            if any(not s.get("address") for s in servers):
                return reply(error={"code": 2103, "message": "Required parameter missing"})
            defaults = {"protocol": "TLS", "port": 6514, "syslogFormat": "RFC5424", "severity": "Warning", "type": "All"}
            d.syslog = {"enabled": False, "servers": [{**defaults, **s} for s in servers]}   # setup disables
            d.write_log.append(("syslog:setup", json_dumps(servers)))
            return reply(data=d.syslog)
        if method == "enable":
            if not d.syslog["servers"]:
                return reply(error={"code": 2200, "message": "No server configured"})
            d.syslog["enabled"] = True
            return reply(data=d.syslog)
        if method == "disable":
            d.syslog["enabled"] = False
            return reply(data=d.syslog)
        return reply(error={"code": 2102, "message": f"Method not supported: '{method}'"})

    def _rest(self, method: str, path: str, body: dict | None) -> SimResponse:
        """Device Configuration REST APIs, backed by recorded GET replies: GET <api>, PATCH <api>/<property>."""
        d = self.dev
        if not hasattr(d, "rest"):
            d.rest = {}
        if method == "PATCH":
            base, prop = path.rsplit("/", 1)
            state = self._rest_state(base)
            if state is None or prop not in state:
                return SimResponse(404, json_dumps({"status": "error", "error": {"message": "not found"}}))
            state[prop] = (body or {}).get("data")
            d.write_log.append((f"rest:{base}#{prop}", json_dumps(state[prop])))
            return SimResponse(200, json_dumps({"status": "success"}))
        state = self._rest_state(path)
        if state is None:
            return SimResponse(404, "")
        return SimResponse(200, json_dumps({"status": "success", "data": state}))

    def _rest_state(self, path: str) -> dict | None:
        d = self.dev
        if path not in d.rest:
            rec = d.recorded(path)
            if not rec or rec.get("status") != 200:
                return None
            d.rest[path] = (json.loads(rec["text"]) or {}).get("data") or {}
        return d.rest[path]

    def _netset(self, body: dict) -> SimResponse:
        """Network settings API: resolver part only, backed by the root.Network.Resolver.* params."""
        d = self.dev
        method, ver = body.get("method"), "1.15"
        if method == "getSupportedVersions":
            return SimResponse(200, json_dumps({"apiVersion": ver, "method": method, "data": {"apiVersions": [ver]}}))
        get = lambda n: d.params.get(d.actual(n) or n, "")   # noqa: E731
        if method == "getNetworkInfo":
            servers = [s for s in (get("root.Network.Resolver.NameServer1"), get("root.Network.Resolver.NameServer2"),
                                   get("root.Network.Resolver.NameServer3")) if s and s != "0.0.0.0"]
            resolver = {"useDhcpResolverInfo": get("root.Network.Resolver.ObtainFromDHCP").lower() == "yes",
                        "nameServers": servers, "staticNameServers": servers, "maxSupportedStaticNameServers": 3,
                        "searchDomains": [], "staticSearchDomains": [], "staticDomainName": "", "domainName": ""}
            return SimResponse(200, json_dumps({"apiVersion": ver, "method": method,
                                                "data": {"system": {"resolver": resolver}, "devices": []}}))
        if method == "setResolverConfiguration":
            prm = body.get("params") or {}
            servers = list(prm.get("staticNameServers") or [])
            if len(servers) > 3:
                return SimResponse(200, json_dumps({"apiVersion": ver, "method": method,
                                                    "error": {"code": 2104, "message": "Too many name servers"}}))
            d.params[d.actual("root.Network.Resolver.ObtainFromDHCP") or "root.Network.Resolver.ObtainFromDHCP"] = \
                "yes" if prm.get("useDhcpResolverInfo") else "no"
            for i in (1, 2):
                key = d.actual(f"root.Network.Resolver.NameServer{i}") or f"root.Network.Resolver.NameServer{i}"
                d.params[key] = servers[i - 1] if len(servers) >= i else ""
            d.write_log.append(("netset:resolver", ",".join(servers)))
            return SimResponse(200, json_dumps({"apiVersion": ver, "method": method, "data": {}}))
        return SimResponse(200, json_dumps({"apiVersion": ver, "method": method,
                                            "error": {"code": 1000, "message": "unknown method"}}))

    def _pwdgrp(self, method: str, query: dict) -> SimResponse:
        d = self.dev
        g = d.groups()
        action = query.get("action", "")
        if action == "get":
            return SimResponse(200, "".join(f'{k}="{",".join(v)}"\r\n' for k, v in g.items()))
        if method != "POST":
            return SimResponse(200, "# Error: simulated camera expects POST for account changes\n")
        user = query.get("user", "")
        if d.reject_accounts:
            return SimResponse(200, f"# Error: could not change account {user}\n")
        if action == "add":
            if not user.isalnum():
                return SimResponse(200, "<html><body>Error: account user name.\n</body></html>")
            if user in g.get("digusers", []):
                return SimResponse(200, f"# Error: account {user} already exists\n")
            g.setdefault("digusers", []).append(user)
            for grp in query.get("sgrp", "").split(":"):
                g.setdefault(grp, []).append(user)
            d.passwords[user] = query.get("pwd", "")
            d.removed.discard(user)
            d.write_log.append((f"account:{user}", query.get("sgrp", "")))
            return SimResponse(200, f"Created account {user}.\n")
        if action == "remove":
            if user not in g.get("digusers", []):
                return SimResponse(200, f"# Error: no account {user}\n")
            if user in d.protected_accounts:
                return SimResponse(200, f"# Error: account {user} cannot be removed\n")
            for members in g.values():
                if user in members:
                    members.remove(user)
            d.passwords.pop(user, None)
            d.removed.add(user)
            d.write_log.append((f"account:{user}", "removed"))
            return SimResponse(200, f"Removed account {user}.\n")
        return SimResponse(200, "# Error: unknown action\n")


def json_dumps(o: Any) -> str:
    return json.dumps(o)


def sim_factory(devices: dict[str, SimDevice]):
    """client_factory(camera, scheme=None, **kw) for a set of simulated cameras keyed by host."""
    def factory(camera: Camera, scheme: str | None = None, **kw: Any) -> SimClient:
        return SimClient(devices[camera.host], camera, scheme=scheme)
    return factory
