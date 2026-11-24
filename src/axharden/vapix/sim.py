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
        if self.scheme == "http" and self._https_only():
            raise Unreachable("Connection failed: simulated camera only accepts HTTPS")

    def _https_only(self) -> bool:
        vals = [self.dev.params.get(f"root.System.BoaGroupPolicy.{g}", "") for g in ("admin", "operator", "viewer")]
        return all(v.lower() == "https" for v in vals)

    def negotiate(self) -> str:
        self._check()
        if self.dev.reject_auth:
            raise AuthFailed("HTTP 401: credentials rejected or account lacks rights")
        self.auth_scheme = self.dev.auth_scheme
        return self.auth_scheme

    # --- requests
    def request(self, method: str, path: str, *, ok_statuses: tuple[int, ...] = (200,), params: dict | None = None,
                json: dict | None = None, data: Any = None, **_: Any) -> SimResponse:
        self._check()
        if self.dev.reject_auth:
            raise AuthFailed("HTTP 401: credentials rejected or account lacks rights")
        with self.dev.lock:
            resp = self._route(method.upper(), path, dict(params or {}), json)
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

        if p == "/axis-cgi/basicdeviceinfo.cgi":
            return SimResponse(200, json_dumps({"apiVersion": "1.3", "data": {"propertyList": d.device}}))
        if p == "/axis-cgi/apidiscovery.cgi":
            return SimResponse(200, json_dumps({"apiVersion": "1.0", "data": {"apiList": d.apis}}))

        if p == "/axis-cgi/applications/config.cgi":
            name = query.get("name", "")
            rec = d.recorded(f"/axis-cgi/applications/config.cgi?action=get&name={name}")
            if rec is not None and rec.get("status") in (404, 501):
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

        rec = d.recorded(path)
        if rec is not None:
            return SimResponse(rec.get("status") or 500, rec.get("text", ""))
        return SimResponse(404, "")


def json_dumps(o: Any) -> str:
    return json.dumps(o)


def sim_factory(devices: dict[str, SimDevice]):
    """client_factory(camera, scheme=None, **kw) for a set of simulated cameras keyed by host."""
    def factory(camera: Camera, scheme: str | None = None, **kw: Any) -> SimClient:
        return SimClient(devices[camera.host], camera, scheme=scheme)
    return factory
