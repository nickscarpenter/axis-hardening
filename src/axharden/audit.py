"""Audit: read every camera, evaluate controls, write per-camera evidence snapshots (CLAUDE.md §7.1)."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import GUIDE_REF, __version__
from .catalog import Catalog, Profile
from .evaluate import AuditContext, ControlResult, evaluate
from .inventory import Camera, Credential, PasswordFindings
from .vapix import device as vdevice
from .vapix import params as vparams
from .vapix.client import CameraClient, CameraError, TLSPolicy
from .version import AxisVersion, v

log = logging.getLogger(__name__)

MIN_SUPPORTED_OS = v("10.0")
SNAPSHOT_VERSION = 1
ClientFactory = Callable[..., Any]   # (camera, scheme=None) -> CameraClient-like


@dataclass
class AuditSettings:
    tls: TLSPolicy = field(default_factory=TLSPolicy)
    workers: int = 8
    timeout: float = 10.0
    min_delay: float = 0.1
    min_axis_os: str = "10.0"
    operator: str = ""
    customer: str = ""        # free text for the report (GUI step 2 / --customer-name)
    site_name: str = ""       # free text for the report (GUI step 2 / --site-name)

    def live_factory(self) -> ClientFactory:
        def factory(camera: Camera, scheme: str | None = None, **_: Any) -> CameraClient:
            return CameraClient(camera, tls=self.tls, timeout=self.timeout, min_delay=self.min_delay, scheme=scheme)
        return factory


@dataclass
class CameraResult:
    camera: dict
    status: str                      # OK | OUT_OF_SCOPE | UNREACHABLE | AUTH_FAILED | TLS_ERROR | INSECURE_AUTH_REFUSED | LOST_CONTACT | ERROR
    error: str = ""
    device: dict = field(default_factory=dict)
    results: list[ControlResult] = field(default_factory=list)     # before (audit)
    auth_scheme: str = ""
    scheme: str = ""
    requests: int = 0
    started: str = ""
    finished: str = ""
    changes: list[dict] = field(default_factory=list)              # apply/rollback runs
    after: list[ControlResult] = field(default_factory=list)       # re-audit after changes

    @property
    def reachable(self) -> bool:
        return self.status in ("OK", "OUT_OF_SCOPE", "LOST_CONTACT") and bool(self.results)

    def to_dict(self) -> dict:
        return {"camera": self.camera, "status": self.status, "error": self.error, "device": self.device,
                "results": [r.to_dict() for r in self.results], "auth_scheme": self.auth_scheme,
                "scheme": self.scheme, "requests": self.requests, "started": self.started, "finished": self.finished,
                "changes": self.changes, "after": [r.to_dict() for r in self.after]}

    @classmethod
    def from_dict(cls, d: dict) -> "CameraResult":
        return cls(camera=d["camera"], status=d["status"], error=d.get("error", ""), device=d.get("device") or {},
                   results=[ControlResult.from_dict(r) for r in d.get("results") or []],
                   auth_scheme=d.get("auth_scheme", ""), scheme=d.get("scheme", ""), requests=d.get("requests", 0),
                   started=d.get("started", ""), finished=d.get("finished", ""), changes=d.get("changes") or [],
                   after=[ControlResult.from_dict(r) for r in d.get("after") or []])


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def safe_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def write_private(path: Path, data: str) -> None:
    """Write a file readable by the owner only (best effort on Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _device_summary(info: dict, tree: vparams.ParamTree | None) -> dict:
    d = dict(info)
    if tree is not None:
        for k, val in vdevice.device_info_from_params(tree).items():
            d.setdefault(k, val)
        mac = vdevice.mac_from_params(tree)
        if mac:
            d["MAC"] = mac
    return d


def _run_checks(camera: Camera, catalog: Catalog, control_ids: list[str], tree: vparams.ParamTree,
                info: dict, api_ids: set[str], passwords: PasswordFindings,
                probe: Callable[[str, Callable[[], Any]], Any], client: Any, min_axis_os: str) -> list[ControlResult]:
    ver = AxisVersion.parse(info.get("Version"))
    ctx = AuditContext(camera=camera, params=tree, version=ver, device_info=info, api_ids=api_ids,
                       passwords=passwords, probe=probe, client=client)
    results = []
    for cid in control_ids:
        ctl = catalog.get(cid)
        if ctl.handler == "os_version":
            ctl.handler_args.setdefault("min_axis_os", min_axis_os)
        results.append(evaluate(ctl, ctx))
    return results


@dataclass
class CameraRead:
    info: dict
    tree: vparams.ParamTree
    apis: list
    results: list[ControlResult]
    probes: dict


def read_camera(client: Any, camera: Camera, catalog: Catalog, control_ids: list[str], passwords: PasswordFindings,
                min_axis_os: str) -> CameraRead:
    """Read everything once (device info, the whole param tree in one call, API list) and evaluate controls."""
    probes: dict[str, Any] = {}

    def probe(key: str, fn: Callable[[], Any]) -> Any:
        if key not in probes:
            probes[key] = fn()
        return probes[key]

    info = vdevice.basic_device_info(client)
    tree = vparams.list_all(client)
    apis = vdevice.api_list(client)
    info = _device_summary(info, tree)
    api_ids = {a.get("id", "") for a in apis}
    results = _run_checks(camera, catalog, control_ids, tree, info, api_ids, passwords, probe, client, min_axis_os)
    return CameraRead(info, tree, apis, results, probes)


def audit_camera(camera: Camera, catalog: Catalog, control_ids: list[str], settings: AuditSettings,
                 passwords: PasswordFindings, run_dir: Path, client_factory: ClientFactory | None = None) -> CameraResult:
    res = CameraResult(camera=camera.public_dict(), status="OK", started=now_iso(), scheme=camera.protocol)
    snapshot: dict[str, Any] = {"snapshot_version": SNAPSHOT_VERSION, "tool_version": __version__}
    client = (client_factory or settings.live_factory())(camera)
    try:
        res.auth_scheme = client.negotiate()
        read = read_camera(client, camera, catalog, control_ids, passwords, settings.min_axis_os)
        res.device, res.results = read.info, read.results
        snapshot.update(params=read.tree.to_dict(), apis=read.apis, device=read.info, probes=read.probes)
        ver = AxisVersion.parse(read.info.get("Version"))
        if ver is not None and ver < MIN_SUPPORTED_OS:
            res.status = "OUT_OF_SCOPE"
            res.error = f"AXIS OS {ver} is below 10.0; audited read-only, no changes will be planned."
    except CameraError as e:
        res.status, res.error = e.code, str(e)
        log.warning("%s: %s %s", camera.label, e.code, e)
    except Exception as e:  # never stop the batch
        res.status, res.error = "ERROR", f"{type(e).__name__}: {e}"
        log.exception("%s: unexpected error", camera.label)
    finally:
        res.requests = client.request_count
        client.close()
        res.finished = now_iso()
    snapshot.update(res.to_dict())
    write_private(run_dir / "cameras" / f"{safe_name(camera.host)}.json", json.dumps(snapshot, indent=1, default=str))
    return res


# ---------------------------------------------------------------- simulate (replay snapshots/fixtures)

def load_fixture_cameras(path: Path) -> list[tuple[Camera, dict]]:
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    out = []
    for f in files:
        snap = json.loads(f.read_text(encoding="utf-8"))
        if "params" not in snap:
            continue
        c = snap.get("camera") or {}
        cam = Camera(host=c.get("host") or f.stem, port=c.get("port"),
                     credential=Credential(c.get("username", "root"), "simulated-" + secrets.token_hex(8)),
                     name=c.get("name", ""), customer=c.get("customer", "") or c.get("site", ""), protocol=c.get("protocol", "https"),
                     profile=c.get("profile", ""), ports=c.get("ports") or [], notes=c.get("notes", ""))
        out.append((cam, snap))
    return out


def simulated_factory(loaded: list[tuple[Camera, dict]]) -> tuple[ClientFactory, dict]:
    from .vapix.sim import SimDevice, sim_factory
    devices = {cam.host: SimDevice(snap) for cam, snap in loaded}
    return sim_factory(devices), devices


# ---------------------------------------------------------------- batch

def make_run_dir(output_dir: Path) -> tuple[str, Path]:
    run_id = new_run_id()
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(run_dir, 0o700)
    except OSError:
        pass
    return run_id, run_dir


def base_meta(run_id: str, kind: str, catalog: Catalog, profile: Profile, settings: AuditSettings,
              passwords: PasswordFindings, cameras: list[Camera], simulated: bool) -> dict:
    return {
        "run_id": run_id, "kind": kind, "started": now_iso(), "tool_version": __version__, "guide": GUIDE_REF,
        "catalog_sha256": catalog.sha256, "profile": profile.name, "control_ids": profile.control_ids,
        "operator": settings.operator, "customer": settings.customer, "site_name": settings.site_name,
        "insecure_tls": settings.tls.insecure,
        "ca_bundle": settings.tls.verify if isinstance(settings.tls.verify, str) else None,
        "simulated": simulated, "min_axis_os": settings.min_axis_os,
        "password_findings": {"shared_groups": passwords.shared_groups, "weak": passwords.weak},
        "cameras": [c.public_dict() for c in cameras],
    }


def run_parallel(cameras: list[Camera], workers: int, fn: Callable[[Camera], CameraResult],
                 progress: Callable[[CameraResult], None] | None) -> list[CameraResult]:
    results: list[CameraResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        # One task per camera => at most one in-flight request per camera.
        futures = {pool.submit(fn, cam): cam for cam in cameras}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if progress:
                progress(r)
    order = {c.host: i for i, c in enumerate(cameras)}
    results.sort(key=lambda r: order.get(r.camera["host"], 0))
    return results


def finish_meta(meta: dict, results: list[CameraResult], t0: float, run_dir: Path) -> None:
    meta["finished"] = now_iso()
    meta["duration_s"] = round(time.monotonic() - t0, 1)
    meta["summary"] = {"in_scope": len(results), "reachable": sum(r.reachable for r in results),
                       "failed": sum(not r.reachable for r in results)}
    write_private(run_dir / "run.json", json.dumps(meta, indent=1, default=str))


def set_baseline(meta: dict, profile: Profile) -> None:
    """Record the baseline a run is scored against. audit-only (every control) means no baseline."""
    if profile.name == "audit-only" or not profile.control_ids:
        meta["baseline"], meta["baseline_ids"] = "", None
    else:
        meta["baseline"], meta["baseline_ids"] = profile.name, list(profile.control_ids)


def run_audit(cameras: list[Camera], catalog: Catalog, profile: Profile, settings: AuditSettings,
              passwords: PasswordFindings, output_dir: Path, client_factory: ClientFactory | None = None,
              progress: Callable[[CameraResult], None] | None = None,
              simulated: bool = False) -> tuple[str, Path, list[CameraResult]]:
    run_id, run_dir = make_run_dir(output_dir)
    meta = base_meta(run_id, "audit", catalog, profile, settings, passwords, cameras, simulated)
    # Every control is always read (Fix problems needs them all, e.g. to put settings back to default); the
    # profile is the baseline the results are scored and reported against.
    all_ids = [c.id for c in catalog.controls]
    meta["control_ids"] = all_ids
    set_baseline(meta, profile)
    t0 = time.monotonic()
    results = run_parallel(cameras, settings.workers,
                           lambda cam: audit_camera(cam, catalog, all_ids, settings, passwords, run_dir,
                                                    client_factory),
                           progress)
    finish_meta(meta, results, t0, run_dir)
    return run_id, run_dir, results


def load_run(run_dir: Path) -> tuple[dict, list[CameraResult]]:
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    by_host = {}
    for f in (run_dir / "cameras").glob("*.json"):
        snap = json.loads(f.read_text(encoding="utf-8"))
        by_host[snap["camera"]["host"]] = CameraResult.from_dict(snap)
    ordered = [by_host[c["host"]] for c in meta.get("cameras", []) if c["host"] in by_host]
    return meta, ordered
