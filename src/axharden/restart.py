"""Restart cameras (VAPIX restart.cgi) and wait until they answer again.

Used after changes that only take effect on a restart (e.g. AX-B-011 TLS ciphers), from the GUI prompt after
"Fix problems...", `apply --restart`, or the stand-alone `restart` command. Every restart is logged in the
audit log. Waiting polls one camera at a time with a gap between attempts (never a burst), and a rejected
login stops the wait at once (§7.5: never retry on 401/403).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable

from .apply import Change, Write
from .audit import (AuditSettings, CameraResult, ClientFactory, base_meta, finish_meta, make_run_dir, now_iso,
                    run_parallel, safe_name, write_private)
from .auditlog import AuditLog
from .catalog import Catalog, Profile
from .inventory import Camera, PasswordFindings
from .vapix.client import AuthFailed, CameraError

log = logging.getLogger(__name__)

KIND_RESTART = "restart"
RESTART_PATH = "/axis-cgi/restart.cgi"
ALIVE_PATH = "/axis-cgi/param.cgi?action=list&group=root.Brand.Brand"
RESTART_CONTROL = "RESTART"


def needs_restart(results: list[CameraResult]) -> list[str]:
    """Hosts with a verified change that only takes effect after a restart."""
    return [r.camera["host"] for r in results
            if any(ch.get("requires_reboot") and ch.get("status") == "verified" for ch in r.changes)]


def _alive(factory: ClientFactory, camera: Camera) -> bool:
    client = factory(camera)
    try:
        client.negotiate()
        client.get(ALIVE_PATH)
        return True
    finally:
        client.close()


def restart_camera(camera: Camera, factory: ClientFactory, alog: AuditLog, run_id: str, run_dir: Path,
                   timeout: float = 300, poll: float = 10, down_wait: float = 20,
                   sleep: Callable[[float], None] = time.sleep,
                   clock: Callable[[], float] = time.monotonic) -> CameraResult:
    res = CameraResult(camera=camera.public_dict(), status="OK", started=now_iso(), scheme=camera.protocol)
    ch = Change(camera=camera.host, control_id=RESTART_CONTROL, title="Restart camera", group=9, kind="restart",
                writes=[Write("restart", "running", "restarted")])
    client = factory(camera)
    requests = 0
    try:
        res.auth_scheme = client.negotiate()
        alog.append("write", run_id=run_id, run_kind=KIND_RESTART, camera=camera.host, camera_name=camera.name,
                    control=RESTART_CONTROL, setting="restart", old="running", new="restarted")
        client.get(RESTART_PATH)
        ch.status = "applied"
    except CameraError as e:
        res.status, res.error = e.code, str(e)
        ch.status, ch.detail = "skipped", f"Not restarted: {e.code}."
        alog.append("camera_error", run_id=run_id, camera=camera.host, detail=f"{e.code}: {e}")
    finally:
        requests += client.request_count
        client.close()

    if ch.status == "applied":
        t0 = clock()
        sleep(down_wait)                       # give it time to go down before the first check
        problem = f"did not answer again within {int(timeout)} s; check the camera"
        while clock() - t0 < timeout:
            try:
                if _alive(factory, camera):
                    problem = ""
                    break
            except AuthFailed as e:
                problem = f"answers again but rejected the login ({e}); not retried"
                break
            except CameraError:
                pass                           # still restarting
            sleep(poll)
        ch.status = "failed" if problem else "verified"
        ch.detail = problem or f"Restarted and answering again after about {int(clock() - t0)} s."
        if problem:
            res.status, res.error = "LOST_CONTACT", f"Camera {problem}."
        alog.append("verify", run_id=run_id, camera=camera.host, control=RESTART_CONTROL,
                    result="mismatch" if problem else "ok", detail=ch.detail)
    res.requests = requests
    res.changes = [ch.to_dict()]
    res.finished = now_iso()
    write_private(run_dir / "cameras" / f"{safe_name(camera.host)}.json", json.dumps(res.to_dict(), indent=1,
                                                                                      default=str))
    return res


def run_restart(cameras: list[Camera], catalog: Catalog, settings: AuditSettings, output_dir: Path,
                confirmed_by: str, client_factory: ClientFactory | None = None,
                progress: Callable[[CameraResult], None] | None = None, simulated: bool = False,
                reason: str = "", **wait: float) -> tuple[str, Path, list[CameraResult]]:
    factory = client_factory or settings.live_factory()
    run_id, run_dir = make_run_dir(output_dir)
    meta = base_meta(run_id, KIND_RESTART, catalog, Profile("restart", "", []), settings, PasswordFindings(),
                     cameras, simulated)
    meta.update(confirmed_by=confirmed_by, reason=reason)
    alog = AuditLog(output_dir / "audit_log.jsonl", operator=settings.operator)
    alog.append("run_start", run_id=run_id, run_kind=KIND_RESTART, cameras=len(cameras), confirmed_by=confirmed_by,
                simulated=simulated, reason=reason)
    t0 = time.monotonic()
    results = run_parallel(cameras, settings.workers,
                           lambda cam: restart_camera(cam, factory, alog, run_id, run_dir, **wait), progress)
    finish_meta(meta, results, t0, run_dir)
    from .apply import change_summary
    meta["change_summary"] = change_summary(results)
    write_private(run_dir / "run.json", json.dumps(meta, indent=1, default=str))
    alog.append("run_end", run_id=run_id, run_kind=KIND_RESTART, summary=meta["change_summary"])
    return run_id, run_dir, results
