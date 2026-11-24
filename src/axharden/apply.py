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
from .catalog import Catalog, Control, Profile
from .evaluate import COMPLIANT, NON_COMPLIANT, ControlResult
from .inventory import Camera, PasswordFindings
from .vapix import params as vparams
from .vapix.client import CameraError

log = logging.getLogger(__name__)

G_PARAMS, G_HANDLERS, G_CIPHERS, G_HTTPS_ONLY, G_WEBUI = 1, 2, 3, 4, 5
SPECIAL_GROUP = {"AX-B-011": G_CIPHERS, "AX-B-009": G_HTTPS_ONLY, "AX-B-016": G_WEBUI}
GROUP_NAME = {G_PARAMS: "settings", G_HANDLERS: "ACAP/REST settings", G_CIPHERS: "TLS ciphers",
              G_HTTPS_ONLY: "HTTPS only", G_WEBUI: "web interface"}
ANON_PATH = "/config/rest/basic-device-info/v2beta/allowAnonymous"


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

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Change":
        d = dict(d)
        d["writes"] = [Write(**w) for w in d.get("writes") or []]
        return cls(**d)


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
    elif ctl.handler == "network_ports":
        return [], "Network port controls arrive in phase 3."
    else:
        return [], "This control is not writable by the tool."
    if not writes:
        return [], "Nothing to write."
    group = SPECIAL_GROUP.get(ctl.id, G_HANDLERS if kind != "param" else G_PARAMS)
    return [Change(camera=host, control_id=ctl.id, title=ctl.title, group=group, kind=kind, writes=writes,
                   disruptive=ctl.disruptive, requires_reboot=ctl.requires_reboot, warning=ctl.warning or "")], None


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
        for r in before.results:
            if r.id not in wanted:
                continue
            chs, reason = changes_for(catalog.get(r.id), r, cam.host)
            plan.changes.extend(chs)
            if reason:
                plan.skipped.append((r.id, reason))
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
                             "warning": ch.warning})
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
                if not _eq(now, w.new):
                    problems.append(f"{w.name} reads back as {now!r}, expected {w.new!r}")
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
