"""Create separate camera user accounts (and undo that), e.g. a viewer/operator account for the VMS.

Guide p.16: do not use the administrator account for daily use; create accounts with the least privilege
needed. Up to two accounts per camera come from the inventory columns new_username / new_role / new_password
and new_username2 / new_role2 / new_password2, or are typed in once for a set of cameras. Passwords are held
in memory only: they are sent to the camera in a POST body and never logged, saved, or shown in reports.

Per camera: read the account list -> for each new account: skip if the name already exists (never changes an
existing account) -> create -> read back (listed with the right role) -> log in once with it.

Optionally (remove_login) the account the tool logged in with (e.g. root) is then removed, but only when one of
the new accounts is an Administrator that was read back with that role and has logged in successfully. The
removal is done while logged in as that new administrator, which proves it works before the old one goes. If the
camera refuses (some AXIS OS versions do not allow removing root) the old account is simply left in place.

Undo removes only accounts this tool created in the given run. If that run removed the login account, undo
first re-creates it (same name and role, password from the camera list) while logged in as the new
administrator, checks it can log in, and only then removes the new accounts.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from .apply import Change, Write
from .audit import (AuditSettings, CameraResult, ClientFactory, base_meta, finish_meta, load_run, make_run_dir,
                    now_iso, read_camera, safe_name, write_private)
from .auditlog import AuditLog
from .catalog import Catalog, Profile
from .inventory import Camera, Credential, NewAccount, PasswordFindings
from .vapix import users as vusers
from .vapix.client import AuthFailed, CameraError

log = logging.getLogger(__name__)

USERS_CONTROL = "AX-C-014"
KIND_CREATE, KIND_UNDO = "accounts", "accounts-undo"
CH_CREATE, CH_REMOVE_LOGIN, CH_REMOVE, CH_RESTORE = "account", "account-remove-login", "account-remove", \
    "account-restore"
LOGIN_TEST_PATH = "/axis-cgi/param.cgi?action=list&group=root.Brand.ProdNbr"
MAX_ACCOUNTS = 2


def _profile(name: str) -> Profile:
    return Profile(name=name, description="", control_ids=[USERS_CONTROL])


def with_accounts(cameras: list[Camera], accounts: list[NewAccount] | None) -> list[Camera]:
    """Cameras that will get accounts: the typed-in ones for all of them, else each camera's own columns."""
    if accounts:
        return [dataclasses.replace(c, new_accounts=list(accounts)) for c in cameras]
    return [c for c in cameras if c.new_accounts]


def account_problems(cameras: list[Camera], remove_login: bool = False) -> list[str]:
    out = []
    for c in cameras:
        names = set()
        for a in c.new_accounts:
            prob = vusers.username_problem(a.username, c.credential.username) or \
                vusers.password_problem(a.credential.password, a.username)
            if prob:
                out.append(f"{c.label}: {a.username or '(blank)'}: {prob}")
            if a.username.lower() in names:
                out.append(f"{c.label}: the two new accounts have the same name ({a.username})")
            names.add(a.username.lower())
        if len(c.new_accounts) > MAX_ACCOUNTS:
            out.append(f"{c.label}: at most {MAX_ACCOUNTS} new accounts per camera")
        if remove_login and not any(a.role == "admin" for a in c.new_accounts):
            out.append(f"{c.label}: to remove the login account '{c.credential.username}', one of the new "
                       "accounts must be an Administrator (otherwise nobody could manage the camera)")
    return out


def shared_new_passwords(cameras: list[Camera]) -> list[list[str]]:
    """New accounts that share a password (guide p.31: common password). Compared in memory only."""
    from .inventory import password_findings
    proxies = [dataclasses.replace(c, name=f"{c.label}: {a.username}", credential=a.credential)
               for c in cameras for a in c.new_accounts]
    return password_findings(proxies).shared_groups if proxies else []


def _login_test(factory: ClientFactory, camera: Camera, cred: Credential, scheme: str | None) -> str:
    """One login with the given account. Returns '' on success or a problem text. Never retried."""
    probe_cam = dataclasses.replace(camera, credential=cred, new_accounts=[])
    client = factory(probe_cam, scheme=scheme)
    try:
        client.negotiate()
        client.get(LOGIN_TEST_PATH)
        return ""
    except AuthFailed as e:
        if "403" in str(e):
            return ""   # logged in; this role may simply not read parameters
        return f"the camera did not accept a login with '{cred.username}' ({e})"
    except CameraError as e:
        return f"login test inconclusive: {e}"
    finally:
        client.close()


def _write_name(ch: dict) -> str:
    return ch["writes"][0]["name"].split(" ", 1)[1]


class _Ctx:
    """Per-camera plumbing shared by create and undo."""

    def __init__(self, camera: Camera, catalog: Catalog, settings: AuditSettings, factory: ClientFactory,
                 alog: AuditLog, run_id: str, kind: str):
        self.camera, self.catalog, self.settings, self.factory = camera, catalog, settings, factory
        self.alog, self.run_id, self.kind = alog, run_id, kind
        self.res = CameraResult(camera=camera.public_dict(), status="OK", started=now_iso(), scheme=camera.protocol)
        self.changes: list[Change] = []
        self.extras: list[dict] = []     # extra fields stored with each change (same index)
        self.requests = 0

    def change(self, title: str, kind: str, setting: str, old: str, new: str, **extra: Any) -> Change:
        ch = Change(camera=self.camera.host, control_id=USERS_CONTROL, title=title, group=2, kind=kind,
                    writes=[Write(setting, old, new)])
        self.changes.append(ch)
        self.extras.append(extra)
        return ch

    def log_write(self, ch: Change) -> None:
        w = ch.writes[0]
        self.alog.append("write", run_id=self.run_id, camera=self.camera.host, control=USERS_CONTROL,
                         setting=w.name, old=w.old, new=w.new, kind=self.kind)

    def log_verify(self, ch: Change, problems: list[str], ok_text: str) -> None:
        ch.status = "failed" if problems else "verified"
        ch.detail = "; ".join(problems) if problems else ok_text
        self.alog.append("verify", run_id=self.run_id, camera=self.camera.host, control=USERS_CONTROL,
                         result="ok" if not problems else "mismatch", detail=ch.detail)

    def log_error(self, ch: Change, e: Exception) -> None:
        ch.status, ch.detail = "failed", str(e)
        self.alog.append("write_result", run_id=self.run_id, camera=self.camera.host, control=USERS_CONTROL,
                         result="error", detail=str(e))

    def client(self, cred: Credential | None = None, scheme: str | None = None):
        cam = self.camera if cred is None else dataclasses.replace(self.camera, credential=cred)
        return self.factory(cam, scheme=scheme) if scheme else self.factory(cam)

    def read_after(self, client) -> None:
        self.res.after = read_camera(client, self.camera, self.catalog, [USERS_CONTROL], PasswordFindings(),
                                     self.settings.min_axis_os).results

    def finish(self, run_dir: Path) -> CameraResult:
        res = self.res
        res.requests = self.requests
        res.finished = now_iso()
        res.changes = [{**ch.to_dict(), **ex} for ch, ex in zip(self.changes, self.extras)]
        write_private(run_dir / "cameras" / f"{safe_name(self.camera.host)}.json",
                      json.dumps(res.to_dict(), indent=1, default=str))
        return res


def _not_attempted(ctx: _Ctx, why: str) -> None:
    for ch in ctx.changes:
        if ch.status == "planned":
            ch.status, ch.detail = "skipped", why


def _create_camera(camera: Camera, catalog: Catalog, settings: AuditSettings, factory: ClientFactory,
                   alog: AuditLog, run_id: str, run_dir: Path, remove_login: bool) -> CameraResult:
    ctx = _Ctx(camera, catalog, settings, factory, alog, run_id, KIND_CREATE)
    login = camera.credential.username
    planned = [(a, ctx.change(f"Create account '{a.username}' ({vusers.role_label(a.role, a.ptz)})", CH_CREATE,
                              f"account {a.username}", "(none)", vusers.role_label(a.role, a.ptz)))
               for a in camera.new_accounts]
    rm = ctx.change(f"Remove the login account '{login}'", CH_REMOVE_LOGIN, f"account {login}", "",
                    "(removed)") if remove_login else None
    client = ctx.client()
    admin_ok: NewAccount | None = None
    try:
        ctx.res.auth_scheme = client.negotiate()
        read = read_camera(client, camera, catalog, [USERS_CONTROL], PasswordFindings(), settings.min_axis_os)
        ctx.res.device, ctx.res.results = read.info, read.results
        existing = vusers.read_accounts(client)
        low = {u.lower(): u for u in existing}
        for acct, ch in planned:
            if acct.username.lower() in low:
                old = existing[low[acct.username.lower()]]
                ch.writes[0].old = vusers.role_label(old["role"], old["ptz"])
                ch.status, ch.detail = "skipped", ("An account with this name already exists, so it was left "
                                                   "unchanged (its password and role were not touched).")
                # an existing administrator can still be used to remove the login account, if its password works
                if remove_login and admin_ok is None and acct.role == "admin" and old["role"] == "admin" and \
                        not _login_test(factory, camera, acct.credential, client.scheme):
                    admin_ok = acct
                continue
            try:
                ctx.log_write(ch)
                vusers.add_account(client, acct.username, acct.credential.password, acct.role, acct.ptz)
                ch.status = "applied"
            except vusers.AccountError as e:
                ctx.log_error(ch, e)
                continue
            got = vusers.read_accounts(client).get(acct.username)
            problems = []
            if got is None:
                problems.append("account is not listed after creation")
            elif got["role"] != acct.role or got["ptz"] != acct.ptz:
                problems.append(f"account has role {vusers.role_label(got['role'], got['ptz'])}, "
                                f"expected {vusers.role_label(acct.role, acct.ptz)}")
            else:
                test = _login_test(factory, camera, acct.credential, client.scheme)
                if test:
                    problems.append(test)
            ctx.log_verify(ch, problems, "Verified: listed with the right role, and a test login worked.")
            if not problems and acct.role == "admin" and admin_ok is None:
                admin_ok = acct

        if rm is None:
            ctx.read_after(client)
        else:
            old = existing.get(login) or next((v for k, v in existing.items() if k.lower() == login.lower()), None)
            rm.writes[0].old = vusers.role_label(old["role"], old["ptz"]) if old else "?"
            if old:
                ctx.extras[-1].update(old_role=old["role"], old_ptz=old["ptz"])
            if admin_ok is None:
                rm.status, rm.detail = "skipped", (f"Kept '{login}': no new Administrator account could be "
                                                   "created and checked, so removing it could lock you out.")
                ctx.read_after(client)
            else:
                _remove_login(ctx, rm, admin_ok, client.scheme)
    except CameraError as e:
        ctx.res.status, ctx.res.error = e.code, str(e)
        _not_attempted(ctx, f"Not attempted: {e.code}.")
        alog.append("camera_error", run_id=run_id, camera=camera.host, detail=f"{e.code}: {e}")
    except Exception as e:  # never stop the batch
        ctx.res.status, ctx.res.error = "ERROR", f"{type(e).__name__}: {e}"
        _not_attempted(ctx, "Not attempted: unexpected error.")
        log.exception("%s: unexpected error", camera.label)
    finally:
        ctx.requests += client.request_count
        client.close()
    return ctx.finish(run_dir)


def _remove_login(ctx: _Ctx, rm: Change, admin: NewAccount, scheme: str | None) -> None:
    """Remove the login account while logged in as the new administrator."""
    login = ctx.camera.credential.username
    ctx.extras[-1]["login_as"] = admin.username
    aclient = ctx.client(admin.credential, scheme)
    try:
        aclient.negotiate()
        before = vusers.read_accounts(aclient)       # needs admin rights: proves the new account really is admin
        if before.get(admin.username, {}).get("role") != "admin":
            rm.status, rm.detail = "skipped", f"Kept '{login}': '{admin.username}' does not have administrator rights."
            ctx.read_after(aclient)
            return
        try:
            ctx.log_write(rm)
            vusers.remove_account(aclient, login)
            rm.status = "applied"
        except vusers.AccountError as e:
            rm.status = "failed"
            rm.detail = (f"The camera did not allow '{login}' to be removed (some AXIS OS versions never allow "
                         f"removing root), so it was left in place. The new accounts were kept. ({e})")
            ctx.alog.append("write_result", run_id=ctx.run_id, camera=ctx.camera.host, control=USERS_CONTROL,
                            result="error", detail=rm.detail)
            ctx.read_after(aclient)
            return
        problems = ["account is still listed after removal"] if login in vusers.read_accounts(aclient) else []
        ctx.log_verify(rm, problems, f"Verified: removed. From now on log in as '{admin.username}': update the "
                                     "camera list (username and password columns).")
        ctx.read_after(aclient)
    finally:
        ctx.requests += aclient.request_count
        aclient.close()


def _run(kind: str, jobs: list[tuple[Camera, Any]], catalog: Catalog, settings: AuditSettings, output_dir: Path,
         confirmed_by: str, client_factory: ClientFactory | None, progress: Callable[[CameraResult], None] | None,
         simulated: bool, extra_meta: dict, work: Callable) -> tuple[str, Path, list]:
    from .audit import run_parallel
    factory = client_factory or settings.live_factory()
    run_id, run_dir = make_run_dir(output_dir)
    cams = [c for c, _ in jobs]
    pf = PasswordFindings()
    if kind == KIND_CREATE:
        pf.shared_groups = shared_new_passwords(cams)
    meta = base_meta(run_id, kind, catalog, _profile("user accounts"), settings, pf, cams, simulated)
    meta.update(confirmed_by=confirmed_by, **extra_meta)
    alog = AuditLog(output_dir / "audit_log.jsonl", operator=settings.operator)
    alog.append("run_start", run_id=run_id, run_kind=kind, cameras=len(cams), confirmed_by=confirmed_by,
                simulated=simulated, **extra_meta)
    by_host = dict((c.host, j) for c, j in jobs)
    t0 = time.monotonic()
    results = run_parallel(cams, settings.workers,
                           lambda cam: work(cam, by_host[cam.host], catalog, settings, factory, alog, run_id,
                                            run_dir), progress)
    finish_meta(meta, results, t0, run_dir)
    from .apply import change_summary
    meta["change_summary"] = change_summary(results)
    write_private(run_dir / "run.json", json.dumps(meta, indent=1, default=str))
    alog.append("run_end", run_id=run_id, run_kind=kind, summary=meta["change_summary"])
    return run_id, run_dir, results


def run_create_accounts(cameras: list[Camera], catalog: Catalog, settings: AuditSettings, output_dir: Path,
                        confirmed_by: str, client_factory: ClientFactory | None = None,
                        progress: Callable[[CameraResult], None] | None = None,
                        simulated: bool = False, remove_login: bool = False) -> tuple[str, Path, list[CameraResult]]:
    """cameras must each carry new_accounts (see with_accounts). remove_login: also remove the login account
    once a new Administrator account has been verified (see module docstring)."""
    todo = [c for c in cameras if c.new_accounts]

    def work(cam, _job, catalog, settings, factory, alog, run_id, run_dir):
        return _create_camera(cam, catalog, settings, factory, alog, run_id, run_dir, remove_login)
    return _run(KIND_CREATE, [(c, None) for c in todo], catalog, settings, output_dir, confirmed_by,
                client_factory, progress, simulated, {"remove_login": remove_login}, work)


# ---------------------------------------------------------------- undo

@dataclasses.dataclass
class UndoJob:
    camera: Camera                         # credential = the account the tool used before the run
    remove: list[str]                      # accounts the run created
    restore: dict | None = None            # {"username", "role", "ptz"} if the run removed the login account
    admin: Credential | None = dataclasses.field(default=None, repr=False)   # new admin, to restore with

    @property
    def summary(self) -> str:
        parts = []
        if self.restore:
            parts.append(f"put back '{self.restore['username']}'")
        if self.remove:
            parts.append("remove " + ", ".join(self.remove))
        return "; ".join(parts)


PasswordAsk = Callable[[str, str], "str | None"]   # (username, why) -> password, None = cancelled


def build_account_undo(run_dir: Path, cameras: list[Camera], only_host: str | None = None,
                       ask: PasswordAsk | None = None) -> tuple[dict, list[UndoJob]]:
    """(meta, jobs) undoing every account change of a create run.

    If the run removed the login account, the job needs two passwords: the old login account's (to re-create
    it) and the new administrator's (to log in). They are taken from the camera list when it has them: the
    original list (username/password = old login, new_* columns = new admin) or an updated one (username/password
    = new admin). Anything missing is asked for via `ask`; without it a ValueError is raised.
    """
    meta, results = load_run(run_dir)
    if meta.get("kind") != KIND_CREATE:
        raise ValueError(f"Run {meta.get('run_id')} is a {meta.get('kind')} run, not an account run.")
    by_host = {c.host: c for c in cameras}
    asked: dict[str, str] = {}

    def password(username: str, why: str) -> str:
        if username in asked:
            return asked[username]
        pw = ask(username, why) if ask else None
        if not pw:
            raise ValueError(f"The password for '{username}' is needed to {why}.")
        asked[username] = pw
        return pw

    jobs = []
    for r in results:
        host = r.camera["host"]
        if only_host and host != only_host:
            continue
        created = [_write_name(ch) for ch in r.changes
                   if ch.get("kind") == CH_CREATE and ch.get("status") in ("verified", "applied", "failed")]
        removed = next((ch for ch in r.changes if ch.get("kind") == CH_REMOVE_LOGIN
                        and ch.get("status") in ("verified", "applied")), None)
        if not created and not removed:
            continue
        if host not in by_host:
            raise ValueError(f"{host} is not in the inventory, so its credentials are unknown.")
        cam = dataclasses.replace(by_host[host])
        job = UndoJob(camera=cam, remove=created)
        if removed:
            old_user, admin_user = _write_name(removed), removed.get("login_as", "")
            inv = cam.credential
            job.restore = {"username": old_user, "role": removed.get("old_role") or "admin",
                           "ptz": bool(removed.get("old_ptz"))}
            if inv.username == old_user:
                old_cred = inv
            else:
                old_cred = Credential(old_user, password(old_user, f"put the account '{old_user}' back"))
            if inv.username == admin_user:
                job.admin = inv
            else:
                a = next((a for a in cam.new_accounts if a.username == admin_user and a.credential.password), None)
                job.admin = a.credential if a else Credential(admin_user, password(
                    admin_user, f"log in as '{admin_user}' and put '{old_user}' back"))
            job.camera = dataclasses.replace(cam, credential=old_cred)
        jobs.append(job)
    return meta, jobs


def _undo_camera(camera: Camera, job: UndoJob, catalog: Catalog, settings: AuditSettings, factory: ClientFactory,
                 alog: AuditLog, run_id: str, run_dir: Path) -> CameraResult:
    ctx = _Ctx(camera, catalog, settings, factory, alog, run_id, KIND_UNDO)
    login = camera.credential.username
    restore = None
    if job.restore:
        rr = job.restore
        restore = ctx.change(f"Put back the login account '{rr['username']}' (undo)", CH_RESTORE,
                             f"account {rr['username']}", "(none)", vusers.role_label(rr["role"], rr["ptz"]))
    removes = [ctx.change(f"Remove account '{u}' (undo)", CH_REMOVE, f"account {u}", "", "(removed)")
               for u in job.remove]
    client = None
    try:
        if restore is not None:
            aclient = ctx.client(job.admin)
            try:
                ctx.res.auth_scheme = aclient.negotiate()
                existing = vusers.read_accounts(aclient)
                rr = job.restore
                if rr["username"] in existing:
                    restore.status, restore.detail = "skipped", "The account is already there."
                else:
                    try:
                        ctx.log_write(restore)
                        vusers.add_account(aclient, rr["username"], camera.credential.password, rr["role"], rr["ptz"])
                        restore.status = "applied"
                    except vusers.AccountError as e:
                        ctx.log_error(restore, e)
                if restore.status == "applied":
                    problems = [] if rr["username"] in vusers.read_accounts(aclient) else ["not listed after creation"]
                    if not problems:
                        test = _login_test(factory, camera, camera.credential, aclient.scheme)
                        if test:
                            problems.append(test)
                    ctx.log_verify(restore, problems, "Verified: back, and a test login worked.")
            finally:
                ctx.requests += aclient.request_count
                aclient.close()
            if restore.status not in ("verified", "skipped"):
                _not_attempted(ctx, f"Not attempted: '{job.restore['username']}' could not be put back, so the "
                                    "new accounts were kept (otherwise nobody could log in).")
                return ctx.finish(run_dir)

        client = ctx.client()
        a = client.negotiate()
        ctx.res.auth_scheme = ctx.res.auth_scheme or a
        read = read_camera(client, camera, catalog, [USERS_CONTROL], PasswordFindings(), settings.min_axis_os)
        ctx.res.device, ctx.res.results = read.info, read.results
        existing = vusers.read_accounts(client)
        for ch in removes:
            u = _write_name(ch.to_dict())
            if u.lower() == login.lower() or u.lower() in vusers.RESERVED:
                ch.status, ch.detail = "skipped", "Refused: never removes the login account or a built-in account."
                continue
            if u not in existing:
                ch.status, ch.detail = "skipped", "Account no longer exists; nothing to remove."
                continue
            old = existing[u]
            ch.writes[0].old = vusers.role_label(old["role"], old["ptz"])
            try:
                ctx.log_write(ch)
                vusers.remove_account(client, u)
                ch.status = "applied"
            except vusers.AccountError as e:
                ctx.log_error(ch, e)
                continue
            problems = ["account is still listed after removal"] if u in vusers.read_accounts(client) else []
            ctx.log_verify(ch, problems, "Verified: removed.")
        ctx.read_after(client)
    except CameraError as e:
        ctx.res.status, ctx.res.error = e.code, str(e)
        _not_attempted(ctx, f"Not attempted: {e.code}.")
        alog.append("camera_error", run_id=run_id, camera=camera.host, detail=f"{e.code}: {e}")
    except Exception as e:  # never stop the batch
        ctx.res.status, ctx.res.error = "ERROR", f"{type(e).__name__}: {e}"
        _not_attempted(ctx, "Not attempted: unexpected error.")
        log.exception("%s: unexpected error", camera.label)
    finally:
        if client is not None:
            ctx.requests += client.request_count
            client.close()
    return ctx.finish(run_dir)


def run_account_undo(run_dir: Path, jobs: list[UndoJob], catalog: Catalog, settings: AuditSettings,
                     output_dir: Path, confirmed_by: str, client_factory: ClientFactory | None = None,
                     progress: Callable[[CameraResult], None] | None = None,
                     simulated: bool = False) -> tuple[str, Path, list[CameraResult]]:
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    return _run(KIND_UNDO, [(j.camera, j) for j in jobs], catalog, settings, output_dir, confirmed_by,
                client_factory, progress, simulated, {"rollback_of": meta["run_id"]}, _undo_camera)


def login_changes(results: list[CameraResult]) -> dict[str, str]:
    """{host: new login username} for cameras whose login account was removed by a create run."""
    out = {}
    for r in results:
        for ch in r.changes:
            if ch.get("kind") == CH_REMOVE_LOGIN and ch.get("status") == "verified" and ch.get("login_as"):
                out[r.camera["host"]] = ch["login_as"]
    return out


def existing_accounts(result: CameraResult) -> dict[str, str]:
    """Accounts seen by the last audit (AX-C-014), {username: role}, for display."""
    for r in result.results:
        if r.id == USERS_CONTROL:
            return dict((r.observed or {}).get("accounts") or {})
    return {}


def fill_passwords(cameras: list[Camera], prompt: Callable[[str], str | None]) -> bool:
    """Ask for blank new-account passwords, once per new username. Returns False if the user cancelled."""
    asked: dict[str, str] = {}
    for c in cameras:
        for a in c.new_accounts:
            if a.credential.password:
                continue
            if a.username not in asked:
                pw = prompt(a.username)
                if pw is None:
                    return False
                asked[a.username] = pw
            a.credential = Credential(a.username, asked[a.username])
    return True
