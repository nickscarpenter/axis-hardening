"""Command line interface (argparse: no extra dependency)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .audit import AuditSettings, CameraResult, load_fixture_cameras, run_audit, simulated_factory
from .catalog import CatalogError, list_profiles, load_catalog, load_profile, user_profiles_dir
from .evaluate import NON_COMPLIANT, compliance_pct
from .inventory import InventoryError, load_inventory, password_findings, write_templates
from .logging_setup import setup_logging
from .vapix.client import CameraError, TLSPolicy

log = logging.getLogger("axharden")


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _tls(args: argparse.Namespace) -> TLSPolicy:
    if getattr(args, "insecure", False):
        print("\n" + "!" * 72 + "\n!! WARNING: --insecure: camera TLS certificates will NOT be verified.\n"
              "!! Use only for self-signed / 802.1AR certificates not in your trust store.\n"
              "!! This is recorded in the report.\n" + "!" * 72 + "\n", file=sys.stderr)
        return TLSPolicy(verify=False)
    if getattr(args, "ca_bundle", None):
        if not Path(args.ca_bundle).exists():
            raise SystemExit(f"error: CA bundle not found: {args.ca_bundle}")
        return TLSPolicy(verify=str(args.ca_bundle))
    return TLSPolicy(verify=True)


def _load_cameras(args: argparse.Namespace):
    try:
        cams = load_inventory(args.inventory)
    except InventoryError as e:
        _err(f"inventory {args.inventory} has problems:")
        for m in e.errors:
            print(f"  - {m}", file=sys.stderr)
        raise SystemExit(2)
    if getattr(args, "customer", None):
        cams = [c for c in cams if c.customer.lower() == args.customer.lower()]
        if not cams:
            raise SystemExit(f"error: no cameras with customer {args.customer!r}")
    return cams


def _operator(args: argparse.Namespace) -> str:
    if args.operator:
        return args.operator
    if sys.stdin.isatty():
        try:
            return input("Operator name for the report: ").strip()
        except EOFError:
            return ""
    return ""


# ---------------------------------------------------------------- commands

def cmd_inventory_template(args: argparse.Namespace) -> int:
    for p in write_templates(args.out):
        print(f"wrote {p}")
    return 0


def cmd_inventory_check(args: argparse.Namespace) -> int:
    cams = _load_cameras(args)
    print(f"{len(cams)} camera(s) OK\n")
    print(f"{'host':<28} {'name':<22} {'customer':<14} {'proto':<6} {'user':<12} password")
    for c in cams:
        print(f"{c.address:<28} {c.name[:22]:<22} {c.customer[:14]:<14} {c.protocol:<6} {c.credential.username[:12]:<12} ********")
    new = [c for c in cams if c.new_accounts]
    if new:
        from .vapix.users import role_label
        print(f"\nNew accounts to create (with 'accounts' / Create accounts... in the GUI):")
        for c in new:
            for a in c.new_accounts:
                pw = "********" if a.credential.password else "(asked for when created)"
                print(f"  {c.address:<28} {a.username:<20} {role_label(a.role, a.ptz):<22} {pw}")
    pf = password_findings(cams)
    for g in pf.shared_groups:
        print(f"\nWARNING common password (guide p.31) shared by: {', '.join(g)}")
    if pf.weak:
        print(f"\nWARNING password shorter than 8 characters (guide p.16): {', '.join(pf.weak)}")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    from .discover import run_discover
    catalog = load_catalog(args.catalog)
    cams = _load_cameras(args)
    target = [c for c in cams if c.host == args.target or c.address == args.target]
    if not target:
        raise SystemExit(f"error: {args.target} is not in the inventory")
    try:
        res = run_discover(target[0], catalog, _tls(args), Path(args.output_dir))
    except CameraError as e:
        _err(f"{args.target}: {e.code}: {e}")
        return 1
    print(f"\nDevice: {res.device.get('ProdFullName', '?')}  AXIS OS {res.device.get('Version', '?')}  "
          f"serial {res.device.get('SerialNumber', '?')}")
    print(f"Parameters: {res.params_count}   APIs: {len(res.api_ids)}")
    groups = {"present": [], "case_differs": [], "missing": [], "pattern_matched": [], "pattern_none": []}
    for c in res.checks:
        groups[c.status].append(c)
    print(f"\nCatalog parameters present: {len(groups['present']) + len(groups['pattern_matched'])}")
    if groups["case_differs"]:
        print("\nCase differs (catalog -> device):")
        for c in groups["case_differs"]:
            print(f"  {c.control_id}  {c.name}  ->  {c.actual}")
    if groups["missing"] or groups["pattern_none"]:
        print("\nMissing on this firmware (NOT_SUPPORTED unless optional):")
        for c in groups["missing"] + groups["pattern_none"]:
            print(f"  {c.control_id}  {c.name}")
    print(f"\nTo mark verified, add  \"{res.model_fw}\"  to verified_on of the matching controls.")
    print(f"Wrote dump + sanitised fixture to {res.out_dir}")
    return 0


def _cameras_and_factory(args: argparse.Namespace):
    """Live cameras from --inventory, or simulated ones from --simulate. Returns (cams, factory, simulated)."""
    if getattr(args, "simulate", None):
        loaded = load_fixture_cameras(Path(args.simulate))
        if not loaded:
            raise SystemExit(f"error: no fixtures found in {args.simulate}")
        factory, _ = simulated_factory(loaded)
        print(f"SIMULATE: {len(loaded)} recorded camera(s); no network traffic, nothing real is changed.")
        return [c for c, _ in loaded], factory, True
    if not args.inventory:
        raise SystemExit("error: --inventory is required (or use --simulate)")
    return _load_cameras(args), None, False


def _settings(args: argparse.Namespace, simulated: bool) -> AuditSettings:
    return AuditSettings(tls=TLSPolicy() if simulated else _tls(args), workers=args.workers,
                         timeout=args.timeout, min_delay=args.delay_ms / 1000.0,
                         min_axis_os=args.min_axis_os, operator=_operator(args),
                         customer=getattr(args, "customer_name", None) or "", site_name=getattr(args, "site_name", None) or "")


def _print_camera(r: CameraResult, baseline=None) -> None:
    from .evaluate import baseline_view
    name = r.camera.get("name") or r.camera["host"]
    if r.reachable:
        res = baseline_view(r.results, baseline.control_ids, baseline.name)             if baseline is not None and baseline.name != "audit-only" else r.results
        p = compliance_pct(res)
        nc = sum(x.status == NON_COMPLIANT for x in res)
        print(f"  {name:<30} {r.device.get('Version', ''):<12} {r.status:<13} "
              f"{'' if p is None else f'{p:.0f}% compliant'}, {nc} non-compliant")
    else:
        print(f"  {name:<30} {'':<12} {r.status:<13} {r.error}")


def _audit(args, catalog, profile, cams, factory, simulated):
    settings = _settings(args, simulated)
    pf = password_findings(cams) if not simulated else password_findings([])
    against = "every control" if profile.name == "audit-only" else f"the '{profile.name}' baseline"
    print(f"Checking {len(cams)} camera(s) against {against}...")
    run_id, run_dir, results = run_audit(cams, catalog, profile, settings, pf, Path(args.output_dir),
                                         client_factory=factory, progress=lambda r: _print_camera(r, profile),
                                         simulated=simulated)
    print(f"\nAudit run {run_id} saved to {run_dir}")
    return settings, pf, run_id, run_dir, results


def _profile_dirs(args) -> list[Path]:
    return [user_profiles_dir(args.output_dir)]


def _profile(args, catalog):
    try:
        return load_profile(args.profile, catalog, extra_dirs=_profile_dirs(args))
    except CatalogError as e:
        raise SystemExit(f"error: {e}")


def _loader(args, catalog):
    return lambda n: load_profile(n, catalog, extra_dirs=_profile_dirs(args))


def cmd_profile_list(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    for p in list_profiles(catalog, _profile_dirs(args)):
        n = sum(catalog.get(i).kind == "apply" for i in p.control_ids)
        kind = "built-in" if p.builtin else f"custom ({p.path})"
        print(f"{p.name:<24} {n:>2} changeable controls  {kind}")
        if p.description:
            print(f"    {p.description}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    profile = _profile(args, catalog)
    cams, factory, simulated = _cameras_and_factory(args)
    _, _, _, run_dir, results = _audit(args, catalog, profile, cams, factory, simulated)
    if not args.no_report:
        _write_reports(run_dir, catalog, args.classification)
    return 0 if all(r.reachable for r in results) else 1


def _controls_arg(args, catalog) -> list[str] | None:
    if not getattr(args, "controls", None):
        return None
    ids = [c.strip().upper() for c in args.controls.split(",") if c.strip()]
    for cid in ids:
        if catalog.get(cid).kind != "apply":
            raise SystemExit(f"error: {cid} is a check-only control and cannot be applied")
    return ids


def _print_plan(plans) -> int:
    from .apply import plan_rows
    rows = plan_rows(plans)
    print("\nPLANNED CHANGES (dry run: nothing has been changed yet)")
    if not rows:
        print("  None: every selected control is already compliant, not supported, or not writable.")
    else:
        print(f"  {'camera':<24} {'control':<9} {'setting':<46} {'now':<10} -> new")
        for r in rows:
            flags = ((" [DISRUPTIVE]" if r["disruptive"] else "") + (" [needs restart]" if r["reboot"] else "") +
                     (" [back to default]" if r.get("revert") else ""))
            cur = "" if r["current"] is None else str(r["current"])
            new = str(r["new"])
            cur = cur if len(cur) <= 10 else cur[:9] + "~"
            new = new if len(new) <= 30 else new[:29] + "~"
            print(f"  {r['camera'][:24]:<24} {r['control']:<9} {r['setting'][:46]:<46} {cur:<10} -> {new}{flags}")
        warned = {(r["control"], r["warning"]) for r in rows if r["warning"]}
        if warned:
            print("\n  Notes:")
            for cid, w in sorted(warned):
                print(f"   {cid}: {w}")
    n_revert = len({(r["host"], r["control"]) for r in rows if r.get("revert")})
    if n_revert:
        print(f"\n  {n_revert} setting(s) marked [back to default] are not in this profile, so they go back to the "
              "AXIS OS factory default (less secure). Use --controls to change only specific controls.")
    for p in plans:
        for cid, reason in p.skipped:
            if cid == "*":
                print(f"  SKIPPED {p.camera.label}: {reason}")
    return len(rows)


def cmd_plan(args: argparse.Namespace) -> int:
    from .apply import make_plan
    catalog = load_catalog(args.catalog)
    profile = _profile(args, catalog)
    cams, factory, simulated = _cameras_and_factory(args)
    _, _, _, run_dir, results = _audit(args, catalog, profile, cams, factory, simulated)
    plans = make_plan(results, cams, catalog, profile, _loader(args, catalog), _controls_arg(args, catalog))
    _print_plan(plans)
    doc = [{"camera": p.camera.host, "changes": [c.to_dict() for c in p.changes], "skipped": p.skipped} for p in plans]
    (run_dir / "plan.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"\nPlan saved to {run_dir / 'plan.json'}. Run 'apply' with the same options to make these changes.")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    from .apply import make_plan, run_apply
    catalog = load_catalog(args.catalog)
    profile = _profile(args, catalog)
    if profile.name == "audit-only" and not args.controls:
        raise SystemExit("error: choose a hardening profile to apply (e.g. --profile basic-safe); "
                         "audit-only would include opt-in controls")
    cams, factory, simulated = _cameras_and_factory(args)
    settings, pf, audit_id, _, results = _audit(args, catalog, profile, cams, factory, simulated)
    plans = make_plan(results, cams, catalog, profile, _loader(args, catalog), _controls_arg(args, catalog))
    n = _print_plan(plans)
    if n == 0:
        return 0
    targets = sum(1 for p in plans if p.changes)
    disruptive = any(ch.disruptive for p in plans for ch in p.changes)
    if args.yes:
        confirmed = "--yes"
        print(f"\n--yes given: applying {n} change(s) to {targets} camera(s) without asking.")
    else:
        if not sys.stdin.isatty():
            raise SystemExit("error: not interactive; re-run with --yes to confirm the changes")
        warn = "  Some changes are DISRUPTIVE (see above)." if disruptive else ""
        answer = input(f"\nApply {n} change(s) to {targets} camera(s)?{warn}\nType YES to continue: ").strip()
        if answer != "YES":
            print("Cancelled. Nothing was changed.")
            return 1
        confirmed = "interactive"
    print("\nApplying...")

    def progress(r: CameraResult) -> None:
        ok = sum(1 for c in r.changes if c.get("status") == "verified")
        bad = sum(1 for c in r.changes if c.get("status") in ("failed", "skipped"))
        name = r.camera.get("name") or r.camera["host"]
        print(f"  {name:<30} {r.status:<13} {ok} verified, {bad} failed/skipped  {r.error}")

    run_id, run_dir, out = run_apply(plans, catalog, profile, settings, pf, Path(args.output_dir), confirmed,
                                     audit_id, client_factory=factory, progress=progress, simulated=simulated)
    print(f"\nApply run {run_id} saved to {run_dir}")
    if not simulated:
        print(f"Undo with:  axharden rollback --run {run_id} --inventory <file>")
    if not args.no_report:
        _write_reports(run_dir, catalog, args.classification)
    rc = 0 if all(r.status == "OK" for r in out if r.changes) else 1
    from .restart import needs_restart
    hosts = needs_restart(out)
    if hosts and args.restart:
        print(f"\nRestarting {len(hosts)} camera(s) so the changes take effect (--restart)...")
        rc = max(rc, _do_restart(args, catalog, [c for c in cams if c.host in hosts], factory, simulated, confirmed,
                                 f"after apply run {run_id}"))
    elif hosts:
        print(f"\n{len(hosts)} camera(s) need a restart for some changes to take effect. Restart them with:\n"
              f"  axharden restart --inventory <file> --camera {','.join(hosts)}")
    return rc


def _do_restart(args, catalog, cams, factory, simulated: bool, confirmed: str, reason: str) -> int:
    from .restart import run_restart

    def progress(r: CameraResult) -> None:
        ch = r.changes[0] if r.changes else {}
        print(f"  {r.camera.get('name') or r.camera['host']:<30} {ch.get('status', r.status):<9} "
              f"{ch.get('detail', '')} {r.error}")
    wait = {"timeout": 5, "poll": 0, "down_wait": 0} if simulated else {}
    run_id, run_dir, out = run_restart(cams, catalog, _settings(args, simulated), Path(args.output_dir), confirmed,
                                       client_factory=factory, progress=progress, simulated=simulated, reason=reason,
                                       **wait)
    print(f"Restart run {run_id} saved to {run_dir}")
    if not getattr(args, "no_report", False):
        _write_reports(run_dir, catalog, args.classification)
    return 0 if all(r.status == "OK" for r in out) else 1


def cmd_restart(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    cams, factory, simulated = _cameras_and_factory(args)
    if args.camera:
        wanted = {h.strip().lower() for h in args.camera.split(",") if h.strip()}
        cams = [c for c in cams if c.host.lower() in wanted or c.address.lower() in wanted]
        if not cams:
            raise SystemExit(f"error: none of {args.camera} is in the camera list")
    print("CAMERAS TO RESTART (video and recording stop for about 1-3 minutes each):")
    for c in cams:
        print(f"  {c.label}")
    confirmed = _confirm(args, f"Restart {len(cams)} camera(s)?")
    return _do_restart(args, catalog, cams, factory, simulated, confirmed, "requested")


def _confirm(args, question: str) -> str:
    if args.yes:
        return "--yes"
    if not sys.stdin.isatty():
        raise SystemExit("error: not interactive; re-run with --yes to confirm")
    if input(f"\n{question}\nType YES to continue: ").strip() != "YES":
        print("Cancelled. Nothing was changed.")
        raise SystemExit(1)
    return "interactive"


def _print_account_result(r: CameraResult) -> None:
    for c in r.changes:
        print(f"  {r.camera.get('name') or r.camera['host']:<30} {c.get('status', ''):<9} {c.get('title', '')}"
              f"  {c.get('detail', '')} {r.error}")


def cmd_accounts(args: argparse.Namespace) -> int:
    from . import accounts as A
    from .inventory import Credential, NewAccount, ask_new_password
    from .vapix.users import ROLE_HELP, parse_role, password_problem, role_label, username_problem
    catalog = load_catalog(args.catalog)
    cams, factory, simulated = _cameras_and_factory(args)
    typed = []
    if args.user2 and not args.user:
        raise SystemExit("error: --user2 needs --user as well")
    for opt, user, role_text, ptz_flag in (("--user", args.user, args.role, args.ptz),
                                           ("--user2", args.user2, args.role2, args.ptz2)):
        if not user:
            continue
        try:
            role, ptz = parse_role(role_text + ("+ptz" if ptz_flag else ""))
        except ValueError as e:
            raise SystemExit(f"error: {opt} role: {e}")
        prob = username_problem(user)
        if prob:
            raise SystemExit(f"error: {opt}: {prob}")
        if not sys.stdin.isatty():
            raise SystemExit("error: the new password is typed in; run this interactively")
        pw = ask_new_password(user)
        prob = password_problem(pw, user)
        if prob:
            raise SystemExit(f"error: {prob}")
        typed.append(NewAccount(Credential(user, pw), role, ptz))
    todo = A.with_accounts(cams, typed)
    if not todo:
        raise SystemExit("error: no accounts to create. Fill in new_username (and new_role / new_password) in the "
                         "camera list, or give --user NAME --role viewer|operator|admin.")
    if any(not a.credential.password for c in todo for a in c.new_accounts):
        if not sys.stdin.isatty():
            raise SystemExit("error: some new_password cells are blank; run interactively to type them")
        A.fill_passwords(todo, ask_new_password)
    problems = A.account_problems(todo, args.remove_login)
    if problems:
        _err("cannot create these accounts:")
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        raise SystemExit(2)
    print("\nACCOUNTS TO CREATE (existing accounts with the same name are left unchanged)")
    for c in todo:
        for a in c.new_accounts:
            print(f"  {c.label:<36} {a.username:<20} {role_label(a.role, a.ptz)}")
    for role in sorted({a.role for c in todo for a in c.new_accounts}):
        print(f"  ({ROLE_HELP[role]})")
    for g in A.shared_new_passwords(todo):
        print(f"  WARNING: {len(g)} new accounts share the same password (guide p.31): {', '.join(g[:5])}")
    n = sum(len(c.new_accounts) for c in todo)
    question = f"Create {n} account(s) on {len(todo)} camera(s)?"
    if args.remove_login:
        logins = sorted({c.credential.username for c in todo})
        print(f"\nTHEN REMOVE THE LOGIN ACCOUNT ({', '.join(logins)}) on each camera, logged in as the new "
              "Administrator, once that account has been checked. Update the camera list afterwards: the tool "
              "must then log in with the new Administrator account.")
        question = f"Create {n} account(s) and remove the login account on {len(todo)} camera(s)?"
    confirmed = _confirm(args, question)
    settings = _settings(args, simulated)
    run_id, run_dir, out = A.run_create_accounts(todo, catalog, settings, Path(args.output_dir), confirmed,
                                                 client_factory=factory, progress=_print_account_result,
                                                 simulated=simulated, remove_login=args.remove_login)
    moved = A.login_changes(out)
    if moved:
        print("\nLOGIN ACCOUNT REMOVED. Update the camera list: log in with these accounts from now on:")
        for host, user in sorted(moved.items()):
            print(f"  {host:<28} {user}")
    print(f"\nAccount run {run_id} saved to {run_dir}")
    if not simulated:
        print(f"Undo (removes the accounts created by this run):  axharden-cli rollback --run {run_id} --inventory <file>")
    if not args.no_report:
        _write_reports(run_dir, catalog, args.classification)
    return 0 if all(c.get("status") in ("verified", "skipped") and r.status == "OK"
                    for r in out for c in r.changes) else 1


def _rollback_accounts(args, catalog, run_dir: Path) -> int:
    from . import accounts as A
    import getpass
    cams = _load_cameras(args)

    def ask(username: str, why: str) -> str | None:
        if not sys.stdin.isatty():
            return None
        return getpass.getpass(f"Password for '{username}' (needed to {why}): ") or None
    try:
        _, jobs = A.build_account_undo(run_dir, cams, args.camera, ask=ask)
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    if not jobs:
        print("Nothing to undo: that run created no accounts.")
        return 0
    for job in jobs:
        print(f"  {job.camera.label:<36} {job.summary}")
    confirmed = _confirm(args, f"Undo the account changes of run {args.run} on {len(jobs)} camera(s)?")
    run_id, out_dir, out = A.run_account_undo(run_dir, jobs, catalog, _settings(args, False), Path(args.output_dir),
                                              confirmed, progress=_print_account_result)
    print(f"\nUndo run {run_id} saved to {out_dir}")
    _write_reports(out_dir, catalog, args.classification)
    return 0 if all(r.status == "OK" for r in out) else 1


def cmd_rollback(args: argparse.Namespace) -> int:
    from .apply import build_rollback, run_rollback
    catalog = load_catalog(args.catalog)
    apply_dir = Path(args.output_dir) / "runs" / args.run
    if not (apply_dir / "run.json").exists():
        raise SystemExit(f"error: run not found: {apply_dir}")
    if json.loads((apply_dir / "run.json").read_text(encoding="utf-8")).get("kind") == "accounts":
        return _rollback_accounts(args, catalog, apply_dir)
    cams = _load_cameras(args)
    try:
        _, plans = build_rollback(apply_dir, cams, args.camera, _controls_arg(args, catalog))
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    n = _print_plan(plans)
    if n == 0:
        print("Nothing to roll back.")
        return 0
    if args.yes:
        confirmed = "--yes"
    else:
        if not sys.stdin.isatty():
            raise SystemExit("error: not interactive; re-run with --yes to confirm")
        if input(f"\nRestore {n} setting(s) to their previous values? Type YES to continue: ").strip() != "YES":
            print("Cancelled. Nothing was changed.")
            return 1
        confirmed = "interactive"
    settings = _settings(args, False)
    run_id, run_dir, out = run_rollback(apply_dir, plans, catalog, settings, Path(args.output_dir), confirmed)
    for r in out:
        ok = sum(1 for c in r.changes if c.get("status") == "verified")
        print(f"  {r.camera.get('name') or r.camera['host']:<30} {r.status:<13} {ok} restored  {r.error}")
    print(f"\nRollback run {run_id} saved to {run_dir}")
    _write_reports(run_dir, catalog, args.classification)
    return 0 if all(r.status == "OK" for r in out) else 1


def cmd_log_verify(args: argparse.Namespace) -> int:
    from .auditlog import verify
    ok, _, msg = verify(Path(args.output_dir) / "audit_log.jsonl")
    print(msg)
    return 0 if ok else 1


def _write_reports(run_dir: Path, catalog, classification: str, out: str | None = None) -> None:
    from .report import write_reports
    html_path, csv_path, json_path = write_reports(run_dir, catalog, classification, out)
    print(f"Report: {html_path}")
    print(f"        {csv_path}")
    print(f"        {json_path}")


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.output_dir) / "runs" / args.run
    if not (run_dir / "run.json").exists():
        raise SystemExit(f"error: run not found: {run_dir}")
    catalog = load_catalog(args.catalog)
    _write_reports(run_dir, catalog, args.classification, args.out)
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui.app import run_gui
    return run_gui(output_dir=None if args.output_dir == "output" else args.output_dir)


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="axharden", description="Offline AXIS OS camera hardening audit "
                                "(AXIS OS Hardening guide T10177717).")
    p.add_argument("--version", action="version", version=f"axharden {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging (credentials are always redacted)")
    p.add_argument("--output-dir", default="output", help="where runs are stored (default: output)")
    p.add_argument("--catalog", default=None, help="alternative catalog YAML")
    sub = p.add_subparsers(dest="command", required=True)

    def net(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--insecure", action="store_true", help="do not verify camera TLS certificates (recorded)")
        sp.add_argument("--ca-bundle", help="PEM file of CA certificates to trust for camera HTTPS")

    inv = sub.add_parser("inventory", help="inventory helpers")
    isub = inv.add_subparsers(dest="inv_command", required=True)
    t = isub.add_parser("template", help="write blank CSV/XLSX inventory templates")
    t.add_argument("--out", default="templates")
    t.set_defaults(func=cmd_inventory_template)
    c = isub.add_parser("check", help="validate an inventory (no network)")
    c.add_argument("--inventory", required=True)
    c.add_argument("--customer", help="only cameras of this customer")
    c.set_defaults(func=cmd_inventory_check)

    d = sub.add_parser("discover", help="dump a reference camera and diff it against the catalog")
    d.add_argument("--inventory", required=True)
    d.add_argument("--target", required=True, help="camera IP/host from the inventory")
    net(d)
    d.set_defaults(func=cmd_discover)

    def run_opts(sp: argparse.ArgumentParser, default_profile: str) -> None:
        sp.add_argument("--inventory")
        sp.add_argument("--simulate", metavar="PATH", help="use fixture/snapshot JSON files instead of cameras")
        sp.add_argument("--customer", help="only cameras of this customer (customer column)")
        sp.add_argument("--customer-name", help="customer name shown on the report (free text)")
        sp.add_argument("--site-name", help="site name shown on the report (free text)")
        sp.add_argument("--profile", default=default_profile)
        sp.add_argument("--workers", type=int, default=8)
        sp.add_argument("--timeout", type=float, default=10.0)
        sp.add_argument("--delay-ms", type=int, default=100, help="minimum gap between requests to one camera")
        sp.add_argument("--min-axis-os", default="10.0", help="flag cameras below this AXIS OS version")
        sp.add_argument("--operator", help="operator name for the report (prompted if omitted)")
        sp.add_argument("--classification", default="", help="marking shown on the report: TLP:CLEAR, TLP:GREEN, TLP:AMBER, "
                        "TLP:AMBER+STRICT or TLP:RED (coloured, with its meaning), or any other text")
        sp.add_argument("--no-report", action="store_true")
        net(sp)

    a = sub.add_parser("audit", help="read-only audit of the cameras in the inventory")
    run_opts(a, "audit-only")
    a.set_defaults(func=cmd_audit)

    pl = sub.add_parser("plan", help="audit, then show the changes a profile would make (dry run)")
    run_opts(pl, "basic-safe")
    pl.add_argument("--controls", help="only these control IDs, e.g. AX-B-001,AX-B-005")
    pl.set_defaults(func=cmd_plan)

    ap = sub.add_parser("apply", help="audit, show the plan, confirm, then make and verify the changes")
    run_opts(ap, "basic-safe")
    ap.add_argument("--controls", help="only these control IDs, e.g. AX-B-001,AX-B-005")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation (logged)")
    ap.add_argument("--restart", action="store_true",
                    help="afterwards, restart the cameras that need it for a change to take effect (e.g. TLS ciphers)")
    ap.set_defaults(func=cmd_apply)

    rs = sub.add_parser("restart", help="restart cameras (e.g. after a TLS cipher change) and wait until they answer")
    run_opts(rs, "audit-only")
    rs.add_argument("--camera", help="only these cameras (comma-separated IPs/hosts); default: all selected")
    rs.add_argument("--yes", action="store_true")
    rs.set_defaults(func=cmd_restart)

    ac = sub.add_parser("accounts", help="create a separate camera account (viewer/operator/admin) on each camera")
    run_opts(ac, "audit-only")
    ac.add_argument("--user", help="create this account on every selected camera (else use the new_username "
                                   "column of the camera list); the password is typed in, never stored")
    ac.add_argument("--role", default="viewer", help="viewer (default), operator or admin")
    ac.add_argument("--ptz", action="store_true", help="also allow PTZ control")
    ac.add_argument("--user2", help="a second account to create on every selected camera (password typed in)")
    ac.add_argument("--role2", default="viewer", help="role of --user2: viewer (default), operator or admin")
    ac.add_argument("--ptz2", action="store_true", help="also allow PTZ control for --user2")
    ac.add_argument("--remove-login", action="store_true",
                    help="after creating the accounts, remove the account the tool logged in with (e.g. root). "
                         "Needs one new Administrator account; it is checked and used to do the removal")
    ac.add_argument("--yes", action="store_true")
    ac.set_defaults(func=cmd_accounts)

    rb = sub.add_parser("rollback", help="undo an apply run (restore values) or an accounts run (remove accounts)")
    rb.add_argument("--run", required=True, help="apply or accounts run ID")
    rb.add_argument("--inventory", required=True)
    rb.add_argument("--camera", help="only this camera IP/host")
    rb.add_argument("--controls", help="only these control IDs")
    rb.add_argument("--yes", action="store_true")
    rb.add_argument("--operator")
    rb.add_argument("--classification", default="")
    rb.add_argument("--workers", type=int, default=8)
    rb.add_argument("--timeout", type=float, default=10.0)
    rb.add_argument("--delay-ms", type=int, default=100)
    rb.add_argument("--min-axis-os", default="10.0")
    rb.add_argument("--customer")
    net(rb)
    rb.set_defaults(func=cmd_rollback)

    lg = sub.add_parser("log", help="audit log tools")
    lsub = lg.add_subparsers(dest="log_command", required=True)
    lv = lsub.add_parser("verify", help="check the audit log hash chain is intact")
    lv.set_defaults(func=cmd_log_verify)

    pr = sub.add_parser("profile", help="hardening profiles (custom ones are made in the GUI)")
    psub = pr.add_subparsers(dest="profile_command", required=True)
    pls = psub.add_parser("list", help="list built-in and custom profiles (custom: <output-dir>/profiles)")
    pls.set_defaults(func=cmd_profile_list)

    r = sub.add_parser("report", help="(re)generate the HTML/CSV/JSON report for a run")
    r.add_argument("--run", required=True)
    r.add_argument("--out", help="HTML output path (CSV/JSON written alongside)")
    r.add_argument("--classification", default="")
    r.set_defaults(func=cmd_report)

    g = sub.add_parser("gui", help="open the graphical interface")
    g.set_defaults(func=cmd_gui)

    return p


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv and getattr(sys, "frozen", False):
        argv = ["gui"]  # double-clicked exe with no arguments: open the GUI
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except CatalogError as e:
        _err(str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
