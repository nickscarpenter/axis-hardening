"""Command line interface (argparse: no extra dependency)."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .audit import AuditSettings, CameraResult, load_fixture_cameras, load_run, run_audit
from .catalog import CatalogError, load_catalog, load_profile
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
    if getattr(args, "site", None):
        cams = [c for c in cams if c.site.lower() == args.site.lower()]
        if not cams:
            raise SystemExit(f"error: no cameras with site {args.site!r}")
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
    print(f"{'host':<28} {'name':<22} {'site':<14} {'proto':<6} {'user':<12} password")
    for c in cams:
        print(f"{c.address:<28} {c.name[:22]:<22} {c.site[:14]:<14} {c.protocol:<6} {c.credential.username[:12]:<12} ********")
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


def cmd_audit(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    try:
        profile = load_profile(args.profile, catalog)
    except CatalogError as e:
        raise SystemExit(f"error: {e}")
    fixtures = None
    if args.simulate:
        loaded = load_fixture_cameras(Path(args.simulate))
        if not loaded:
            raise SystemExit(f"error: no fixtures found in {args.simulate}")
        cams = [c for c, _ in loaded]
        fixtures = {c.host: snap for c, snap in loaded}
        print(f"SIMULATE: replaying {len(cams)} recorded camera(s); no network traffic.")
    else:
        if not args.inventory:
            raise SystemExit("error: --inventory is required (or use --simulate)")
        cams = _load_cameras(args)
    settings = AuditSettings(tls=TLSPolicy() if args.simulate else _tls(args), workers=args.workers,
                             timeout=args.timeout, min_delay=args.delay_ms / 1000.0,
                             min_axis_os=args.min_axis_os, operator=_operator(args))
    pf = password_findings(cams) if not args.simulate else password_findings([])

    def progress(r: CameraResult) -> None:
        name = r.camera.get("name") or r.camera["host"]
        if r.reachable:
            p = compliance_pct(r.results)
            nc = sum(x.status == NON_COMPLIANT for x in r.results)
            print(f"  {name:<30} {r.device.get('Version', ''):<12} {r.status:<13} "
                  f"{'' if p is None else f'{p:.0f}% compliant'}, {nc} non-compliant")
        else:
            print(f"  {name:<30} {'':<12} {r.status:<13} {r.error}")

    print(f"Auditing {len(cams)} camera(s) with profile '{profile.name}' ({len(profile.control_ids)} controls)...")
    run_id, run_dir, results = run_audit(cams, catalog, profile, settings, pf, Path(args.output_dir),
                                         fixtures=fixtures, progress=progress)
    print(f"\nRun {run_id} saved to {run_dir}")
    if not args.no_report:
        _write_reports(run_dir, catalog, args.classification)
    return 0 if all(r.reachable for r in results) else 1


def _write_reports(run_dir: Path, catalog, classification: str, out: str | None = None) -> None:
    from .report.export import export_csv, export_json
    from .report.html import build_html
    meta, cams = load_run(run_dir)
    html_path = Path(out) if out else run_dir / f"report-{meta['run_id']}.html"
    build_html(meta, cams, catalog, html_path, classification=classification)
    export_csv(meta, cams, catalog, html_path.with_suffix(".csv"))
    export_json(meta, cams, html_path.with_suffix(".json"))
    print(f"Report: {html_path}\n        {html_path.with_suffix('.csv')}\n        {html_path.with_suffix('.json')}")


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.output_dir) / "runs" / args.run
    if not (run_dir / "run.json").exists():
        raise SystemExit(f"error: run not found: {run_dir}")
    catalog = load_catalog(args.catalog)
    _write_reports(run_dir, catalog, args.classification, args.out)
    return 0


def cmd_phase2(args: argparse.Namespace) -> int:
    _err(f"'{args.command}' is part of phase 2 (apply/rollback) and is not implemented yet. "
         "This build is read-only.")
    return 2


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
    c.add_argument("--site")
    c.set_defaults(func=cmd_inventory_check)

    d = sub.add_parser("discover", help="dump a reference camera and diff it against the catalog")
    d.add_argument("--inventory", required=True)
    d.add_argument("--target", required=True, help="camera IP/host from the inventory")
    net(d)
    d.set_defaults(func=cmd_discover)

    a = sub.add_parser("audit", help="read-only audit of the cameras in the inventory")
    a.add_argument("--inventory")
    a.add_argument("--simulate", metavar="PATH", help="replay fixture/snapshot JSON files instead of cameras")
    a.add_argument("--site")
    a.add_argument("--profile", default="audit-only")
    a.add_argument("--workers", type=int, default=8)
    a.add_argument("--timeout", type=float, default=10.0)
    a.add_argument("--delay-ms", type=int, default=100, help="minimum gap between requests to one camera")
    a.add_argument("--min-axis-os", default="10.0", help="flag cameras below this AXIS OS version")
    a.add_argument("--operator", help="operator name for the report (prompted if omitted)")
    a.add_argument("--classification", default="", help='marking shown on the report, e.g. "OFFICIAL-SENSITIVE"')
    a.add_argument("--no-report", action="store_true")
    net(a)
    a.set_defaults(func=cmd_audit)

    r = sub.add_parser("report", help="(re)generate the HTML/CSV/JSON report for a run")
    r.add_argument("--run", required=True)
    r.add_argument("--out", help="HTML output path (CSV/JSON written alongside)")
    r.add_argument("--classification", default="")
    r.set_defaults(func=cmd_report)

    for name in ("plan", "apply", "rollback"):
        sp = sub.add_parser(name, help="phase 2 (not yet implemented)")
        sp.set_defaults(func=cmd_phase2)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if extra and args.command not in ("plan", "apply", "rollback"):
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
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
