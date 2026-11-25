"""Checking against a baseline (profile): everything is read, but only the baseline is scored and reported."""

import json

from axharden.apply import make_plan
from axharden.audit import AuditSettings, load_run, run_audit
from axharden.catalog import load_profile
from axharden.evaluate import NA, NON_COMPLIANT, baseline_view, compliance_pct
from axharden.inventory import password_findings
from axharden.report import write_reports

from test_apply import setup


def _audit(tmp_path, catalog, cams, factory, profile):
    return run_audit(cams, catalog, load_profile(profile, catalog), AuditSettings(operator="t"),
                     password_findings([]), tmp_path / "out", client_factory=factory, simulated=True)


def test_everything_is_read_but_only_the_baseline_counts(tmp_path, catalog, m4216):
    cams, factory, *_ = setup(tmp_path, catalog, [m4216])
    run_id, run_dir, res = _audit(tmp_path, catalog, cams, factory, "basic-safe")
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert meta["baseline"] == "basic-safe" and "AX-B-016" not in meta["baseline_ids"]
    raw = {r.id: r for r in res[0].results}
    assert len(raw) == len(catalog.controls)                       # every control read
    assert raw["AX-B-016"].status == NON_COMPLIANT                 # web interface on: a problem in general...
    view = {r.id: r for r in baseline_view(res[0].results, meta["baseline_ids"], "basic-safe")}
    assert view["AX-B-016"].status == NA and "basic-safe baseline" in view["AX-B-016"].detail   # ...not for basic-safe
    assert compliance_pct(list(view.values())) > compliance_pct(res[0].results)
    write_reports(run_dir, catalog)
    html = (run_dir / f"report-{run_id}.html").read_text(encoding="utf-8")
    assert "Checked against" in html and "basic-safe: Axis recommended" in html
    problems = html.split("<h2>Problems")[1].split("</table>")[0]
    assert "AX-B-016" not in problems and "AX-B-001" in problems


def test_no_baseline_means_every_control(tmp_path, catalog, m4216):
    cams, factory, *_ = setup(tmp_path, catalog, [m4216])
    _, run_dir, _ = _audit(tmp_path, catalog, cams, factory, "audit-only")
    meta, _ = load_run(run_dir)
    assert meta["baseline"] == "" and meta["baseline_ids"] is None


def test_plan_after_baseline_check_can_still_revert(tmp_path, catalog, m4216):
    """The check reads every control, so Fix problems can put settings outside the profile back to default."""
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216], "vysiion")
    from test_apply import apply
    apply(catalog, prof, out, plans, factory)                     # SD slot and audio disabled
    _, _, res = _audit(tmp_path, catalog, cams, factory, "basic-safe")
    plan = make_plan(res, cams, catalog, load_profile("basic-safe", catalog))
    assert any(c.control_id == "AX-B-023" and c.revert for c in plan[0].changes)
