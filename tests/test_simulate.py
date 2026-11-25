"""End-to-end audit in simulate mode against recorded and synthetic fixtures."""

import json
from pathlib import Path

from axharden.audit import AuditSettings, load_fixture_cameras, load_run, run_audit, simulated_factory
from axharden.catalog import load_profile
from axharden.cli import main
from axharden.inventory import password_findings
from axharden.report.export import export_csv, export_json
from axharden.report.html import build_html

from conftest import FIXTURES, variant


def _run(tmp_path, catalog, snaps, profile="audit-only"):
    fx = tmp_path / "fx"
    fx.mkdir()
    for i, s in enumerate(snaps):
        (fx / f"{i}.json").write_text(json.dumps(s), encoding="utf-8")
    loaded = load_fixture_cameras(fx)
    cams = [c for c, _ in loaded]
    factory, _ = simulated_factory(loaded)
    run_id, run_dir, results = run_audit(cams, catalog, load_profile(profile, catalog), AuditSettings(),
                                         password_findings([]), tmp_path / "out", client_factory=factory,
                                         simulated=True)
    return run_dir, {r.camera["host"]: {x.id: x for x in r.results} for r in results}, results


def test_real_fixture_results(tmp_path, catalog, m4216):
    _, res, results = _run(tmp_path, catalog, [m4216])
    r = res[m4216["camera"]["host"]]
    assert results[0].status == "OK"
    assert r["AX-B-001"].status == "NON_COMPLIANT"                 # Bonjour on
    assert r["AX-B-005"].status == "COMPLIANT"                     # SSH off
    assert r["AX-B-011"].status == "NON_COMPLIANT"                 # DHE ciphers present
    assert "DHE-RSA-AES128-GCM-SHA256" in r["AX-B-011"].detail
    assert r["AX-B-019"].status == "NOT_SUPPORTED"                 # config.cgi 404 on 10.12
    assert r["AX-B-021"].status == "NOT_SUPPORTED"                 # needs 11.2
    assert r["AX-C-002"].status == "COMPLIANT"                     # digest
    assert r["AX-C-003"].status == "NON_COMPLIANT"                 # HTTP 200 on port 80
    assert r["AX-C-005"].status == "NON_COMPLIANT"                 # DHCP NTP with static IP
    assert r["AX-C-014"].status == "NON_COMPLIANT"                 # root only
    assert not any(x.status == "ERROR" for x in r.values())


def test_version_gating_across_firmware(tmp_path, catalog, m4216):
    v11 = variant(m4216, "11.11.100", "192.0.2.11",
                  drop=("root.Network.FTP.Enabled", "root.System.EditCgi"))
    v12 = variant(m4216, "12.2.50", "192.0.2.12",
                  drop=("root.Network.FTP.Enabled", "root.System.EditCgi", "root.HTTPS.AllowTLS1",
                        "root.HTTPS.AllowTLS11"),
                  set_={"root.Network.ZeroConf.Enabled": "yes"})
    v9 = variant(m4216, "9.80.3", "192.0.2.9")
    _, res, results = _run(tmp_path, catalog, [m4216, v11, v12, v9])
    r11, r12 = res["192.0.2.11"], res["192.0.2.12"]
    assert r11["AX-B-006"].status == "NOT_SUPPORTED" and "compliant by design" in r11["AX-B-006"].detail
    assert r11["AX-B-013"].status == "NOT_SUPPORTED"
    assert r11["AX-B-010"].status == "COMPLIANT"
    assert r12["AX-B-010"].status == "NOT_SUPPORTED" and "12.0" in r12["AX-B-010"].detail
    assert r12["AX-B-008"].status == "INFO"            # ZeroConf advisory from 12.1
    assert r11["AX-C-009"].status == "INFO"            # firewall era (11.9+)
    assert res["192.0.2.9"]["AX-C-001"].status == "NON_COMPLIANT"
    by_host = {x.camera["host"]: x for x in results}
    assert by_host["192.0.2.9"].status == "OUT_OF_SCOPE"


def test_reports_contain_no_secrets(tmp_path, catalog, m4216):
    run_dir, _, _ = _run(tmp_path, catalog, [m4216])
    meta, cams = load_run(run_dir)
    html = build_html(meta, cams, catalog, tmp_path / "r.html", classification="OFFICIAL-SENSITIVE").read_text("utf-8")
    export_csv(meta, cams, catalog, tmp_path / "r.csv")
    export_json(meta, cams, tmp_path / "r.json")
    assert "OFFICIAL-SENSITIVE" in html and "Content-Security-Policy" in html
    tlp = build_html(meta, cams, catalog, tmp_path / "t.html", classification="tlp amber").read_text("utf-8")
    assert tlp.count("TLP:AMBER") == 2 and "#FFC000" in tlp and "need-to-know" in tlp
    assert "<script" not in html and "http://" not in html.split("</style>")[0]
    for f in [tmp_path / "r.html", tmp_path / "r.csv", tmp_path / "r.json", *run_dir.rglob("*.json")]:
        text = f.read_text(encoding="utf-8")
        assert "simulated-" not in text  # the dummy simulate password never reaches disk


def test_html_escapes_device_strings(tmp_path, catalog, m4216):
    m4216["camera"]["name"] = "<script>alert(1)</script>"
    run_dir, _, _ = _run(tmp_path, catalog, [m4216])
    meta, cams = load_run(run_dir)
    html = build_html(meta, cams, catalog, tmp_path / "r.html").read_text("utf-8")
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_cli_simulate_end_to_end(tmp_path, capsys):
    rc = main(["--output-dir", str(tmp_path), "audit", "--simulate", str(FIXTURES), "--operator", "tester",
               "--classification", "TEST"])
    out = capsys.readouterr().out
    assert rc == 0 and "SIMULATE" in out
    assert list(Path(tmp_path).rglob("report-*.html"))


