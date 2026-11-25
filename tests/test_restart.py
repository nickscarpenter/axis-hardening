"""Restarting cameras and waiting until they answer again (simulated)."""

from pathlib import Path

from axharden.audit import AuditSettings, load_fixture_cameras, simulated_factory
from axharden.auditlog import verify
from axharden.cli import main
from axharden.report import write_reports
from axharden.restart import needs_restart, run_restart

ROOT = Path(__file__).resolve().parents[1]
FAST = {"timeout": 5, "poll": 0, "down_wait": 0}


def test_restart_waits_until_camera_answers_again(catalog, tmp_path):
    loaded = load_fixture_cameras(ROOT / "catalog" / "demo")
    factory, devices = simulated_factory(loaded)
    cams = [c for c, _ in loaded]
    devices[cams[1].host].stays_down = True
    run_id, run_dir, res = run_restart(cams, catalog, AuditSettings(operator="t"), tmp_path, "test",
                                       client_factory=factory, simulated=True, **FAST)
    by_host = {r.camera["host"]: r for r in res}
    good, bad = by_host[cams[0].host], by_host[cams[1].host]
    assert good.status == "OK" and good.changes[0]["status"] == "verified" and "answering again" in good.changes[0]["detail"]
    assert bad.status == "LOST_CONTACT" and bad.changes[0]["status"] == "failed"
    assert all(d.restarts == 1 for d in devices.values())
    write_reports(run_dir, catalog)
    assert "Camera restarts" in (run_dir / f"report-{run_id}.html").read_text(encoding="utf-8")
    assert verify(tmp_path / "audit_log.jsonl")[0]


def test_needs_restart_only_for_verified_reboot_changes():
    class R:
        def __init__(self, host, changes):
            self.camera, self.changes = {"host": host}, changes
    rs = [R("a", [{"requires_reboot": True, "status": "verified"}]),
          R("b", [{"requires_reboot": True, "status": "failed"}]),
          R("c", [{"requires_reboot": False, "status": "verified"}])]
    assert needs_restart(rs) == ["a"]


def test_cli_apply_restart_and_restart_command(tmp_path, capsys):
    demo = str(ROOT / "catalog" / "demo")
    rc = main(["--output-dir", str(tmp_path), "apply", "--simulate", demo, "--profile", "basic-safe", "--yes",
               "--restart", "--operator", "t", "--no-report"])
    out = capsys.readouterr().out
    assert rc == 0 and "Restarting 2 camera(s)" in out and "Restart run" in out
    rc = main(["--output-dir", str(tmp_path), "restart", "--simulate", demo, "--camera", "192.0.2.100", "--yes",
               "--operator", "t", "--no-report"])
    out = capsys.readouterr().out
    assert rc == 0 and "verified" in out and out.count("Restarted and answering again") == 1
