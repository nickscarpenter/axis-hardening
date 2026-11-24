"""Phase 2: plan, apply with read-back, write order, lost contact, rollback, audit log."""

import json

import pytest

from axharden.apply import (G_CIPHERS, G_HTTPS_ONLY, G_PARAMS, G_WEBUI, build_rollback, make_plan, plan_rows,
                            run_apply, run_rollback, _match_case)
from axharden.audit import AuditSettings, load_fixture_cameras, run_audit, simulated_factory
from axharden.auditlog import AuditLog, verify
from axharden.catalog import load_profile
from axharden.inventory import password_findings

from conftest import variant


def setup(tmp_path, catalog, snaps, profile="basic-safe"):
    fx = tmp_path / "fx"
    fx.mkdir(exist_ok=True)
    for i, s in enumerate(snaps):
        (fx / f"{i}.json").write_text(json.dumps(s), encoding="utf-8")
    loaded = load_fixture_cameras(fx)
    factory, devices = simulated_factory(loaded)
    cams = [c for c, _ in loaded]
    prof = load_profile(profile, catalog)
    out = tmp_path / "out"
    _, _, audits = run_audit(cams, catalog, prof, AuditSettings(operator="t"), password_findings([]), out,
                             client_factory=factory, simulated=True)
    plans = make_plan(audits, cams, catalog, prof, lambda n: load_profile(n, catalog))
    return cams, factory, devices, prof, out, plans


def apply(catalog, prof, out, plans, factory):
    return run_apply(plans, catalog, prof, AuditSettings(operator="t"), password_findings([]), out, "--yes",
                     "audit-x", client_factory=factory, simulated=True)


def test_match_case():
    assert _match_case("Yes", "no") == "No"
    assert _match_case("Off", "on") == "On"
    assert _match_case("both", "https") == "https"
    assert _match_case("50", "20") == "20"


def test_plan_only_non_compliant_and_ordered(tmp_path, catalog, m4216):
    _, _, _, _, _, plans = setup(tmp_path, catalog, [m4216])
    ids = [c.control_id for c in plans[0].changes]
    assert "AX-B-005" not in ids                     # SSH already off
    assert "AX-B-016" not in ids                     # not in basic-safe
    assert "AX-B-019" not in ids                     # NOT_SUPPORTED on 10.12
    groups = [c.group for c in plans[0].changes]
    assert groups == sorted(groups)
    assert groups[-1] == G_HTTPS_ONLY and G_CIPHERS in groups
    rows = plan_rows(plans)
    disc = next(r for r in rows if r["control"] == "AX-B-003")
    assert disc["current"] == "Yes" and disc["new"] == "No"          # device case preserved
    ciph = next(r for r in rows if r["control"] == "AX-B-011")
    assert not any(c.startswith("DHE-") for c in ciph["new"].split(":")) and ciph["reboot"]


def test_apply_writes_in_order_and_verifies(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216], "basic-full")
    run_id, run_dir, res = apply(catalog, prof, out, plans, factory)
    r = res[0]
    assert r.status == "OK"
    statuses = {c["control_id"]: c["status"] for c in r.changes if "writes" in c}
    assert set(statuses.values()) == {"verified"}
    # after state is compliant for everything we changed
    after = {x.id: x.status for x in r.after}
    assert all(after[cid] == "COMPLIANT" for cid in statuses)
    # write order: params, ciphers, https-only, web UI last
    log = [name for name, _ in devices[cams[0].host].write_log]
    pos = lambda n: next(i for i, x in enumerate(log) if x.endswith(n))
    assert pos("Bonjour.Enabled") < pos("HTTPS.Ciphers") < pos("BoaGroupPolicy.admin") < pos("WebInterfaceDisabled")
    assert r.scheme == "https"
    ok, n, _ = verify(out / "audit_log.jsonl")
    assert ok and n > 10


def test_read_back_mismatch_is_failure(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    devices[cams[0].host].ignore_params.add("root.Network.Bonjour.Enabled")
    _, _, res = apply(catalog, prof, out, plans, factory)
    ch = next(c for c in res[0].changes if c.get("control_id") == "AX-B-001")
    assert ch["status"] == "failed" and "reads back" in ch["detail"]
    others = [c["status"] for c in res[0].changes if c.get("control_id") == "AX-B-005"]
    assert others == []


def test_refused_write_attributed_to_its_control(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    devices[cams[0].host].reject_params.add("root.System.AccessLog")
    _, _, res = apply(catalog, prof, out, plans, factory)
    by = {c["control_id"]: c for c in res[0].changes if "writes" in c}
    assert by["AX-B-014"]["status"] == "failed" and "Error setting" in by["AX-B-014"]["detail"]
    assert by["AX-B-001"]["status"] == "verified"     # batch fallback kept the others


def test_lost_contact_after_https_only_stops_camera(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216], "basic-full")
    dev = devices[cams[0].host]

    def drop(name, value):
        if name.endswith("BoaGroupPolicy.viewer"):
            dev.reachable = False
    dev.after_write_hook = drop
    _, _, res = apply(catalog, prof, out, plans, factory)
    r = res[0]
    assert r.status == "LOST_CONTACT"
    by = {c["control_id"]: c["status"] for c in r.changes if "writes" in c}
    assert by["AX-B-016"] == "skipped"                # never attempted after contact was lost
    assert not any(n.endswith("WebInterfaceDisabled") for n, _ in dev.write_log)
    events = [json.loads(l)["event"] for l in (out / "audit_log.jsonl").read_text().splitlines()]
    assert "camera_stopped" in events


def test_https_only_not_enabled_when_https_broken(tmp_path, catalog, m4216):
    m4216["camera"]["protocol"] = "http"
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    from axharden.vapix import sim

    real = sim.SimClient.negotiate

    def negotiate(self):
        if self.scheme == "https":
            from axharden.vapix.client import TLSFailed
            raise TLSFailed("TLS error: handshake failed")
        return real(self)
    sim.SimClient.negotiate = negotiate
    try:
        _, _, res = apply(catalog, prof, out, plans, factory)
    finally:
        sim.SimClient.negotiate = real
    ch = next(c for c in res[0].changes if c.get("control_id") == "AX-B-009")
    assert ch["status"] == "failed" and "HTTPS does not work" in ch["detail"]
    assert devices[cams[0].host].params["root.System.BoaGroupPolicy.admin"] == "both"


def test_rollback_restores_previous_values(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216], "basic-full")
    dev = devices[cams[0].host]
    before = dict(dev.params)
    run_id, run_dir, _ = apply(catalog, prof, out, plans, factory)
    assert dev.params["root.System.BoaGroupPolicy.admin"] == "https"
    _, rplans = build_rollback(run_dir, cams)
    rid, rdir, rres = run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes",
                                   client_factory=factory, simulated=True)
    assert rres[0].status == "OK"
    for k in ("root.Network.Bonjour.Enabled", "root.HTTPS.Ciphers", "root.System.BoaGroupPolicy.admin",
              "root.System.WebInterfaceDisabled", "root.WebService.DiscoveryMode.Discoverable"):
        assert dev.params[k] == before[k], k
    assert all(c["status"] == "verified" for c in rres[0].changes if "writes" in c)
    ok, _, _ = verify(out / "audit_log.jsonl")
    assert ok


def test_rollback_refuses_audit_runs(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    audit_dir = next((out / "runs").iterdir())
    with pytest.raises(ValueError, match="only apply runs"):
        build_rollback(audit_dir, cams)


def test_out_of_scope_and_unreachable_not_planned(tmp_path, catalog, m4216):
    old = variant(m4216, "9.80.1", "192.0.2.9")
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [old])
    assert plans[0].changes == [] and "OUT_OF_SCOPE" in plans[0].skipped[0][1]


def test_audit_log_detects_tampering(tmp_path):
    path = tmp_path / "log.jsonl"
    alog = AuditLog(path, operator="t")
    for i in range(3):
        alog.append("write", run_id="r", setting=f"s{i}", old="a", new="b", result="ok")
    assert verify(path)[0]
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"new": "b"', '"new": "X"')
    path.write_text("\n".join(lines) + "\n")
    ok, _, msg = verify(path)
    assert not ok and "altered" in msg
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, msg = verify(path)
    assert not ok and "chain broken" in msg


def test_no_credentials_in_apply_outputs(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    apply(catalog, prof, out, plans, factory)
    pw = cams[0].credential.password
    for f in out.rglob("*"):
        if f.is_file():
            assert pw not in f.read_text(encoding="utf-8", errors="ignore"), f


def test_cli_apply_simulate(tmp_path, capsys):
    from axharden.cli import main
    rc = main(["--output-dir", str(tmp_path), "apply", "--simulate", "catalog/demo", "--operator", "t", "--yes"])
    out = capsys.readouterr().out
    assert rc == 0 and "verified" in out and "PLANNED CHANGES" in out
    assert main(["--output-dir", str(tmp_path), "log", "verify"]) == 0


def test_cli_apply_refuses_audit_only(tmp_path):
    from axharden.cli import main
    with pytest.raises(SystemExit, match="hardening profile"):
        main(["--output-dir", str(tmp_path), "apply", "--simulate", "catalog/demo", "--profile", "audit-only",
              "--operator", "t", "--yes"])
