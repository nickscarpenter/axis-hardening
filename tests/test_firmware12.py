"""The same M4216-LV after an upgrade to AXIS OS 12.11.77 (real, anonymised discover fixture)."""

from axharden.apply import make_plan
from axharden.catalog import load_profile

from test_simulate import _run


def test_12_11_audit_results(tmp_path, catalog, m4216_12):
    _, by, results = _run(tmp_path, catalog, [m4216_12])
    r = by["192.0.2.12"]
    assert results[0].status == "OK" and results[0].device["Version"] == "12.11.77"
    assert r["AX-B-019"].status == "NOT_SUPPORTED" and "no longer exists" in r["AX-B-019"].detail   # was ERROR 400
    assert r["AX-B-020"].status == "COMPLIANT"                    # unsigned apps blocked by default from 12.0
    for cid in ("AX-B-006", "AX-B-010", "AX-B-013"):              # removed features: compliant by design
        assert r[cid].status == "NOT_SUPPORTED", cid
    assert r["AX-B-002"].status == "COMPLIANT"                    # UPnP off, NATTraversal gone
    assert r["AX-B-008"].status == "INFO"                         # ZeroConf advisory from 12.1
    assert r["AX-C-016"].status == "INFO"                         # strict security mode exists from 12.11
    assert r["AX-C-018"].status == "NOT_SUPPORTED"                # IP filter replaced by the firewall
    assert r["AX-C-006"].status == "NON_COMPLIANT"                # syslog API 1.2 still read by "status"
    assert r["AX-C-010"].status == "NON_COMPLIANT" and "Unauthorized" in r["AX-C-010"].detail
    assert r["AX-C-020"].observed.get("resolver") is not None     # network settings API 1.37
    assert not [x for x in results[0].results if x.status == "ERROR"]


def test_12_11_plan_only_what_is_missing(tmp_path, catalog, m4216_12):
    _, _, results = _run(tmp_path, catalog, [m4216_12])
    from axharden.audit import load_fixture_cameras
    cams = [c for c, _ in load_fixture_cameras(tmp_path / "fx")]
    plan = make_plan(results, cams, catalog, load_profile("basic-full", catalog))
    ids = {c.control_id for c in plan[0].changes if not c.revert}
    assert ids == {"AX-B-016", "AX-B-017"}                         # the camera is already basic-safe hardened


def test_extra_settings_apply_verify_and_undo(tmp_path, catalog, m4216_12):
    from axharden.apply import build_rollback, run_rollback
    from axharden.audit import AuditSettings
    from axharden.catalog import Profile
    from test_apply import apply, setup
    cams, factory, devices, _, out, plans = setup(tmp_path, catalog, [m4216_12])
    extra = ["AX-E-001", "AX-E-002", "AX-E-003", "AX-E-004", "AX-E-005"]
    prof = Profile("extras", "", extra)
    plan = make_plan([p.before for p in plans], cams, catalog, prof, controls=extra)
    ids = {c.control_id for c in plan[0].changes}
    assert ids == {"AX-E-001", "AX-E-002", "AX-E-005"}          # SNMP v1/v2c already off; filter log gone on 12.x
    _, run_dir, res = apply(catalog, prof, out, plan, factory)
    done = {c["control_id"]: c["status"] for c in res[0].changes if "writes" in c}
    assert set(done.values()) == {"verified"}, done
    dev = devices["192.0.2.12"]
    assert dev.params["root.Network.RTSPS.Enabled"] == "yes"
    assert dev.params["root.Image.I0.MPEG.SignedVideo.Enabled"] == "yes"
    assert dev.rest["/config/rest/lldp/v1"]["activated"] is False
    _, rplans = build_rollback(run_dir, cams)
    run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes", client_factory=factory,
                 simulated=True)
    assert dev.params["root.Network.RTSPS.Enabled"] == "no" and dev.rest["/config/rest/lldp/v1"]["activated"] is True


def test_extra_settings_are_opt_in_and_never_reverted(catalog):
    from axharden.catalog import load_profile
    for name in ("basic-safe", "basic-full", "vysiion"):
        assert not [i for i in load_profile(name, catalog).control_ids if i.startswith("AX-E-")], name
    for ctl in catalog.controls:
        if ctl.id.startswith("AX-E-"):
            assert ctl.opt_in and ctl.warning is not None or ctl.id == "AX-E-004"
            assert all(p.default is None for p in ctl.params) and "default" not in ctl.handler_args
