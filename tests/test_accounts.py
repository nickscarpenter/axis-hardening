"""Creating separate camera accounts (and undoing that) against simulated cameras."""

import json
from pathlib import Path

import pytest

from axharden import accounts as A
from axharden.audit import AuditSettings, load_fixture_cameras, simulated_factory
from axharden.auditlog import verify
from axharden.inventory import Credential, InventoryError, NewAccount, load_inventory
from axharden.report import write_reports
from axharden.vapix import users as vusers

ROOT = Path(__file__).resolve().parents[1]
NEW_PW = "Vms-Viewer-Pass-42"


@pytest.fixture
def demo():
    loaded = load_fixture_cameras(ROOT / "catalog" / "demo")
    factory, devices = simulated_factory(loaded)
    return [c for c, _ in loaded], factory, devices


def _run(cams, catalog, factory, out):
    return A.run_create_accounts(cams, catalog, AuditSettings(operator="tester"), out, "test",
                                 client_factory=factory, simulated=True)


def test_parse_role_and_validation():
    assert vusers.parse_role("Operator") == ("operator", False)
    assert vusers.parse_role("viewer+PTZ") == ("viewer", True)
    assert vusers.parse_role("administrator ptz") == ("admin", True)
    with pytest.raises(ValueError):
        vusers.parse_role("boss")
    assert vusers.SGRP["operator"] == "viewer:operator"
    assert vusers.username_problem("root")
    assert vusers.username_problem("bad name")
    assert vusers.username_problem("vms_op")         # real camera rejects underscores
    assert vusers.username_problem("camadmin", login_user="CAMADMIN")
    assert vusers.username_problem("vmsviewer2") is None
    assert vusers.password_problem("short")
    assert vusers.password_problem("has a space 123")
    assert vusers.password_problem("samename1", "samename1")
    assert vusers.password_problem(NEW_PW, "vms") is None


def test_create_verify_skip_existing_and_undo(demo, catalog, tmp_path):
    cams, factory, devices = demo
    todo = A.with_accounts(cams, [NewAccount(Credential("vmsop", NEW_PW), "operator", True)])
    run_id, run_dir, res = _run(todo, catalog, factory, tmp_path)
    for r in res:
        (ch,) = r.changes
        assert ch["status"] == "verified", ch
        assert "test login worked" in ch["detail"]
        assert ch["writes"][0]["new"] == "Operator + PTZ"
    dev = devices[cams[0].host]
    groups = dev.groups()
    assert "vmsop" in groups["digusers"] and "vmsop" in groups["operator"] and "vmsop" in groups["ptz"]
    assert "vmsop" not in groups["admin"]
    # the after-state shows the new limited account, so AX-C-014 becomes compliant
    assert all(next(x for x in r.after if x.id == "AX-C-014").status == "COMPLIANT" for r in res)

    # second run: the account exists, so it is left alone
    _, _, res2 = _run(todo, catalog, factory, tmp_path)
    assert [c["status"] for r in res2 for c in r.changes] == ["skipped"] * len(cams)

    # undo removes only what the first run created
    _, jobs = A.build_account_undo(run_dir, cams)
    assert sorted(u for j in jobs for u in j.remove) == ["vmsop"] * len(cams)
    _, undo_dir, res3 = A.run_account_undo(run_dir, jobs, catalog, AuditSettings(operator="tester"), tmp_path,
                                           "test", client_factory=factory, simulated=True)
    assert [c["status"] for r in res3 for c in r.changes] == ["verified"] * len(cams)
    assert "vmsop" not in dev.groups()["digusers"]

    # no password anywhere on disk, audit log intact, reports render
    write_reports(run_dir, catalog)
    write_reports(undo_dir, catalog)
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert NEW_PW not in f.read_text(encoding="utf-8", errors="ignore"), f
    ok, n, _ = verify(tmp_path / "audit_log.jsonl")
    assert ok and n > 0
    html = (run_dir / f"report-{run_id}.html").read_text(encoding="utf-8")
    assert "User accounts created" in html and "vmsop" in html


def test_refuses_and_reports_camera_errors(demo, catalog, tmp_path):
    cams, factory, devices = demo
    devices[cams[0].host].reject_accounts = True
    todo = A.with_accounts(cams, [NewAccount(Credential("vmsview", NEW_PW), "viewer", False)])
    _, _, res = _run(todo, catalog, factory, tmp_path)
    by_host = {r.camera["host"]: r.changes[0] for r in res}
    assert by_host[cams[0].host]["status"] == "failed" and "refused" in by_host[cams[0].host]["detail"]
    assert by_host[cams[1].host]["status"] == "verified"


def test_password_sent_in_body_not_url(demo, catalog, tmp_path, monkeypatch):
    cams, factory, _ = demo
    seen = []
    from axharden.vapix import sim
    orig = sim.SimClient.request

    def spy(self, method, path, **kw):
        seen.append((method, path, kw))
        return orig(self, method, path, **kw)
    monkeypatch.setattr(sim.SimClient, "request", spy)
    _run(A.with_accounts(cams[:1], [NewAccount(Credential("vmsx", NEW_PW), "viewer")]), catalog, factory, tmp_path)
    adds = [s for s in seen if "pwdgrp" in s[1] and s[0] == "POST"]
    assert adds and all(NEW_PW not in path for _, path, _ in seen)
    assert adds[0][2]["data"]["pwd"] == NEW_PW and adds[0][2]["data"]["sgrp"] == "viewer"


def test_inventory_new_account_columns(tmp_path):
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password,new_username,new_password,new_role\n"
                   f"192.0.2.1,root,Long-Password-1,vms,{NEW_PW},operator+ptz\n"
                   "192.0.2.2,root,Long-Password-1,vms,,\n"
                   "192.0.2.3,root,Long-Password-1,,,\n", encoding="utf-8")
    cams = load_inventory(inv)                      # no new-account prompt during a normal load
    a1, a2, a3 = (c.new_accounts[0] if c.new_accounts else None for c in cams)
    assert (a1.username, a1.role, a1.ptz, a1.credential.password) == ("vms", "operator", True, NEW_PW)
    assert (a2.role, a2.credential.password) == ("viewer", "")     # role defaults to viewer
    assert a3 is None
    assert NEW_PW not in repr(cams) and NEW_PW not in json.dumps([c.public_dict() for c in cams])
    asked = []
    assert A.fill_passwords(cams, lambda u: asked.append(u) or "Typed-Pass-777")
    assert asked == ["vms"] and a2.credential.password == "Typed-Pass-777" and a1.credential.password == NEW_PW
    assert A.shared_new_passwords(cams) == []

    bad = tmp_path / "bad.csv"
    bad.write_text("ip,username,password,new_username,new_password,new_role\n"
                   "192.0.2.1,root,x,root,short,boss\n192.0.2.2,root,x,,pw-without-user,\n", encoding="utf-8")
    with pytest.raises(InventoryError) as e:
        load_inventory(bad)
    text = "\n".join(e.value.errors)
    assert "reserved" in text and "new_role" in text and "at least 8" in text and "new_username is blank" in text


ADMIN_PW = "Site-Admin-Pass-99"


def _two(cams):
    return A.with_accounts(cams, [NewAccount(Credential("vmsview", NEW_PW), "viewer"),
                                  NewAccount(Credential("siteadmin", ADMIN_PW), "admin", True)])


def test_two_accounts_remove_login_and_undo_puts_it_back(demo, catalog, tmp_path):
    cams, factory, devices = demo
    todo = _two(cams)
    assert A.account_problems(todo, remove_login=True) == []
    run_id, run_dir, res = A.run_create_accounts(todo, catalog, AuditSettings(operator="tester"), tmp_path, "test",
                                                 client_factory=factory, simulated=True, remove_login=True)
    for r in res:
        kinds = [(c["kind"], c["status"]) for c in r.changes]
        assert kinds == [("account", "verified"), ("account", "verified"), ("account-remove-login", "verified")], kinds
        assert r.changes[2]["login_as"] == "siteadmin" and "update the camera list" in r.changes[2]["detail"]
    dev = devices[cams[0].host]
    assert "root" not in dev.groups()["digusers"] and {"vmsview", "siteadmin"} <= set(dev.groups()["digusers"])
    assert A.login_changes(res) == {c.host: "siteadmin" for c in cams}

    # undo with the ORIGINAL camera list (root + new_* passwords in memory): root comes back first
    _, jobs = A.build_account_undo(run_dir, todo)
    assert all(j.restore == {"username": "root", "role": "admin", "ptz": True} for j in jobs), jobs[0].restore
    _, undo_dir, res2 = A.run_account_undo(run_dir, jobs, catalog, AuditSettings(operator="tester"), tmp_path, "t",
                                           client_factory=factory, simulated=True)
    for r in res2:
        assert [(c["kind"], c["status"]) for c in r.changes] == [
            ("account-restore", "verified"), ("account-remove", "verified"), ("account-remove", "verified")]
    assert dev.groups()["digusers"] == ["root"] and "root" in dev.groups()["admin"]
    write_reports(run_dir, catalog)
    write_reports(undo_dir, catalog)
    for f in tmp_path.rglob("*"):
        if f.is_file():
            text = f.read_text(encoding="utf-8", errors="ignore")
            assert NEW_PW not in text and ADMIN_PW not in text, f
    assert verify(tmp_path / "audit_log.jsonl")[0]


def test_undo_with_updated_camera_list_asks_for_old_password(demo, catalog, tmp_path):
    import dataclasses
    cams, factory, _ = demo
    _, run_dir, _ = A.run_create_accounts(_two(cams[:1]), catalog, AuditSettings(operator="t"), tmp_path, "t",
                                          client_factory=factory, simulated=True, remove_login=True)
    updated = [dataclasses.replace(cams[0], credential=Credential("siteadmin", ADMIN_PW))]   # list now logs in as admin
    asked = []
    _, jobs = A.build_account_undo(run_dir, updated, ask=lambda u, why: asked.append(u) or "Old-Root-Pass-1")
    assert asked == ["root"] and jobs[0].admin.username == "siteadmin" and jobs[0].camera.credential.username == "root"
    with pytest.raises(ValueError):
        A.build_account_undo(run_dir, updated)          # no way to ask: refuses instead of guessing


def test_login_removal_refused_or_not_possible(demo, catalog, tmp_path):
    cams, factory, devices = demo
    # no administrator among the new accounts: refused before anything is sent
    viewer_only = A.with_accounts(cams, [NewAccount(Credential("vmsview", NEW_PW), "viewer")])
    assert any("must be an Administrator" in p for p in A.account_problems(viewer_only, remove_login=True))
    # the camera does not allow removing root: root stays, new accounts stay, reported clearly
    devices[cams[0].host].protected_accounts = {"root"}
    _, _, res = A.run_create_accounts(_two(cams), catalog, AuditSettings(operator="t"), tmp_path, "t",
                                      client_factory=factory, simulated=True, remove_login=True)
    by_host = {r.camera["host"]: r.changes[-1] for r in res}
    assert by_host[cams[0].host]["status"] == "failed" and "left in place" in by_host[cams[0].host]["detail"]
    assert "root" in devices[cams[0].host].groups()["digusers"]
    assert by_host[cams[1].host]["status"] == "verified"


def test_inventory_second_account_columns(tmp_path):
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password,new_username,new_password,new_role,new_username2,new_password2,new_role2\n"
                   f"192.0.2.1,root,Long-Password-1,vms,{NEW_PW},viewer,siteadmin,{ADMIN_PW},admin+ptz\n",
                   encoding="utf-8")
    (cam,) = load_inventory(inv)
    assert [(a.username, a.role, a.ptz) for a in cam.new_accounts] == [("vms", "viewer", False),
                                                                      ("siteadmin", "admin", True)]
    assert ADMIN_PW not in repr(cam) and ADMIN_PW not in json.dumps(cam.public_dict())
    bad = tmp_path / "bad.csv"
    bad.write_text("ip,username,password,new_username,new_username2,new_role2\n"
                   "192.0.2.1,root,x,vms,VMS,\n192.0.2.2,root,x,vms,,admin\n", encoding="utf-8")
    with pytest.raises(InventoryError) as e:
        load_inventory(bad)
    text = "\n".join(e.value.errors)
    assert "are the same" in text and "new_username2 is blank" in text
