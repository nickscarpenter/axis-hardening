"""Drive the GUI programmatically (skipped where no display is available)."""

import time
from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture(scope="module")
def tk_root():
    # One Tk interpreter per process: repeatedly creating/destroying Tk() is flaky on Windows
    # ("Can't find a usable tk.tcl"). The real app only ever creates one.
    try:
        root = tk.Tk()
    except tk.TclError as e:
        pytest.skip(f"no display: {e}")
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def app(tmp_path, monkeypatch, tk_root):
    from axharden.gui import app as gui
    calls = []
    for name in ("showinfo", "showerror", "showwarning"):
        monkeypatch.setattr(gui.messagebox, name, lambda *a, _n=name, **k: calls.append((_n, a)))
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: calls.append(("askyesno", a)) or False)
    monkeypatch.setattr(gui, "open_path", lambda p: calls.append(("open", p)))
    root = tk.Toplevel(tk_root)
    root.withdraw()
    a = gui.App(root, output_dir=str(tmp_path / "out"))
    a.calls = calls
    yield a
    root.destroy()


def _wait(app, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        app.root.update()
        if app.worker and not app.worker.is_alive() and app.queue.empty():
            app.root.update()
            return
        time.sleep(0.02)
    raise AssertionError("worker did not finish")


def test_demo_run_produces_report(app):
    app.run_demo()
    _wait(app)
    assert len(app.results) == 2
    assert app.last_report and app.last_report.exists()
    assert str(app.btn_report["state"]) == "normal"
    rows = [app.tree.item(i, "values") for i in app.tree.get_children()]
    assert all(r[4] == "Checked" for r in rows)
    assert ("askyesno" in [c[0] for c in app.calls])


def test_fix_and_undo_in_demo(app, monkeypatch):
    from axharden.gui import app as gui
    app.run_demo()
    _wait(app)
    assert str(app.btn_fix["state"]) == "normal"
    dlg = gui.FixDialog(app)
    dlg.win.withdraw()
    # HTTPS-only is disruptive but needs no extra step: ticked by default like the rest
    https = [iid for iid in dlg.changes if iid.endswith("AX-B-009")]
    assert https and all(i in dlg.ticked for i in https)
    n = len(dlg.ticked)
    assert n > 5 and str(dlg.btn_apply["text"]) == f"Apply {n} change(s)"
    # untick Bonjour on the car park camera
    bonjour = next(i for i in dlg.changes if i.endswith("AX-B-001"))
    dlg.ticked.discard(bonjour)
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    shown = []
    real_restart = app.start_restart
    monkeypatch.setattr(app, "start_restart", lambda cams: shown.append([c.host for c in cams]))
    dlg.apply()
    _wait(app)
    dev = app.sim_devices[bonjour.split("|")[0]]
    assert dev.params["root.Network.Bonjour.Enabled"] == "yes"          # unticked: untouched
    assert dev.params["root.Network.UPnP.Enabled"] == "no"              # ticked: changed
    assert dev.params["root.System.BoaGroupPolicy.admin"] == "https"    # HTTPS only: changed
    assert str(app.btn_undo["state"]) == "normal"
    rows = [app.tree.item(i, "values")[4] for i in app.tree.get_children()]
    assert all("changed" in r for r in rows)
    # the TLS cipher change needs a restart: the program offers it for exactly those cameras
    assert shown and set(shown[0]) == set(app.sim_devices)
    real_restart([c for c in app.audit_cams if c.host in shown[0]])
    _wait(app)
    assert all(d.restarts == 1 for d in app.sim_devices.values())
    assert all(app.tree.item(i, "values")[4] == "Restarted" for i in app.tree.get_children())
    assert str(app.btn_undo["state"]) == "normal"
    app.undo()
    _wait(app)
    assert dev.params["root.Network.UPnP.Enabled"] == "yes"             # restored
    assert str(app.btn_undo["state"]) == "disabled"


def test_load_inventory_with_prompt_and_warnings(app, tmp_path, monkeypatch):
    from axharden.gui import app as gui
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password,name,customer\n192.0.2.1,root,,A,North\n192.0.2.2,root,,B,South\n",
                   encoding="utf-8")
    asked = []
    monkeypatch.setattr(gui.simpledialog, "askstring", lambda *a, **k: asked.append(k.get("show")) or "short")
    assert app.load_inventory(inv)
    assert asked == ["*"]                                  # one hidden prompt for the shared username
    assert "share the same password" in app.lbl_warn.cget("text")
    assert "shorter than 8" in app.lbl_warn.cget("text")
    assert app.var_customer.get() == ""                   # two customers in the list: not pre-filled
    assert str(app.btn_run["state"]) == "normal"
    one = tmp_path / "one.csv"
    one.write_text("ip,username,password,customer\n192.0.2.1,root,Long-Password-1,Acme Ltd\n", encoding="utf-8")
    assert app.load_inventory(one) and app.var_customer.get() == "Acme Ltd"   # single customer: pre-filled


def test_customer_and_site_name_go_on_the_report(app, monkeypatch):
    app.var_customer.set("Acme Ltd")
    app.var_site_name.set("North depot")
    app.run_demo()
    _wait(app)
    from axharden.audit import load_run
    meta, _ = load_run(app.last_run_dir if hasattr(app, "last_run_dir") else
                       max((Path(app.var_output.get()) / "runs").iterdir()))
    assert meta["customer"] == "Acme Ltd" and meta["site_name"] == "North depot"
    html = next(Path(app.var_output.get()).glob("runs/*/report-*.html")).read_text(encoding="utf-8")
    assert "Acme Ltd" in html and "North depot" in html


def test_bad_inventory_shows_errors(app, tmp_path):
    inv = tmp_path / "bad.csv"
    inv.write_text("ip,username\nnot an ip!,root\n", encoding="utf-8")
    assert not app.load_inventory(inv)
    assert app.calls[-1][0] == "showerror"


def test_run_requires_operator_name(app, tmp_path, monkeypatch):
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password\n192.0.2.1,root,Long-Password-1\n", encoding="utf-8")
    app.load_inventory(inv)
    app.var_operator.set("")
    app.run()
    assert app.worker is None and app.calls[-1][0] == "showwarning"


def test_unreachable_camera_reported_in_plain_english(app, tmp_path, monkeypatch):
    from axharden.gui import app as gui
    from axharden.vapix import client as vclient
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password,name\n192.0.2.1,root,Long-Password-1,Lobby\n", encoding="utf-8")
    app.load_inventory(inv)
    app.var_operator.set("Tester")

    def refuse(self):
        raise vclient.Unreachable("Connection failed: refused")
    monkeypatch.setattr(vclient.CameraClient, "negotiate", refuse)
    app.run()
    _wait(app)
    assert app.tree.item("192.0.2.1", "values")[4] == "Not reachable"
    app.tree.selection_set("192.0.2.1")
    app._show_row(None)
    assert "Could not reach the camera" in app.calls[-1][1][1]


def test_profile_editor_save_copy_and_use_in_fix(app, monkeypatch):
    from axharden.gui import app as gui
    app.run_demo()
    _wait(app)
    ed = gui.ProfileEditor(app, start="basic-safe")
    ed.win.withdraw()
    assert ed.current.builtin and "AX-B-001" in ed.ticked
    assert str(ed.btn_delete["state"]) == "disabled"
    # build a custom profile: only Bonjour + audio off
    ed.untick_all()
    ed.toggle("AX-B-001")
    ed.toggle("AX-B-024")
    ed.toggle("AX-B-021")                       # port controls are not available yet
    assert ed.ticked == {"AX-B-001", "AX-B-024"}
    monkeypatch.setattr(gui.simpledialog, "askstring", lambda *a, **k: "Lobby only")
    assert ed.save()                            # built-in name -> asked for a new one
    assert (app.profiles_dir / "lobby-only.yaml").exists()
    assert ed.current.name == "lobby-only" and not ed.current.builtin
    closed = []
    ed.on_close = closed.append
    ed.close()
    assert closed == ["lobby-only"]
    # the fix dialog offers it and plans only those controls
    dlg = gui.FixDialog(app)
    dlg.win.withdraw()
    label = next(lbl for lbl, n in dlg.labels.items() if n == "lobby-only")
    dlg.var_label.set(label)
    dlg._profile_chosen()
    harden = {iid.split("|")[1] for iid, (_, ch) in dlg.changes.items() if not ch.revert}
    assert harden and harden <= {"AX-B-001", "AX-B-024"}
    # everything else the gate camera had hardened goes back to the firmware default (ticked)
    reverts = [iid for iid, (_, ch) in dlg.changes.items() if ch.revert]
    assert reverts and all(i in dlg.ticked for i in reverts)
    dlg.win.destroy()


def test_profile_editor_risky_needs_confirmation_and_delete(app, monkeypatch):
    from axharden.gui import app as gui
    ed = gui.ProfileEditor(app)
    ed.win.withdraw()
    ed.new_blank()
    ed.toggle("AX-B-009")                       # HTTPS only: no extra confirmation
    assert "AX-B-009" in ed.ticked
    ed.toggle("AX-B-016")                       # askyesno patched to False in the fixture
    assert "AX-B-016" not in ed.ticked
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    ed.toggle("AX-B-016")
    assert "AX-B-016" in ed.ticked
    ed.var_name.set("https test")
    assert ed.save() and (app.profiles_dir / "https-test.yaml").exists()
    ed.delete()
    assert not (app.profiles_dir / "https-test.yaml").exists()
    assert ed.current.name == "basic-safe"
    ed.close()


def test_create_account_with_privilege_level_and_undo(app, monkeypatch):
    from axharden.gui import app as gui
    from axharden.vapix import users as vusers
    app.run_demo()
    _wait(app)
    assert str(app.btn_accounts["state"]) == "normal"
    dlg = gui.AccountDialog(app)
    dlg.win.withdraw()
    assert dlg.var_mode.get() == "typed"            # demo camera list has no new_username column
    f1 = dlg.form1
    f1.var_user.set("vmsop")
    f1.var_role.set(vusers.ROLE_HELP["operator"])
    f1.var_ptz.set(True)
    f1.var_pw1.set("Operator-Pass-77")
    f1.var_pw2.set("Different-Pass-77")
    dlg.create()                                     # mismatch -> error, nothing happens
    assert app.calls[-1][0] == "showerror" and app.worker is not None and not app.worker.is_alive()
    f1.var_pw2.set("Operator-Pass-77")
    rows = [dlg.tree.item(i, "values") for i in dlg.tree.get_children()]
    assert all("create vmsop as Operator + PTZ" in r[4] for r in rows)
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    dlg.create()
    _wait(app)
    for host, dev in app.sim_devices.items():
        assert "vmsop" in dev.groups()["operator"] and "vmsop" not in dev.groups()["admin"]
    assert all(app.tree.item(i, "values")[4] == "1 created" for i in app.tree.get_children())
    assert str(app.btn_undo["state"]) == "normal"
    app.undo()
    _wait(app)
    assert all("vmsop" not in d.groups()["digusers"] for d in app.sim_devices.values())
    assert all(app.tree.item(i, "values")[4] == "1 removed" for i in app.tree.get_children())


def test_create_accounts_from_camera_list_columns(app, tmp_path, monkeypatch):
    from axharden.gui import app as gui
    from axharden.inventory import load_inventory
    app.run_demo()
    _wait(app)
    inv = tmp_path / "cams.csv"
    hosts = [c.host for c in app.audit_cams]
    inv.write_text("ip,username,password,new_username,new_password,new_role\n"
                   f"{hosts[0]},root,Long-Password-1,viewer1,,viewer\n"
                   f"{hosts[1]},root,Long-Password-1,,,\n", encoding="utf-8")
    listed = {c.host: c for c in load_inventory(inv)}
    for c in app.audit_cams:              # keep the demo cameras but take the account columns from the list
        c.new_accounts = listed[c.host].new_accounts
    dlg = gui.AccountDialog(app)
    dlg.win.withdraw()
    assert dlg.var_mode.get() == "list" and [c.host for c in dlg._targets()] == [hosts[0]]
    monkeypatch.setattr(gui.simpledialog, "askstring", lambda *a, **k: "Viewer-Pass-123")
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    dlg.create()
    _wait(app)
    assert "viewer1" in app.sim_devices[hosts[0]].groups()["viewer"]
    assert "viewer1" not in app.sim_devices[hosts[1]].groups().get("digusers", [])
    assert app.audit_cams[0].new_accounts[0].credential.password == ""    # typed password not kept on the list


def test_two_accounts_remove_login_then_undo(app, monkeypatch):
    from axharden.gui import app as gui
    from axharden.vapix import users as vusers
    app.run_demo()
    _wait(app)
    dlg = gui.AccountDialog(app)
    dlg.win.withdraw()
    dlg.form1.var_user.set("vmsview")
    dlg.form1.var_pw1.set("Viewer-Pass-123")
    dlg.form1.var_pw2.set("Viewer-Pass-123")
    dlg.var_remove.set(True)
    dlg.refresh()
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    dlg.create()                                   # viewer only + remove login: refused, nothing written
    assert app.calls[-1][0] == "showerror" and "Administrator" in str(app.calls[-1])
    dlg.var_second.set(True)
    dlg.form2.var_user.set("siteadmin")
    dlg.form2.var_role.set(vusers.ROLE_HELP["admin"])
    dlg.form2.var_pw1.set("Admin-Pass-456")
    dlg.form2.var_pw2.set("Admin-Pass-456")
    dlg.refresh()
    rows = [dlg.tree.item(i, "values")[4] for i in dlg.tree.get_children()]
    assert all("create siteadmin as Administrator" in r and "then remove root" in r for r in rows)
    dlg.create()
    _wait(app)
    for dev in app.sim_devices.values():
        assert "root" not in dev.groups()["digusers"] and "siteadmin" in dev.groups()["admin"]
    assert all("login account removed" in app.tree.item(i, "values")[4] for i in app.tree.get_children())
    assert all(c.credential.username == "siteadmin" for c in app.audit_cams)     # this session logs in as admin
    app.undo()
    _wait(app)
    for dev in app.sim_devices.values():
        assert dev.groups()["digusers"] == ["root"]
    assert all(c.credential.username == "root" for c in app.audit_cams)


def test_gui_check_against_choice(app, monkeypatch):
    labels = list(app.baseline_labels)
    assert labels[0] == app.EVERYTHING and any("vysiion" in lbl.lower() for lbl in labels)
    assert not any("factory" in lbl.lower() for lbl in labels)
    app.var_baseline.set(next(lbl for lbl, n in app.baseline_labels.items() if n == "basic-safe"))
    app.run_demo()
    _wait(app)
    assert app.baseline_name == "basic-safe"
    from axharden.gui import app as gui
    dlg = gui.FixDialog(app)
    dlg.win.withdraw()
    assert dlg.var_profile.get() == "basic-safe"                   # Fix problems opens on the same baseline
    dlg.win.destroy()
