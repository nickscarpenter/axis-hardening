"""Drive the GUI programmatically (skipped where no display is available)."""

import time

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
    # risky HTTPS-only is listed but not ticked by default
    risky = [iid for iid, (_, ch) in dlg.changes.items() if ch.disruptive]
    assert risky and not any(i in dlg.ticked for i in risky)
    n = len(dlg.ticked)
    assert n > 5 and str(dlg.btn_apply["text"]) == f"Apply {n} change(s)"
    # untick Bonjour on the car park camera
    bonjour = next(i for i in dlg.changes if i.endswith("AX-B-001"))
    dlg.ticked.discard(bonjour)
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    dlg.apply()
    _wait(app)
    dev = app.sim_devices[bonjour.split("|")[0]]
    assert dev.params["root.Network.Bonjour.Enabled"] == "yes"          # unticked: untouched
    assert dev.params["root.Network.UPnP.Enabled"] == "no"              # ticked: changed
    assert dev.params["root.System.BoaGroupPolicy.admin"] == "both"     # risky: untouched
    assert str(app.btn_undo["state"]) == "normal"
    rows = [app.tree.item(i, "values")[4] for i in app.tree.get_children()]
    assert all("changed" in r for r in rows)
    app.undo()
    _wait(app)
    assert dev.params["root.Network.UPnP.Enabled"] == "yes"             # restored
    assert str(app.btn_undo["state"]) == "disabled"


def test_load_inventory_with_prompt_and_warnings(app, tmp_path, monkeypatch):
    from axharden.gui import app as gui
    inv = tmp_path / "cams.csv"
    inv.write_text("ip,username,password,name,site\n192.0.2.1,root,,A,North\n192.0.2.2,root,,B,South\n",
                   encoding="utf-8")
    asked = []
    monkeypatch.setattr(gui.simpledialog, "askstring", lambda *a, **k: asked.append(k.get("show")) or "short")
    assert app.load_inventory(inv)
    assert asked == ["*"]                                  # one hidden prompt for the shared username
    assert "share the same password" in app.lbl_warn.cget("text")
    assert "shorter than 8" in app.lbl_warn.cget("text")
    assert list(app.cmb_site.cget("values")) == ["All sites", "North", "South"]
    assert str(app.btn_run["state"]) == "normal"


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
