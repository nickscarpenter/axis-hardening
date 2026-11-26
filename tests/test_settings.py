"""hostname / dns / ntp / timezone columns: validation, planning, apply with read-back, rollback; Excel template."""

import pytest

from axharden.apply import SET_DNS, SET_HOSTNAME, SET_NTP, SET_TZ, build_rollback, make_plan, run_rollback
from axharden.audit import AuditSettings
from axharden.inventory import InventoryError, load_inventory, password_findings, write_templates

from test_apply import apply, setup


def test_columns_are_validated(tmp_path):
    inv = tmp_path / "c.csv"
    inv.write_text("ip,username,password,hostname,dns,ntp,timezone\n"
                   "192.0.2.1,root,Long-Password-1,gate-1,10.0.0.2;10.0.0.3,ntp.example.local,europe/london\n",
                   encoding="utf-8")
    (cam,) = load_inventory(inv)
    assert (cam.hostname, cam.dns, cam.ntp, cam.timezone) == ("gate-1", ["10.0.0.2", "10.0.0.3"],
                                                              "ntp.example.local", "europe/london")
    bad = tmp_path / "b.csv"
    bad.write_text("ip,username,password,hostname,dns,ntp,timezone\n"
                   "192.0.2.1,root,x,bad_name,10.0.0.2;10.0.0.3;10.0.0.4,a;b,Mars/Base\n"
                   "192.0.2.2,root,x,,dns.local,,\n", encoding="utf-8")
    with pytest.raises(InventoryError) as e:
        load_inventory(bad)
    text = "\n".join(e.value.errors)
    for bit in ("hostname 'bad_name'", "at most two DNS", "one time server", "unknown time zone", "'dns.local' is not"):
        assert bit in text, bit


def _with_settings(cams, **kw):
    import dataclasses
    return [dataclasses.replace(c, **kw) for c in cams]


def test_settings_are_planned_applied_verified_and_undone(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    cams = _with_settings(cams, hostname="gate-1", dns=["10.0.0.2"], ntp="10.0.0.5", timezone="Europe/Paris")
    plans = make_plan([p.before for p in plans], cams, catalog, prof)
    by_id = {c.control_id: c for c in plans[0].changes}
    assert {SET_HOSTNAME, SET_DNS, SET_NTP, SET_TZ} <= set(by_id)
    assert (by_id[SET_TZ].now_label, by_id[SET_TZ].new_label) == ("Europe/London", "Europe/Paris")
    assert by_id[SET_NTP].now_label == "From DHCP" and by_id[SET_NTP].new_label == "10.0.0.5"
    assert by_id[SET_DNS].now_label == "None" and by_id[SET_DNS].kind == "net_resolver"   # not param.cgi (401 on 10.12)
    _, run_dir, res = apply(catalog, prof, out, plans, factory)
    done = {c["control_id"]: c["status"] for c in res[0].changes if "writes" in c}
    assert all(done[i] == "verified" for i in (SET_HOSTNAME, SET_DNS, SET_NTP, SET_TZ)), done
    d = devices[cams[0].host].params
    assert d["root.Network.HostName"] == "gate-1" and d["root.Network.Resolver.NameServer1"] == "10.0.0.2"
    assert d["root.Time.NTP.Server"] == "10.0.0.5" and d["root.Time.ObtainFromDHCP"] == "no"
    assert d["root.Time.POSIXTimeZone"] == "CET-1CEST,M3.5.0,M10.5.0/3"
    # undo puts the old values back
    _, rplans = build_rollback(run_dir, cams, only_controls=[SET_TZ, SET_NTP])
    run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes", client_factory=factory,
                 simulated=True)
    assert d["root.Time.POSIXTimeZone"] == "GMT0BST,M3.5.0/1,M10.5.0" and d["root.Time.ObtainFromDHCP"] == "yes"


def test_nothing_planned_when_already_set(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    cams = _with_settings(cams, timezone="Europe/London", hostname="axis-accc8e000001")
    ids = {c.control_id for c in make_plan([p.before for p in plans], cams, catalog, prof)[0].changes}
    assert SET_TZ not in ids and SET_HOSTNAME not in ids


def test_excel_template_has_dropdowns_and_notes(tmp_path):
    from openpyxl import load_workbook
    _, xlsx = write_templates(tmp_path)
    wb = load_workbook(xlsx)
    ws = wb["cameras"]
    assert wb.worksheets[0].title == "cameras" and wb["lists"].sheet_state == "hidden"
    header = [c.value for c in ws[1]]
    assert {"hostname", "dns", "ntp", "timezone", "new_role", "new_role2"} <= set(header)
    assert ws.cell(row=1, column=1).comment.text.startswith("Required")
    formulas = {str(dv.sqref): dv.formula1 for dv in ws.data_validations.dataValidation}
    col = lambda name: ws.cell(row=1, column=header.index(name) + 1).column_letter   # noqa: E731
    assert any(k.startswith(col("timezone")) for k in formulas) and any(k.startswith(col("new_role")) for k in formulas)
    roles = [wb["lists"].cell(row=r, column=4).value for r in range(2, 8)]
    assert roles == ["viewer", "operator", "admin", "viewer+ptz", "operator+ptz", "admin+ptz"]
    (cam,) = load_inventory(xlsx, prompt=lambda u: "Long-Password-1")      # the example row itself is valid
    assert cam.timezone == "Europe/London"


def test_no_address_spellings_count_as_equal():
    from axharden.apply import _same
    assert _same("", "0.0.0.0") and _same("0.0.0.0", "") and _same("::", "")
    assert not _same("", "10.0.0.1") and _same("Yes", "yes")


def test_syslog_column_parse_and_validate():
    from axharden.inventory import parse_syslog
    assert parse_syslog("10.0.0.9") == [{"address": "10.0.0.9", "port": 6514, "protocol": "TLS"}]
    assert parse_syslog("10.0.0.9:514/udp; logs.local/tcp") == [
        {"address": "10.0.0.9", "port": 514, "protocol": "UDP"}, {"address": "logs.local", "port": 601, "protocol": "TCP"}]
    for bad, why in (("10.0.0.9/ftp", "udp, tcp or tls"), ("a;b;c", "at most two"), ("10.0.0.9:99999", "1 to 65535"),
                     ("x;x", "the same"), ("bad host!", "not an IP")):
        with pytest.raises(ValueError, match=why):
            parse_syslog(bad)


def test_syslog_set_verify_and_undo(tmp_path, catalog, m4216_12):
    from axharden.apply import SET_SYSLOG
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216_12])
    cams = _with_settings(cams, syslog=[{"address": "192.0.2.50", "port": 514, "protocol": "UDP"}])
    plan = make_plan([p.before for p in plans], cams, catalog, prof)
    ch = next(c for c in plan[0].changes if c.control_id == SET_SYSLOG)
    assert (ch.now_label, ch.new_label) == ("Disabled", "192.0.2.50:514/UDP")
    _, run_dir, res = apply(catalog, prof, out, plan, factory)
    done = next(c for c in res[0].changes if c.get("control_id") == SET_SYSLOG)
    assert done["status"] == "verified", done
    dev = devices["192.0.2.12"]
    assert dev.syslog["enabled"] is True and dev.syslog["servers"][0]["address"] == "192.0.2.50"
    after = {r.id: r for r in res[0].after}
    assert after["AX-C-006"].status == "COMPLIANT" and "not over TLS" in after["AX-C-006"].detail
    _, rplans = build_rollback(run_dir, cams, only_controls=[SET_SYSLOG])
    run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes", client_factory=factory,
                 simulated=True)
    assert dev.syslog["enabled"] is False and dev.syslog["servers"] == []


def _fw_setup(tmp_path, catalog, m4216_12, monkeypatch, camera_sees="192.0.2.200"):
    import axharden.apply as apply_mod
    monkeypatch.setattr(apply_mod, "FIREWALL_SETTLE", 0)
    monkeypatch.setattr(apply_mod, "local_ip_for", lambda host: "192.0.2.200")      # what the tool thinks it is
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216_12])
    devices["192.0.2.12"].client_ip = camera_sees                                     # what the camera sees
    cams = _with_settings(cams, allow=["192.0.2.102", "198.51.100.0/24"])
    return cams, factory, devices["192.0.2.12"], prof, out, make_plan([p.before for p in plans], cams, catalog, prof)


def test_allow_column_validation():
    from axharden.inventory import parse_allow
    assert parse_allow("10.0.0.5; 10.0.200.7/24, 10.0.0.10-10.0.0.20") == ["10.0.0.5", "10.0.200.0/24",
                                                                           "10.0.0.10-10.0.0.20"]
    for bad, why in (("0.0.0.0/0", "allow everyone"), ("10.0.0.9-10.0.0.1", "before"), ("nope", "not an IP")):
        with pytest.raises(ValueError, match=why):
            parse_allow(bad)


def test_firewall_set_with_safety_net_and_undo(tmp_path, catalog, m4216_12, monkeypatch):
    from axharden.apply import SET_FIREWALL
    cams, factory, dev, prof, out, plan = _fw_setup(tmp_path, catalog, m4216_12, monkeypatch)
    ch = next(c for c in plan[0].changes if c.control_id == SET_FIREWALL)
    assert ch.disruptive and ch.now_label == "Disabled"
    assert ch.new_label == "Block all except 192.0.2.102, 198.51.100.0/24, 192.0.2.200"   # this PC added
    _, run_dir, res = apply(catalog, prof, out, plan, factory)
    done = next(c for c in res[0].changes if c.get("control_id") == SET_FIREWALL)
    assert done["status"] == "verified", done
    assert dev.fw["activated"] and dev.fw["conf"]["rules"]["activeDefaultPolicy"] == "DROP" and dev.fw_prev is None
    assert {r.id: r for r in res[0].after}["AX-C-009"].status == "COMPLIANT"
    dev.client_ip = "192.0.2.99"                                    # some other device: now blocked
    with pytest.raises(Exception):
        factory(cams[0]).negotiate()
    dev.client_ip = "192.0.2.200"
    _, rplans = build_rollback(run_dir, cams, only_controls=[SET_FIREWALL])
    run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes", client_factory=factory,
                 simulated=True)
    assert dev.fw["activated"] is False                             # back to the original state


def test_firewall_not_confirmed_when_tool_is_cut_off(tmp_path, catalog, m4216_12, monkeypatch):
    """The camera sees the tool under another address (e.g. NAT): the test connection fails, the rules are never
    confirmed, the camera's fallback restores access and the camera is reported, not left locked."""
    from axharden.apply import SET_FIREWALL
    cams, factory, dev, prof, out, plan = _fw_setup(tmp_path, catalog, m4216_12, monkeypatch,
                                                    camera_sees="203.0.113.5")
    _, _, res = apply(catalog, prof, out, plan, factory)
    assert res[0].status == "LOST_CONTACT"
    done = next(c for c in res[0].changes if c.get("control_id") == SET_FIREWALL)
    assert done["status"] == "failed" and "NOT confirmed" in done["detail"]
    assert dev.fw["conf"]["rules"]["activeDefaultPolicy"] == "ACCEPT"   # fallback put the accept-all set back
    factory(cams[0]).negotiate()                                         # reachable again


def _dot1x_setup(tmp_path, catalog, m4216_12, monkeypatch, **cols):
    import axharden.apply as apply_mod
    monkeypatch.setattr(apply_mod, "DOT1X_POLL", 0)
    monkeypatch.setattr(apply_mod, "DOT1X_WATCH", 0)
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216_12])
    cams = _with_settings(cams, **cols)
    return cams, factory, devices["192.0.2.12"], prof, out, make_plan([p.before for p in plans], cams, catalog, prof)


def test_dot1x_columns_validated():
    from axharden.inventory import parse_onoff
    assert parse_onoff("On") == "on" and parse_onoff("disabled") == "off" and parse_onoff("") == ""
    with pytest.raises(ValueError):
        parse_onoff("maybe")


def test_dot1x_off_identity_and_undo(tmp_path, catalog, m4216_12, monkeypatch):
    from axharden.apply import SET_DOT1X
    cams, factory, dev, prof, out, plan = _dot1x_setup(tmp_path, catalog, m4216_12, monkeypatch, dot1x="off",
                                                       dot1x_identity="gatecam1")
    ch = next(c for c in plan[0].changes if c.control_id == SET_DOT1X)
    assert ch.disruptive and (ch.now_label, ch.new_label) == ("Enabled", "Disabled, identity gatecam1")
    _, run_dir, res = apply(catalog, prof, out, plan, factory)
    assert next(c for c in res[0].changes if c.get("control_id") == SET_DOT1X)["status"] == "verified"
    key = "root.Network.Interface.I0.dot1x"
    assert dev.params[key + ".Enabled"] == "no" and dev.params[key + ".EAPTLS.Identity"] == "gatecam1"
    _, rplans = build_rollback(run_dir, cams, only_controls=[SET_DOT1X])
    run_rollback(run_dir, rplans, catalog, AuditSettings(operator="t"), out, "--yes", client_factory=factory,
                 simulated=True)
    assert dev.params[key + ".Enabled"] == "yes" and dev.params[key + ".EAPTLS.Identity"] == "axis-accc8e000012"


def test_dot1x_enable_on_enforcing_port_is_reported(tmp_path, catalog, m4216_12, monkeypatch):
    """Turning 802.1X on where RADIUS rejects the camera: it drops off, the camera is stopped and reported."""
    from axharden.apply import SET_DOT1X
    key = "root.Network.Interface.I0.dot1x.Enabled"
    m4216_12["params"][key] = "no"
    cams, factory, dev, prof, out, plan = _dot1x_setup(tmp_path, catalog, m4216_12, monkeypatch, dot1x="on")
    dev.after_write_hook = lambda name, value: setattr(dev, "reachable", not (name == key and value == "yes"))
    _, _, res = apply(catalog, prof, out, plan, factory)
    assert res[0].status == "LOST_CONTACT" and "cannot be undone remotely" in res[0].error
    ch = next(c for c in plan[0].changes if c.control_id == SET_DOT1X)
    assert "NO automatic undo" in ch.warning
