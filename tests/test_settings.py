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
