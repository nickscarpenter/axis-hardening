"""Remote syslog (API status), SD card encryption (disk list), certificate pass/fail, report follow-up groups."""

import copy
import json

from axharden.report.html import _info_groups

from test_simulate import _run


def _with_probe(snap: dict, key: str, text: str, host: str) -> dict:
    s = copy.deepcopy(snap)
    s["probes"][key] = {"status": 200, "text": text}
    s["camera"]["host"] = host
    return s


def test_syslog_read_from_api(tmp_path, catalog, m4216):
    on = json.dumps({"apiVersion": "1.0", "method": "status", "data": {"enabled": True, "servers": [
        {"server": {"type": "IP", "address": "10.0.0.9"}, "port": 6514, "protocol": "TLS"}]}})
    plain = json.dumps({"apiVersion": "1.0", "method": "status", "data": {"enabled": True, "servers": [
        {"server": {"type": "IP", "address": "10.0.0.9"}, "port": 514, "protocol": "UDP"}]}})
    key = "POST /axis-cgi/remotesyslog.cgi status"
    _, by, _ = _run(tmp_path, catalog, [m4216, _with_probe(m4216, key, on, "192.0.2.2"),
                                        _with_probe(m4216, key, plain, "192.0.2.3")])
    off, tls, udp = (by[h]["AX-C-006"] for h in (m4216["camera"]["host"], "192.0.2.2", "192.0.2.3"))
    assert off.status == "NON_COMPLIANT" and "disabled" in off.detail                 # the real camera: syslog off
    assert tls.status == "COMPLIANT" and "10.0.0.9:6514" in tls.detail and "TLS" not in tls.detail
    assert udp.status == "COMPLIANT" and "not over TLS" in udp.detail


def test_sd_encryption_from_disk_list(tmp_path, catalog, m4216):
    key = "GET /axis-cgi/disks/list.cgi?diskid=all"
    base = m4216["probes"][key]["text"]
    plain = base.replace('status="disconnected" filesystem="vfat"', 'status="OK" filesystem="vfat"', 1)
    enc = plain.replace('encryptionenabled="false" diskencrypted="false"', 'encryptionenabled="true" diskencrypted="true"', 1)
    _, by, _ = _run(tmp_path, catalog, [m4216, _with_probe(m4216, key, plain, "192.0.2.2"),
                                        _with_probe(m4216, key, enc, "192.0.2.3")])
    assert by[m4216["camera"]["host"]]["AX-C-012"].status == "N/A"                # empty slot on the real camera
    assert by["192.0.2.2"]["AX-C-012"].status == "NON_COMPLIANT"
    assert by["192.0.2.3"]["AX-C-012"].status == "COMPLIANT"


def test_axis_device_certificate_is_compliant(tmp_path, catalog, m4216):
    _, by, _ = _run(tmp_path, catalog, [m4216])
    cert = by[m4216["camera"]["host"]]["AX-C-004"]
    assert cert.status == "COMPLIANT" and "802.1AR" in cert.detail


def test_follow_up_groups(tmp_path, catalog, m4216):
    _, _, results = _run(tmp_path, catalog, [m4216])
    groups = _info_groups(results, catalog)
    ids = {g: [cid for cid, _ in items] for g, items in groups.items()}
    strict = next(r for r in results[0].results if r.id == "AX-C-016")
    assert strict.status == "NOT_SUPPORTED" and "12.11" in strict.detail   # 10.12: strict mode does not exist yet
    assert "AX-C-016" not in ids["manual"]
    assert "AX-C-017" in ids["decision"]                     # depends on the site
    assert {"AX-C-001", "AX-C-020"} <= set(ids["info"])      # read automatically
    every = {cid for items in ids.values() for cid in items}
    assert not every & {"AX-C-004", "AX-C-006", "AX-C-008", "AX-C-010", "AX-C-012"}   # real pass/fail (or N/A)
    (finding, names), = dict(groups["info"])["AX-C-020"]
    assert "Host name" in finding and names


def test_extended_checks_are_pass_fail(tmp_path, catalog, m4216):
    from conftest import variant
    host = m4216["camera"]["host"]
    authorised = variant(m4216, "10.12.252", "192.0.2.2", set_={"root.Network.RTSPS.Enabled": "yes",
                                                                "root.Network.Interface.I0.dot1x.Status": "Authorized"})
    off = variant(m4216, "10.12.252", "192.0.2.3", set_={"root.Network.Interface.I0.dot1x.Enabled": "no"})
    _, by, _ = _run(tmp_path, catalog, [m4216, authorised, off])
    assert by[host]["AX-C-008"].status == "NON_COMPLIANT"                     # real camera: RTSPS off
    assert by[host]["AX-C-010"].status == "NON_COMPLIANT" and "Unauthorized" in by[host]["AX-C-010"].detail
    assert by["192.0.2.2"]["AX-C-008"].status == "COMPLIANT"
    assert by["192.0.2.2"]["AX-C-010"].status == "COMPLIANT"
    assert by["192.0.2.3"]["AX-C-010"].status == "NON_COMPLIANT" and "disabled" in by["192.0.2.3"]["AX-C-010"].detail


def test_strict_security_mode_is_manual_from_12_11(tmp_path, catalog, m4216):
    from conftest import variant
    _, by, results = _run(tmp_path, catalog, [variant(m4216, "12.11.50", "192.0.2.12")])
    strict = by["192.0.2.12"]["AX-C-016"]
    assert strict.status == "INFO" and "never enabled by this tool" in strict.detail
    assert "AX-C-016" in [cid for cid, _ in _info_groups(results, catalog)["manual"]]


def test_report_shows_actual_compliance_and_info_tables(tmp_path, catalog, m4216):
    import re
    from axharden.report import write_reports
    from test_apply import apply, setup
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216])
    run_id, run_dir, res = apply(catalog, prof, out, plans, factory)
    write_reports(run_dir, catalog)
    html = (run_dir / f"report-{run_id}.html").read_text(encoding="utf-8")
    assert "→" not in html.split("<h1>Overview")[0]                      # summary: one figure, no before -> after
    score = re.search(r"<b>Compliance</b><span>([^<]*)</span>", html).group(1)
    assert re.fullmatch(r"\d+%", score)                                   # camera page: the actual figure only
    assert "Needs a manual check" not in html
    assert '<table class="fu">' in html and "What was found" in html
