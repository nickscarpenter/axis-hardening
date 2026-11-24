import logging
import pickle

import pytest

from axharden.inventory import (Credential, InventoryError, load_inventory, parse_host, password_findings,
                                write_templates)
from axharden.logging_setup import RedactingFilter, redact, register_secret
from axharden.version import AxisVersion, v


# ---------------------------------------------------------------- version

def test_numeric_comparison():
    assert v("10.6") < v("10.12")
    assert v("11.5") < v("11.11")
    assert v("10.12.252") > v("10.12")
    assert v("12.0") >= v("12.0.0")
    assert AxisVersion.parse("garbage") is None
    assert v("10.12.252").track == "10.x"


# ---------------------------------------------------------------- inventory

def _csv(tmp_path, text):
    p = tmp_path / "inv.csv"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_valid_csv(tmp_path):
    p = _csv(tmp_path, "IP,Username,Password,Name,Site,ports\n10.0.0.1,root,Secret-123,Cam 1,A,5;6\n"
                       "cam2.local:8443,root,Other-456,,B,\n[fe80::1]:443,admin,Third-789,,,\n")
    cams = load_inventory(p, prompt=None)
    assert [c.host for c in cams] == ["10.0.0.1", "cam2.local", "fe80::1"]
    assert cams[0].ports == [5, 6]
    assert cams[1].port == 8443
    assert cams[2].address == "[fe80::1]:443"


def test_all_errors_reported_at_once(tmp_path):
    p = _csv(tmp_path, "ip,username,password,protocol\n10.0.0.1,root,x,https\n10.0.0.1,root,x,https\n"
                       "999.1.1.1,root,x,https\n10.0.0.3,,x,ftp\n")
    with pytest.raises(InventoryError) as ei:
        load_inventory(p, prompt=None)
    msgs = " | ".join(ei.value.errors)
    assert "duplicate" in msgs and "999.1.1.1" in msgs and "missing 'username'" in msgs and "protocol" in msgs


def test_missing_required_column(tmp_path):
    with pytest.raises(InventoryError, match="inventory error"):
        load_inventory(_csv(tmp_path, "address,username\n1.2.3.4,root\n"), prompt=None)


def test_blank_password_prompted_once_per_user(tmp_path):
    p = _csv(tmp_path, "ip,username,password\n10.0.0.1,root,\n10.0.0.2,root,\n10.0.0.3,ops,\n")
    asked = []
    cams = load_inventory(p, prompt=lambda u: asked.append(u) or f"pw-for-{u}-long")
    assert asked == ["root", "ops"]
    assert cams[1].credential.password == "pw-for-root-long"


def test_blank_password_without_prompt_is_error(tmp_path):
    with pytest.raises(InventoryError):
        load_inventory(_csv(tmp_path, "ip,username,password\n10.0.0.1,root,\n"), prompt=None)


def test_credential_never_exposed():
    c = Credential("root", "Hunter2-Secret")
    assert "Hunter2" not in repr(c) and "Hunter2" not in str(c)
    with pytest.raises(TypeError):
        pickle.dumps(c)


def test_password_findings(tmp_path):
    p = _csv(tmp_path, "ip,username,password,name\n10.0.0.1,root,Same-Pass-1,a\n10.0.0.2,root,Same-Pass-1,b\n"
                       "10.0.0.3,root,short,c\n")
    pf = password_findings(load_inventory(p, prompt=None))
    assert pf.shared_groups == [["a (10.0.0.1)", "b (10.0.0.2)"]]
    assert pf.weak == ["c (10.0.0.3)"]


def test_xlsx_and_templates(tmp_path):
    paths = write_templates(tmp_path)
    assert {x.suffix for x in paths} == {".csv", ".xlsx"}
    cams = load_inventory(tmp_path / "inventory_template.xlsx", prompt=lambda u: "prompted-password")
    assert cams[0].host == "10.0.0.21" and cams[0].credential.password == "prompted-password"


@pytest.mark.parametrize("bad", ["", "1.2.3.4:0", "1.2.3.4:99999", "bad host!", "[zz::1]"])
def test_parse_host_rejects(bad):
    with pytest.raises(ValueError):
        parse_host(bad)


# ---------------------------------------------------------------- logging redaction

def test_redaction_patterns():
    register_secret("Sup3r-Secret!")
    text = ('Authorization: Digest username="root", response="abc123" https://root:pw@10.0.0.1/x '
            'password=Sup3r-Secret! and Sup3r-Secret!')
    out = redact(text)
    assert "Sup3r-Secret" not in out and "abc123" not in out and "root:pw@" not in out


def test_filter_redacts_log_records():
    register_secret("Very-Secret-99")
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "login with %s", ("Very-Secret-99",), None)
    RedactingFilter().filter(rec)
    assert "Very-Secret-99" not in rec.getMessage()
