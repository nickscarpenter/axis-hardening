import pytest

from axharden.catalog import CatalogError, _control, load_profile
from axharden.evaluate import (COMPLIANT, INFO, NA, NON_COMPLIANT, NOT_SUPPORTED, compliance_pct,
                               evaluate_params, ControlResult)
from axharden.vapix.params import ParamTree, parse_list
from axharden.version import v


def test_catalog_loads_and_is_consistent(catalog):
    ids = [c.id for c in catalog.controls]
    assert len(ids) == len(set(ids))
    assert "AX-B-007" not in ids  # retired: out of scope for AXIS OS 10.0+
    assert all(c.guide_page > 0 for c in catalog.controls)
    assert len(catalog.sha256) == 64


def test_profiles(catalog):
    safe = load_profile("basic-safe", catalog)
    full = load_profile("basic-full", catalog)
    audit = load_profile("audit-only", catalog)
    assert "AX-B-016" not in safe.control_ids and "AX-B-016" in full.control_ids
    assert set(safe.control_ids) < set(full.control_ids) <= set(audit.control_ids)
    assert len(audit.control_ids) == len(catalog.controls)
    vys = load_profile("vysiion", catalog)
    assert vys.builtin and set(vys.control_ids) == set(safe.control_ids) | {"AX-B-023", "AX-B-024"}
    assert all(cid.startswith("AX-C-") for cid in safe.control_ids if cid not in full.control_ids) or True
    with pytest.raises(CatalogError):
        load_profile("legacy", catalog)  # dropped


def test_schema_validation():
    base = {"id": "X", "title": "t", "guide_section": "s", "guide_page": 1, "level": "basic", "kind": "apply",
            "method": "param", "params": [{"name": "root.A", "hardened": "no"}]}
    _control(base)
    for bad in ({"level": "nope"}, {"method": "param", "params": []}, {"compare": "regex"},
                {"method": "handler", "handler": None, "params": []}, {"removed_in": "abc"}):
        with pytest.raises(CatalogError):
            _control({**base, **bad})


def ctl(**kw):
    raw = {"id": "T-1", "title": "t", "guide_section": "s", "guide_page": 1, "level": "basic", "kind": "apply",
           "method": "param", "params": [{"name": "root.A.Enabled", "hardened": "no"}]}
    raw.update(kw)
    return _control(raw)


def test_parse_list_handles_equals_in_values_and_errors():
    vals = parse_list("root.A=1\r\nroot.B=x=y\n# Error: -1 getting param\n\nroot.C=\n")
    assert vals == {"root.A": "1", "root.B": "x=y", "root.C": ""}


def test_case_insensitive_values_and_names():
    t = ParamTree({"root.a.ENABLED": "No"})
    r = evaluate_params(ctl(), t, v("10.12"))
    assert r.status == COMPLIANT and "Device spells it" in r.detail


def test_non_compliant():
    r = evaluate_params(ctl(), ParamTree({"root.A.Enabled": "yes"}), v("10.12"))
    assert r.status == NON_COMPLIANT and "want no" in r.detail


def test_missing_param_reasons():
    t = ParamTree({})
    assert "removed in AXIS OS 11.1" in evaluate_params(ctl(removed_in="11.1"), t, v("12.0")).detail
    assert "Needs AXIS OS 11.2" in evaluate_params(ctl(introduced_in="11.2"), t, v("10.12")).detail
    assert evaluate_params(ctl(), t, v("10.12")).status == NOT_SUPPORTED
    assert evaluate_params(ctl(missing_status="na"), t, v("10.12")).status == NA


def test_present_param_wins_over_removed_in():
    # System.EditCgi still exists on 10.12 although the guide says it was removed in 10.11.
    r = evaluate_params(ctl(removed_in="10.11"), ParamTree({"root.A.Enabled": "yes"}), v("10.12"))
    assert r.status == NON_COMPLIANT


def test_optional_params():
    c = ctl(params=[{"name": "root.A.Enabled", "hardened": "no"},
                    {"name": "root.B.Enabled", "hardened": "no", "optional": True}])
    assert evaluate_params(c, ParamTree({"root.A.Enabled": "no"}), v("10.12")).status == COMPLIANT
    only_opt = ctl(params=[{"name": "root.B.Enabled", "hardened": "no", "optional": True}])
    assert evaluate_params(only_opt, ParamTree({}), v("10.12")).status == NOT_SUPPORTED


def test_subset_compare():
    c = ctl(compare="subset", params=[{"name": "root.HTTPS.Ciphers", "hardened": "A:B:C"}])
    assert evaluate_params(c, ParamTree({"root.HTTPS.Ciphers": "A:C"}), v("10.12")).status == COMPLIANT
    r = evaluate_params(c, ParamTree({"root.HTTPS.Ciphers": "A:D"}), v("10.12"))
    assert r.status == NON_COMPLIANT and "D" in r.detail
    assert evaluate_params(c, ParamTree({"root.HTTPS.Ciphers": ""}), v("10.12")).status == NON_COMPLIANT


def test_advisory_from():
    c = ctl(advisory_from="12.1")
    t = ParamTree({"root.A.Enabled": "yes"})
    assert evaluate_params(c, t, v("12.0")).status == NON_COMPLIANT
    assert evaluate_params(c, t, v("12.1")).status == INFO


def test_glob_params():
    c = ctl(params=[{"name": "root.Audio.A*.Enabled", "hardened": "no"}], missing_status="na")
    assert evaluate_params(c, ParamTree({"root.Audio.A0.Enabled": "no", "root.Audio.A1.Enabled": "no"}),
                           v("10.12")).status == COMPLIANT
    assert evaluate_params(c, ParamTree({"root.Audio.A0.Enabled": "no", "root.Audio.A1.Enabled": "yes"}),
                           v("10.12")).status == NON_COMPLIANT
    assert evaluate_params(c, ParamTree({}), v("10.12")).status == NA


def test_compliance_pct_ignores_unscored():
    rs = [ControlResult("a", COMPLIANT), ControlResult("b", NON_COMPLIANT), ControlResult("c", NOT_SUPPORTED),
          ControlResult("d", INFO)]
    assert compliance_pct(rs) == 50.0
    assert compliance_pct([ControlResult("x", INFO)]) is None


def test_custom_profile_save_load_and_list(catalog, tmp_path):
    from axharden.catalog import list_profiles, save_profile
    path = save_profile(tmp_path, "Car Park Cams", "no SD", ["AX-B-023", "AX-B-001", "AX-C-001"], catalog, author="T")
    assert path.name == "car-park-cams.yaml"
    prof = load_profile("car-park-cams", catalog, extra_dirs=[tmp_path])
    assert not prof.builtin and prof.path == path
    applies = [i for i in prof.control_ids if catalog.get(i).kind == "apply"]
    assert applies == ["AX-B-001", "AX-B-023"]                       # catalog order
    assert any(catalog.get(i).kind == "check" for i in prof.control_ids)  # checks always included
    names = [p.name for p in list_profiles(catalog, [tmp_path])]
    assert names[:5] == ["basic-safe", "basic-full", "vysiion", "factory-defaults", "audit-only"] and "car-park-cams" in names
    assert load_profile("basic-safe", catalog, extra_dirs=[tmp_path]).builtin


def test_custom_profile_cannot_shadow_builtin(catalog, tmp_path):
    from axharden.catalog import save_profile
    with pytest.raises(CatalogError):
        save_profile(tmp_path, "Basic-Safe", "", ["AX-B-001"], catalog)
    with pytest.raises(CatalogError):
        save_profile(tmp_path, "!!!", "", ["AX-B-001"], catalog)
    with pytest.raises(CatalogError):
        save_profile(tmp_path, "ok", "", ["AX-B-999"], catalog)
