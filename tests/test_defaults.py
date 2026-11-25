"""Firmware defaults: version-aware default values, the factory-defaults profile, and reverting settings that a
newly chosen profile leaves out."""

from axharden.apply import make_plan, run_apply
from axharden.audit import AuditSettings, run_audit
from axharden.catalog import default_for, load_profile
from axharden.inventory import password_findings
from axharden.version import v

from conftest import variant
from test_apply import apply, setup


def test_default_values_follow_the_axis_os_version(catalog):
    upnp = catalog.get("AX-B-002").params[0]
    assert default_for(upnp.default, upnp.default_from, v("11.11")) == "yes"
    assert default_for(upnp.default, upnp.default_from, v("12.0")) == "no"
    dos = catalog.get("AX-B-012").params[0]
    assert default_for(dos.default, dos.default_from, v("10.12")) == "off"
    assert default_for(dos.default, dos.default_from, v("11.5")) == "on"
    https = catalog.get("AX-B-009").params[0]
    assert default_for(https.default, https.default_from, v("13.0")) == "https"
    assert catalog.get("AX-B-011").params[0].default is None          # cipher list: never reverted


def _harden_then(tmp_path, catalog, snaps, first: str, second: str):
    """Apply profile `first`, re-audit, and plan profile `second`."""
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, snaps, first)
    apply(catalog, prof, out, plans, factory)
    nxt = load_profile(second, catalog)
    _, _, audits = run_audit(cams, catalog, load_profile("audit-only", catalog), AuditSettings(operator="t"),
                             password_findings([]), out, client_factory=factory, simulated=True)
    return cams, factory, devices, nxt, out, make_plan(audits, cams, catalog, nxt)


def test_switching_profile_reverts_settings_it_leaves_out(tmp_path, catalog, m4216):
    sd_on = dict(m4216["params"])
    cams, factory, devices, nxt, out, plans = _harden_then(tmp_path, catalog, [m4216], "vysiion", "basic-safe")
    dev = devices[cams[0].host]
    sd_key = next(k for k in dev.params if k.endswith(".DiskID") and dev.params[k] == "SD_DISK")[:-len("DiskID")]
    assert dev.params[sd_key + "Enabled"] == "no"                       # vysiion turned the SD slot off
    reverts = {c.control_id: c for c in plans[0].changes if c.revert}
    assert set(reverts) == {"AX-B-023"}                                 # basic-safe leaves out SD (audio stays off)
    assert not [c for c in plans[0].changes if not c.revert]           # everything else already matches
    apply(catalog, nxt, out, plans, factory)
    assert dev.params[sd_key + "Enabled"] == sd_on[sd_key + "Enabled"] == "yes"


def test_factory_defaults_profile_undoes_hardening_per_version(tmp_path, catalog, m4216):
    v12 = variant(m4216, "12.0.50", "192.0.2.12")
    cams, factory, devices, nxt, out, plans = _harden_then(tmp_path, catalog, [m4216, v12], "basic-full",
                                                           "factory-defaults")
    by_host = {p.camera.host: {c.control_id: c for c in p.changes} for p in plans}
    old, new = by_host[cams[0].host], by_host[cams[1].host]
    assert all(c.revert and not c.disruptive for p in plans for c in p.changes)
    assert "AX-B-002" in old and "AX-B-002" not in new                  # UPnP is off by default from 12.0
    assert "AX-B-011" not in old                                        # ciphers are never reverted
    assert {"AX-B-001", "AX-B-009", "AX-B-014", "AX-B-016"} <= set(old)
    apply(catalog, nxt, out, plans, factory)
    d10 = devices[cams[0].host].params
    assert d10["root.Network.Bonjour.Enabled"] == "yes" and d10["root.System.BoaGroupPolicy.admin"] == "both"
    assert d10["root.System.WebInterfaceDisabled"] == "no" and d10["root.Network.UPnP.Enabled"] == "yes"
    assert devices[cams[1].host].params["root.Network.UPnP.Enabled"] == "no"


def test_controls_option_never_reverts(tmp_path, catalog, m4216):
    cams, factory, devices, prof, out, plans = setup(tmp_path, catalog, [m4216], "basic-full")
    apply(catalog, prof, out, plans, factory)
    _, _, audits = run_audit(cams, catalog, load_profile("audit-only", catalog), AuditSettings(operator="t"),
                             password_findings([]), out, client_factory=factory, simulated=True)
    only = make_plan(audits, cams, catalog, load_profile("audit-only", catalog), controls=["AX-B-001"])
    assert not only[0].changes
    assert not any(c.revert for c in make_plan(audits, cams, catalog, load_profile("basic-full", catalog))[0].changes)


def test_rows_use_plain_state_words(tmp_path, catalog, m4216):
    cams, factory, devices, nxt, out, plans = _harden_then(tmp_path, catalog, [m4216], "basic-full",
                                                           "factory-defaults")
    by_id = {c.control_id: c for c in plans[0].changes}
    bonjour = by_id["AX-B-001"]
    assert bonjour.title == "Bonjour discovery: back to factory default"
    assert (bonjour.now_label, bonjour.new_label) == ("Disabled", "Enabled (factory)")
    assert (by_id["AX-B-014"].now_label, by_id["AX-B-014"].new_label) == ("Enabled", "Disabled (factory)")
    assert by_id["AX-B-009"].new_label == "HTTP and HTTPS (factory)"
    (tmp_path / "b").mkdir()
    _, _, _, _, _, fresh = setup(tmp_path / "b", catalog, [m4216], "basic-safe")
    up = next(c for c in fresh[0].changes if c.control_id == "AX-B-002")
    assert (up.now_label, up.new_label) == ("Enabled", "Disabled")
