"""discover: dump a reference camera and diff it against the catalog (CLAUDE.md §7.4)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .audit import SNAPSHOT_VERSION, _device_summary, _run_checks, safe_name, write_private
from .catalog import Catalog
from .inventory import Camera, PasswordFindings
from .vapix import device as vdevice
from .vapix import params as vparams
from .vapix.client import CameraClient, TLSPolicy

# Mask parameters whose name ENDS in a secret word (ActivatePasswordThrottling / HTTPServerTokens are settings, not secrets).
_SECRET_NAME = re.compile(r"(?i)(password|passwd|pwd|passphrase|secret|community|psk|privatekey|proxylogin|token|key)$")


@dataclass
class ParamCheck:
    control_id: str
    name: str
    status: str            # present | missing | case_differs | pattern_matched | pattern_none
    actual: str | None = None
    value: str | None = None


@dataclass
class DiscoverResult:
    device: dict
    params_count: int
    api_ids: list[str]
    checks: list[ParamCheck] = field(default_factory=list)
    out_dir: Path | None = None

    @property
    def model_fw(self) -> str:
        return f"{self.device.get('ProdNbr', '?')} {self.device.get('Version', '?')}"


def sanitise_params(values: dict[str, str]) -> dict[str, str]:
    """Mask values of secret-looking parameters so dumps can be kept as test fixtures."""
    out = {}
    for k, val in values.items():
        last = k.rsplit(".", 1)[-1]
        if val and _SECRET_NAME.search(last):
            out[k] = "***"
        else:
            out[k] = val
    return out


def diff_catalog(tree: vparams.ParamTree, catalog: Catalog) -> list[ParamCheck]:
    checks: list[ParamCheck] = []
    for ctl in catalog.controls:
        for spec in ctl.params:
            if "*" in spec.name:
                matches = list(tree.match(spec.name))
                if matches:
                    for actual, value in matches:
                        checks.append(ParamCheck(ctl.id, spec.name, "pattern_matched", actual, value))
                else:
                    checks.append(ParamCheck(ctl.id, spec.name, "pattern_none"))
                continue
            actual = tree.actual_name(spec.name)
            if actual is None:
                checks.append(ParamCheck(ctl.id, spec.name, "missing"))
            elif actual != vparams.normalise(spec.name):
                checks.append(ParamCheck(ctl.id, spec.name, "case_differs", actual, tree.values[actual]))
            else:
                checks.append(ParamCheck(ctl.id, spec.name, "present", actual, tree.values[actual]))
    return checks


def run_discover(camera: Camera, catalog: Catalog, tls: TLSPolicy, output_dir: Path,
                 timeout: float = 10.0, min_delay: float = 0.1) -> DiscoverResult:
    probes: dict[str, Any] = {}

    def probe(key: str, fn: Callable[[], Any]) -> Any:
        if key not in probes:
            probes[key] = fn()
        return probes[key]

    with CameraClient(camera, tls=tls, timeout=timeout, min_delay=min_delay) as client:
        auth = client.negotiate()
        info = vdevice.basic_device_info(client)
        tree = vparams.list_all(client)
        apis = vdevice.api_list(client)
        info = _device_summary(info, tree)
        api_ids = sorted({a.get("id", "") for a in apis})
        # Run every catalog check once so its probes are captured for the fixture.
        results = _run_checks(camera, catalog, [c.id for c in catalog.controls], tree, info, set(api_ids),
                              PasswordFindings(), probe, client, "10.0")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = output_dir / "discover" / f"{safe_name(camera.host)}-{stamp}"
    result = DiscoverResult(device=info, params_count=len(tree), api_ids=api_ids,
                            checks=diff_catalog(tree, catalog), out_dir=out)

    write_private(out / "params.json", json.dumps(sanitise_params(tree.to_dict()), indent=1))
    write_private(out / "apidiscovery.json", json.dumps(apis, indent=1))
    write_private(out / "catalog_diff.json", json.dumps([c.__dict__ for c in result.checks], indent=1))
    fixture_cam = {"host": camera.host, "port": camera.port, "name": camera.name or info.get("ProdNbr", ""),
                   "customer": camera.customer, "protocol": camera.protocol, "profile": "", "ports": camera.ports,
                   "notes": "discover fixture", "username": camera.credential.username}
    fixture = {"snapshot_version": SNAPSHOT_VERSION, "tool_version": __version__, "camera": fixture_cam,
               "device": info, "params": sanitise_params(tree.to_dict()), "apis": apis, "probes": probes,
               "auth_scheme": auth, "results": [r.to_dict() for r in results], "status": "OK"}
    write_private(out / "fixture.json", json.dumps(fixture, indent=1, default=str))
    return result
