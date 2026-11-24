import copy
import json
from pathlib import Path

import pytest

from axharden.catalog import load_catalog
from axharden.logging_setup import clear_secrets

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _clean_secrets():
    yield
    clear_secrets()


@pytest.fixture(scope="session")
def catalog():
    return load_catalog()


@pytest.fixture
def m4216():
    """Real (anonymised) AXIS M4216-LV AXIS OS 10.12.252 discover fixture."""
    return json.loads((FIXTURES / "m4216lv_10.12.252.json").read_text(encoding="utf-8"))


def variant(base: dict, version: str, host: str, drop: tuple[str, ...] = (), set_: dict | None = None) -> dict:
    """Derive a synthetic fixture for another AXIS OS version."""
    snap = copy.deepcopy(base)
    snap["device"]["Version"] = version
    snap["params"]["root.Properties.Firmware.Version"] = version
    for name in drop:
        snap["params"].pop(name, None)
    snap["params"].update(set_ or {})
    snap["camera"]["host"] = host
    snap["camera"]["name"] = f"synthetic {version}"
    return snap
