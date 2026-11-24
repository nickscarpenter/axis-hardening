"""Control catalog and profiles: loading, schema validation, hashing."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .version import AxisVersion, v

LEVELS = ("default", "basic", "extended", "legacy")
KINDS = ("apply", "check")
METHODS = ("param", "handler")
COMPARES = ("equals", "subset")


class CatalogError(Exception):
    pass


def resource_dir() -> Path:
    """Directory holding catalog/ (works from source checkout and PyInstaller one-folder builds)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class ParamSpec:
    name: str
    hardened: str
    optional: bool = False
    removed_in: AxisVersion | None = None


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    guide_section: str
    guide_page: int
    csc: tuple[str, ...]
    level: str
    kind: str
    method: str
    params: tuple[ParamSpec, ...] = ()
    compare: str = "equals"
    handler: str | None = None
    handler_args: dict = field(default_factory=dict, hash=False, compare=False)
    removed_in: AxisVersion | None = None
    introduced_in: AxisVersion | None = None
    advisory_from: AxisVersion | None = None
    missing_status: str = "not_supported"
    disruptive: bool = False
    requires_reboot: bool = False
    opt_in: bool = False
    warning: str | None = None
    verified_on: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        return bool(self.verified_on)

    @property
    def hardened_summary(self) -> str:
        if self.params:
            return "; ".join(f"{p.name}={p.hardened}" for p in self.params)
        if self.handler_args.get("hardened") is not None:
            return f"{self.handler}: {self.handler_args.get('name', '')}={self.handler_args['hardened']}".replace(": =", ": ")
        return f"({self.handler})"


@dataclass
class Catalog:
    controls: list[Control]
    sha256: str
    path: Path

    def __post_init__(self) -> None:
        self.by_id = {c.id: c for c in self.controls}

    def get(self, cid: str) -> Control:
        try:
            return self.by_id[cid]
        except KeyError:
            raise CatalogError(f"Unknown control id {cid!r}") from None


def _opt_version(value: Any, where: str) -> AxisVersion | None:
    if value is None:
        return None
    try:
        return v(str(value))
    except ValueError as e:
        raise CatalogError(f"{where}: {e}") from None


def _control(raw: dict) -> Control:
    cid = raw.get("id", "<no id>")
    for key in ("id", "title", "guide_section", "guide_page", "level", "kind", "method"):
        if key not in raw:
            raise CatalogError(f"{cid}: missing field '{key}'")
    if raw["level"] not in LEVELS:
        raise CatalogError(f"{cid}: level must be one of {LEVELS}")
    if raw["kind"] not in KINDS:
        raise CatalogError(f"{cid}: kind must be one of {KINDS}")
    if raw["method"] not in METHODS:
        raise CatalogError(f"{cid}: method must be one of {METHODS}")
    compare = raw.get("compare", "equals")
    if compare not in COMPARES:
        raise CatalogError(f"{cid}: compare must be one of {COMPARES}")
    params = []
    for p in raw.get("params") or []:
        if "name" not in p or "hardened" not in p:
            raise CatalogError(f"{cid}: each param needs 'name' and 'hardened'")
        params.append(ParamSpec(name=str(p["name"]), hardened=str(p["hardened"]),
                                optional=bool(p.get("optional", False)),
                                removed_in=_opt_version(p.get("removed_in"), cid)))
    if raw["method"] == "param" and not params:
        raise CatalogError(f"{cid}: method 'param' needs at least one param")
    if raw["method"] == "handler" and not raw.get("handler"):
        raise CatalogError(f"{cid}: method 'handler' needs 'handler'")
    missing_status = raw.get("missing_status", "not_supported")
    if missing_status not in ("not_supported", "na"):
        raise CatalogError(f"{cid}: missing_status must be not_supported or na")
    return Control(
        id=cid, title=raw["title"], guide_section=raw["guide_section"], guide_page=int(raw["guide_page"]),
        csc=tuple(str(c) for c in raw.get("csc") or ()), level=raw["level"], kind=raw["kind"],
        method=raw["method"], params=tuple(params), compare=compare, handler=raw.get("handler"),
        handler_args=dict(raw.get("handler_args") or {}),
        removed_in=_opt_version(raw.get("removed_in"), cid),
        introduced_in=_opt_version(raw.get("introduced_in"), cid),
        advisory_from=_opt_version(raw.get("advisory_from"), cid),
        missing_status=missing_status,
        disruptive=bool(raw.get("disruptive", False)), requires_reboot=bool(raw.get("requires_reboot", False)),
        opt_in=bool(raw.get("opt_in", False)), warning=raw.get("warning"),
        verified_on=tuple(raw.get("verified_on") or ()),
    )


def load_catalog(path: str | Path | None = None) -> Catalog:
    path = Path(path) if path else resource_dir() / "catalog" / "hardening_controls.yaml"
    data = path.read_bytes()
    doc = yaml.safe_load(data)
    if not isinstance(doc, dict) or "controls" not in doc:
        raise CatalogError(f"{path}: expected a mapping with 'controls'")
    controls = [_control(c) for c in doc["controls"]]
    ids = [c.id for c in controls]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise CatalogError(f"Duplicate control ids: {sorted(dupes)}")
    return Catalog(controls=controls, sha256=hashlib.sha256(data).hexdigest(), path=path)


@dataclass
class Profile:
    name: str
    description: str
    control_ids: list[str]


def load_profile(name_or_path: str, catalog: Catalog, profiles_dir: Path | None = None) -> Profile:
    profiles_dir = profiles_dir or resource_dir() / "catalog" / "profiles"
    p = Path(name_or_path)
    if not p.suffix:
        p = profiles_dir / f"{name_or_path}.yaml"
    if not p.exists():
        available = ", ".join(sorted(x.stem for x in profiles_dir.glob("*.yaml")))
        raise CatalogError(f"Profile not found: {name_or_path} (available: {available})")
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    ids: list[str] = []
    if doc.get("extends"):
        ids.extend(load_profile(doc["extends"], catalog, profiles_dir).control_ids)
    if doc.get("include_all"):
        ids.extend(c.id for c in catalog.controls)
    if doc.get("include_checks"):
        ids.extend(c.id for c in catalog.controls if c.kind == "check")
    for cid in doc.get("controls") or []:
        catalog.get(cid)  # validates
        ids.append(cid)
    for cid in doc.get("exclude") or []:
        ids = [i for i in ids if i != cid]
    # keep catalog order, de-duplicate
    wanted = set(ids)
    ordered = [c.id for c in catalog.controls if c.id in wanted]
    return Profile(name=doc.get("name", p.stem), description=str(doc.get("description", "")).strip(), control_ids=ordered)
