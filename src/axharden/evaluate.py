"""Evaluate controls against a camera's data. Pure logic: all I/O goes through AuditContext."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .catalog import Control
from .inventory import Camera, PasswordFindings
from .vapix.params import ParamTree
from .version import AxisVersion

COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_SUPPORTED = "NOT_SUPPORTED"
NA = "N/A"
ERROR = "ERROR"
INFO = "INFO"
STATUSES = (COMPLIANT, NON_COMPLIANT, NOT_SUPPORTED, NA, ERROR, INFO)


@dataclass
class ControlResult:
    id: str
    status: str
    observed: dict[str, Any] = field(default_factory=dict)
    detail: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "observed": self.observed, "detail": self.detail}

    @classmethod
    def from_dict(cls, d: dict) -> "ControlResult":
        return cls(id=d["id"], status=d["status"], observed=d.get("observed") or {}, detail=d.get("detail", ""))


class ProbeUnavailable(Exception):
    """Raised in simulate mode when a fixture lacks a recorded probe."""


@dataclass
class AuditContext:
    camera: Camera
    params: ParamTree
    version: AxisVersion | None
    device_info: dict[str, str]
    api_ids: set[str]
    passwords: PasswordFindings
    # probe(key, live_fn) -> recorded value. In live mode calls live_fn and records; in simulate mode replays.
    probe: Callable[[str, Callable[[], Any]], Any]
    client: Any = None


def _eq(a: str | None, b: str) -> bool:
    return a is not None and a.strip().lower() == b.strip().lower()


def _subset(device: str | None, allowed: str) -> tuple[bool, list[str]]:
    allowed_set = {x.strip().upper() for x in allowed.split(":") if x.strip()}
    items = [x.strip() for x in (device or "").split(":") if x.strip()]
    extra = [x for x in items if x.upper() not in allowed_set]
    return (bool(items) and not extra), extra


def _missing_reason(ctl: Control, removed_in: AxisVersion | None, ver: AxisVersion | None) -> str:
    removed = removed_in or ctl.removed_in
    if removed and ver and ver >= removed:
        return f"Feature removed in AXIS OS {removed}; compliant by design."
    if ctl.introduced_in and ver and ver < ctl.introduced_in:
        return f"Needs AXIS OS {ctl.introduced_in} or later (device has {ver}). Upgrade to get this control."
    return "Parameter not present on this model/firmware."


def evaluate_params(ctl: Control, params: ParamTree, ver: AxisVersion | None) -> ControlResult:
    observed: dict[str, Any] = {}
    failures: list[str] = []
    notes: list[str] = []
    evaluated = 0
    for spec in ctl.params:
        if "*" in spec.name:
            matches = list(params.match(spec.name))
        else:
            actual = params.actual_name(spec.name)
            matches = [(actual, params.values[actual])] if actual else []
        if not matches:
            observed[spec.name] = None
            if spec.optional:
                continue
            status = NA if ctl.missing_status == "na" else NOT_SUPPORTED
            return ControlResult(ctl.id, status, observed, _missing_reason(ctl, spec.removed_in, ver))
        for actual, value in matches:
            observed[actual] = value
            evaluated += 1
            if actual.lower() == spec.name.lower() and actual != spec.name and "*" not in spec.name:
                notes.append(f"Device spells it {actual}")
            if ctl.compare == "subset":
                ok, extra = _subset(value, spec.hardened)
                if not ok:
                    failures.append(f"Also allows older ciphers: {', '.join(extra)}" if extra else "Cipher list is empty")
            elif not _eq(value, spec.hardened):
                failures.append(f"{actual}={value!r} (want {spec.hardened})")
    if evaluated == 0:
        status = NA if ctl.missing_status == "na" else NOT_SUPPORTED
        return ControlResult(ctl.id, status, observed, _missing_reason(ctl, None, ver))
    if failures:
        detail = "; ".join(failures + notes)
        if ctl.advisory_from and ver and ver >= ctl.advisory_from:
            prefix = "Advisory" if ctl.advisory_from.key == (0, 0, 0, 0) else f"Advisory from AXIS OS {ctl.advisory_from}"
            return ControlResult(ctl.id, INFO, observed, f"{prefix}: {detail}")
        return ControlResult(ctl.id, NON_COMPLIANT, observed, detail)
    return ControlResult(ctl.id, COMPLIANT, observed, "; ".join(notes))


def evaluate(ctl: Control, ctx: AuditContext) -> ControlResult:
    from .vapix.handlers import HANDLERS  # local import to avoid a cycle

    try:
        if ctl.method == "param":
            return evaluate_params(ctl, ctx.params, ctx.version)
        fn = HANDLERS.get(ctl.handler or "")
        if fn is None:
            return ControlResult(ctl.id, ERROR, detail=f"No handler named {ctl.handler!r}")
        if ctl.introduced_in and ctx.version and ctx.version < ctl.introduced_in:
            return ControlResult(ctl.id, NOT_SUPPORTED,
                                 detail=f"Needs AXIS OS {ctl.introduced_in} or later (device has {ctx.version}).")
        return fn(ctl, ctx)
    except ProbeUnavailable as e:
        return ControlResult(ctl.id, ERROR, detail=f"No recorded data for this check ({e})")
    except Exception as e:  # one control never stops the camera
        from .vapix.client import CameraError
        if isinstance(e, CameraError) and e.code == "AUTH_FAILED":
            raise
        return ControlResult(ctl.id, ERROR, detail=f"{type(e).__name__}: {e}")


def baseline_view(results: list[ControlResult], baseline_ids: list[str] | None,
                  baseline_name: str = "") -> list[ControlResult]:
    """Results as seen against a baseline (profile): controls outside it become N/A ("not in this baseline"), so
    they are not scored or listed as problems. The raw results are kept elsewhere for planning (reverts)."""
    if not baseline_ids:
        return results
    wanted = set(baseline_ids)
    label = f"Not part of the {baseline_name} baseline." if baseline_name else "Not part of the chosen baseline."
    return [r if r.id in wanted else ControlResult(r.id, NA, r.observed, label) for r in results]


def compliance_pct(results: list[ControlResult]) -> float | None:
    scored = [r for r in results if r.status in (COMPLIANT, NON_COMPLIANT)]
    if not scored:
        return None
    return 100.0 * sum(r.status == COMPLIANT for r in scored) / len(scored)
