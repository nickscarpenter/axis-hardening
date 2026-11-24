"""AXIS OS version parsing and numeric comparison (10.6 < 10.12)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?")


@total_ordering
@dataclass(frozen=True)
class AxisVersion:
    major: int
    minor: int
    patch: int = 0
    build: int = 0
    raw: str = ""

    @classmethod
    def parse(cls, text: str | None) -> "AxisVersion | None":
        if not text:
            return None
        m = _VERSION_RE.match(str(text))
        if not m:
            return None
        parts = [int(g) if g else 0 for g in m.groups()]
        return cls(*parts, raw=str(text).strip())

    @property
    def key(self) -> tuple[int, int, int, int]:
        return (self.major, self.minor, self.patch, self.build)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, AxisVersion):
            return NotImplemented
        return self.key < other.key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AxisVersion):
            return NotImplemented
        return self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    @property
    def track(self) -> str:
        """Major.x track label, e.g. '10.x'. LTS tracks are 10.12 (2022 LTS), 11.11 (2024 LTS), 12.x (2026 LTS)."""
        return f"{self.major}.x"

    def __str__(self) -> str:
        return self.raw or ".".join(str(p) for p in self.key)


def v(text: str) -> AxisVersion:
    """Parse or raise; for catalog/config values that must be valid."""
    parsed = AxisVersion.parse(text)
    if parsed is None:
        raise ValueError(f"Not a valid AXIS OS version: {text!r}")
    return parsed
