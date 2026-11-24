"""param.cgi list (one call for the whole tree) and case-insensitive lookup."""

from __future__ import annotations

import fnmatch
from typing import Iterator

from .client import CameraClient


class ParamTree:
    """All parameters from one param.cgi?action=list call. Lookups are case-insensitive and
    report the camera's own spelling, so `discover` can flag case differences."""

    def __init__(self, values: dict[str, str]):
        self.values = dict(values)
        self._lower = {k.lower(): k for k in values}

    def __len__(self) -> int:
        return len(self.values)

    def __contains__(self, name: str) -> bool:
        return normalise(name).lower() in self._lower

    def actual_name(self, name: str) -> str | None:
        return self._lower.get(normalise(name).lower())

    def get(self, name: str) -> str | None:
        actual = self.actual_name(name)
        return None if actual is None else self.values[actual]

    def match(self, pattern: str) -> Iterator[tuple[str, str]]:
        """Glob match (case-insensitive), e.g. 'root.Image.I*.SignedVideo.Enabled'."""
        pat = normalise(pattern).lower()
        for low, actual in self._lower.items():
            if fnmatch.fnmatchcase(low, pat):
                yield actual, self.values[actual]

    def group(self, prefix: str) -> dict[str, str]:
        p = normalise(prefix).lower().rstrip(".") + "."
        return {a: self.values[a] for low, a in self._lower.items() if low.startswith(p)}

    def to_dict(self) -> dict[str, str]:
        return dict(sorted(self.values.items()))


def normalise(name: str) -> str:
    """Add the 'root.' prefix the guide sometimes omits."""
    name = name.strip()
    return name if name.lower().startswith("root.") else "root." + name


def parse_list(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value
    return values


def list_all(client: CameraClient) -> ParamTree:
    resp = client.get("/axis-cgi/param.cgi?action=list")
    return ParamTree(parse_list(resp.text))
