"""Append-only, hash-chained audit log of every camera write (CLAUDE.md §2, §9).

Each JSONL line holds `prev_hash` (the previous line's `hash`) and `hash` = SHA-256 of the line's canonical
JSON without the `hash` field. Editing, deleting or reordering any line breaks verification.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import threading
from pathlib import Path
from typing import Any

from .audit import now_iso

GENESIS = "0" * 64
_LOCK = threading.Lock()


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path, operator: str = ""):
        self.path = Path(path)
        self.operator = operator
        try:
            self.os_user = getpass.getuser()
        except Exception:
            self.os_user = ""
        self.host = socket.gethostname()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open("rb") as f:
            # read the final non-empty line without loading a huge file
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, 65536)
            f.seek(size - block)
            for line in f.read().splitlines():
                if line.strip():
                    last = line.decode("utf-8")
        if not last:
            return GENESIS
        return json.loads(last)["hash"]

    def append(self, event: str, **fields: Any) -> dict:
        with _LOCK:
            entry = {"ts": now_iso(), "event": event, "operator": self.operator, "os_user": self.os_user,
                     "workstation": self.host, **fields, "prev_hash": self._last_hash()}
            entry["hash"] = _digest(entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            new = not self.path.exists()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            if new:
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            return entry


def verify(path: Path) -> tuple[bool, int, str]:
    """Check the whole chain. Returns (ok, entries_checked, message)."""
    path = Path(path)
    if not path.exists():
        return True, 0, "No audit log yet."
    prev = GENESIS
    n = 0
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, n, f"Line {lineno}: not valid JSON"
            if entry.get("prev_hash") != prev:
                return False, n, f"Line {lineno}: chain broken (prev_hash does not match the previous entry)"
            if entry.get("hash") != _digest(entry):
                return False, n, f"Line {lineno}: entry has been altered (hash mismatch)"
            prev = entry["hash"]
            n += 1
    return True, n, f"OK: {n} entries, chain intact."


def entries_for_run(path: Path, run_id: str) -> list[dict]:
    if not Path(path).exists():
        return []
    out = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                if e.get("run_id") == run_id:
                    out.append(e)
    return out
