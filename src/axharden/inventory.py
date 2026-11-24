"""Inventory loading (CSV/XLSX). Credentials are held in memory only and never written anywhere."""

from __future__ import annotations

import csv
import getpass
import hashlib
import ipaddress
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .logging_setup import register_secret

COLUMNS = ["ip", "username", "password", "name", "site", "protocol", "profile", "ports", "notes"]
REQUIRED = ["ip", "username"]
WEAK_PASSWORD_LEN = 8  # guide p.16
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


class InventoryError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"{len(errors)} inventory error(s)")


class Credential:
    """Username/password pair. The password is never exposed by repr/str."""

    __slots__ = ("username", "_password")

    def __init__(self, username: str, password: str):
        self.username = username
        self._password = password
        register_secret(password)

    @property
    def password(self) -> str:
        return self._password

    def __repr__(self) -> str:
        return f"Credential(username={self.username!r}, password='***')"

    __str__ = __repr__

    def __reduce__(self):  # refuse pickling
        raise TypeError("Credential objects cannot be serialised")


@dataclass
class Camera:
    host: str            # IP or hostname, no port
    port: int | None
    credential: Credential = field(repr=False)
    name: str = ""
    site: str = ""
    protocol: str = "https"
    profile: str = ""
    ports: list[int] = field(default_factory=list)  # network ports for AX-B-021/022 (phase 3)
    notes: str = ""
    row: int = 0

    @property
    def address(self) -> str:
        """host[:port] suitable for a URL (IPv6 bracketed)."""
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}" if self.port else h

    @property
    def label(self) -> str:
        return f"{self.name} ({self.host})" if self.name else self.host

    def public_dict(self) -> dict:
        """Safe for snapshots/reports: no credentials."""
        return {
            "host": self.host, "port": self.port, "name": self.name, "site": self.site,
            "protocol": self.protocol, "profile": self.profile, "ports": self.ports,
            "notes": self.notes, "username": self.credential.username,
        }


@dataclass
class PasswordFindings:
    shared_groups: list[list[str]] = field(default_factory=list)  # camera labels sharing a password
    weak: list[str] = field(default_factory=list)                 # camera labels with < 8 char passwords

    def for_camera(self, label: str) -> tuple[bool, bool]:
        shared = any(label in g for g in self.shared_groups)
        return shared, label in self.weak


def parse_host(text: str) -> tuple[str, int | None]:
    """Split 'host', 'host:port', '[v6]:port' or bare IPv6. Raises ValueError."""
    text = text.strip()
    if not text:
        raise ValueError("empty address")
    if text.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", text)
        if not m:
            raise ValueError(f"bad bracketed IPv6 address {text!r}")
        ipaddress.IPv6Address(m.group(1))
        return m.group(1), _port(m.group(2))
    if text.count(":") > 1:  # bare IPv6
        ipaddress.IPv6Address(text)
        return text, None
    host, _, port = text.partition(":")
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if re.match(r"^[\d.]+$", host) or not _HOSTNAME_RE.match(host):
            raise ValueError(f"not a valid IP address or hostname: {host!r}")
    return host, _port(port or None)


def _port(text: str | None) -> int | None:
    if text is None:
        return None
    p = int(text)
    if not 1 <= p <= 65535:
        raise ValueError(f"port out of range: {p}")
    return p


def _read_rows(path: Path) -> list[dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows = list(reader)
    elif suffix in (".xlsx", ".xlsm"):
        from openpyxl import load_workbook
        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb.worksheets[0]
        rows = [["" if c is None else str(c) for c in r] for r in ws.iter_rows(values_only=True)]
        wb.close()
    else:
        raise InventoryError([f"Unsupported inventory format {suffix!r}: use .csv or .xlsx"])
    if not rows:
        raise InventoryError(["Inventory file is empty"])
    header = [h.strip().lower() for h in rows[0]]
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise InventoryError([f"Header row is missing required column(s): {', '.join(missing)}"])
    out = []
    for r in rows[1:]:
        if not any(str(c).strip() for c in r):
            continue  # blank line
        padded = list(r) + [""] * (len(header) - len(r))
        out.append({header[i]: str(padded[i]).strip() if header[i] != "password" else str(padded[i])
                    for i in range(len(header)) if header[i]})
    return out


PromptFn = Callable[[str], str]


def _default_prompt(username: str) -> str:
    return getpass.getpass(f"Password for camera user '{username}': ")


def load_inventory(path: str | os.PathLike, prompt: PromptFn | None = _default_prompt) -> list[Camera]:
    """Read and validate the inventory. Reports every error at once. Blank passwords are prompted for
    once per distinct username (if prompt is None, blank passwords are an error)."""
    path = Path(path)
    if not path.exists():
        raise InventoryError([f"Inventory file not found: {path}"])
    raw = _read_rows(path)
    errors: list[str] = []
    seen: dict[tuple[str, int | None], int] = {}
    pending: list[tuple[int, dict[str, str], str, int | None, list[int]]] = []

    for i, row in enumerate(raw, start=2):  # row 1 is the header
        for col in REQUIRED:
            if not row.get(col, "").strip():
                errors.append(f"Row {i}: missing '{col}'")
        if not row.get("ip", "").strip():
            continue
        try:
            host, port = parse_host(row["ip"])
        except ValueError as e:
            errors.append(f"Row {i}: {e}")
            continue
        key = (host.lower(), port)
        if key in seen:
            errors.append(f"Row {i}: duplicate address {row['ip']} (first seen on row {seen[key]})")
        else:
            seen[key] = i
        proto = (row.get("protocol") or "https").strip().lower()
        if proto not in ("http", "https"):
            errors.append(f"Row {i}: protocol must be 'https' or 'http', got {proto!r}")
        ports: list[int] = []
        if row.get("ports", "").strip():
            try:
                ports = [int(p) for p in re.split(r"[;,\s]+", row["ports"].strip()) if p]
            except ValueError:
                errors.append(f"Row {i}: 'ports' must be a list of numbers, e.g. '5;6;7'")
        pending.append((i, row, host, port, ports))

    if errors:
        raise InventoryError(errors)

    # Prompt for blank passwords, once per username.
    prompted: dict[str, str] = {}
    cameras: list[Camera] = []
    for i, row, host, port, ports in pending:
        user = row["username"].strip()
        pw = row.get("password", "")
        if pw == "":
            if prompt is None:
                errors.append(f"Row {i}: password is blank and prompting is disabled")
                continue
            if user not in prompted:
                prompted[user] = prompt(user)
            pw = prompted[user]
        cameras.append(Camera(
            host=host, port=port, credential=Credential(user, pw),
            name=row.get("name", ""), site=row.get("site", ""),
            protocol=(row.get("protocol") or "https").strip().lower(),
            profile=row.get("profile", ""), ports=ports, notes=row.get("notes", ""), row=i,
        ))
    if errors:
        raise InventoryError(errors)
    return cameras


def password_findings(cameras: Iterable[Camera]) -> PasswordFindings:
    """Common-password (guide p.31) and weak-password (p.16) checks, using salted hashes in memory only."""
    salt = secrets.token_bytes(16)
    groups: dict[bytes, list[str]] = {}
    findings = PasswordFindings()
    for cam in cameras:
        pw = cam.credential.password
        digest = hashlib.sha256(salt + pw.encode("utf-8")).digest()
        groups.setdefault(digest, []).append(cam.label)
        if len(pw) < WEAK_PASSWORD_LEN:
            findings.weak.append(cam.label)
    findings.shared_groups = [g for g in groups.values() if len(g) > 1]
    return findings


def write_templates(out_dir: str | os.PathLike) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    example = ["10.0.0.21", "root", "", "Gate cam 1", "Site A", "https", "", "", "Leave password blank to be prompted"]
    csv_path = out / "inventory_template.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        w.writerow(example)
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "cameras"
    ws.append(COLUMNS)
    ws.append(example)
    xlsx_path = out / "inventory_template.xlsx"
    wb.save(xlsx_path)
    return [csv_path, xlsx_path]
