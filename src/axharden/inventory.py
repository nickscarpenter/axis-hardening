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

COLUMNS = ["ip", "username", "password", "name", "customer", "protocol", "profile", "ports", "notes",
           "hostname", "dns", "ntp", "timezone",
           "new_username", "new_password", "new_role", "new_username2", "new_password2", "new_role2"]
SECRET_COLUMNS = ("password", "new_password", "new_password2")   # kept exactly as typed (no stripping)
NEW_ACCOUNT_SLOTS = ("", "2")   # column suffixes: new_username / new_username2, ...
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
class NewAccount:
    """An account to create on a camera. The password lives in the Credential (masked, memory only)."""
    credential: Credential = field(repr=False)
    role: str = "viewer"          # viewer | operator | admin
    ptz: bool = False

    @property
    def username(self) -> str:
        return self.credential.username

    def public_dict(self) -> dict:
        return {"username": self.username, "role": self.role, "ptz": self.ptz}


@dataclass
class Camera:
    host: str            # IP or hostname, no port
    port: int | None
    credential: Credential = field(repr=False)
    name: str = ""
    customer: str = ""
    protocol: str = "https"
    profile: str = ""
    ports: list[int] = field(default_factory=list)  # network ports for AX-B-021/022 (phase 3)
    notes: str = ""
    hostname: str = ""                                    # camera host name to set (Fix problems)
    dns: list[str] = field(default_factory=list)          # 0-2 DNS servers to set
    ntp: str = ""                                         # NTP server to set (IP or host name)
    timezone: str = ""                                    # IANA name from timezones.ZONES, or a POSIX rule
    row: int = 0
    new_accounts: list[NewAccount] = field(default_factory=list, repr=False)   # 0-2 accounts to create

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
            "host": self.host, "port": self.port, "name": self.name, "customer": self.customer,
            "protocol": self.protocol, "profile": self.profile, "ports": self.ports,
            "notes": self.notes, "username": self.credential.username,
            "hostname": self.hostname, "dns": self.dns, "ntp": self.ntp, "timezone": self.timezone,
            "new_accounts": [a.public_dict() for a in self.new_accounts],
        }


@dataclass
class PasswordFindings:
    shared_groups: list[list[str]] = field(default_factory=list)  # camera labels sharing a password
    weak: list[str] = field(default_factory=list)                 # camera labels with < 8 char passwords

    def for_camera(self, label: str) -> tuple[bool, bool]:
        shared = any(label in g for g in self.shared_groups)
        return shared, label in self.weak


def split_list(text: str) -> list[str]:
    return [x for x in re.split(r"[;,\s]+", (text or "").strip()) if x]


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def network_problems(row: dict[str, str]) -> list[str]:
    """Validate the hostname / dns / ntp / timezone columns of one row."""
    from .timezones import resolve
    out = []
    hn = row.get("hostname", "").strip()
    if hn and not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", hn):
        out.append(f"hostname {hn!r}: use 1-63 letters, digits and '-' (no dots, spaces or '_'; not starting or "
                   "ending with '-')")
    dns = split_list(row.get("dns", ""))
    if len(dns) > 2:
        out.append("dns: give at most two DNS servers, separated by ';'")
    out += [f"dns: {d!r} is not an IP address" for d in dns if not _is_ip(d)]
    ntp = row.get("ntp", "").strip()
    if ntp and len(split_list(ntp)) > 1:
        out.append("ntp: give one time server (the camera stores a single NTP server)")
    elif ntp and not (_is_ip(ntp) or _HOSTNAME_RE.match(ntp)):
        out.append(f"ntp: {ntp!r} is not an IP address or host name")
    tz = row.get("timezone", "").strip()
    if tz:
        try:
            resolve(tz)
        except ValueError as e:
            out.append(f"timezone: {e}")
    return out


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
        out.append({header[i]: str(padded[i]).strip() if header[i] not in SECRET_COLUMNS else str(padded[i])
                    for i in range(len(header)) if header[i]})
    return out


PromptFn = Callable[[str], str]


def _default_prompt(username: str) -> str:
    return getpass.getpass(f"Password for camera user '{username}': ")


def ask_new_password(username: str) -> str:
    while True:
        a = getpass.getpass(f"Password for the NEW account '{username}': ")
        if a == getpass.getpass("Type it again: "):
            return a
        print("The two passwords differ, try again.")


def load_inventory(path: str | os.PathLike, prompt: PromptFn | None = _default_prompt,
                   new_prompt: PromptFn | None = None) -> list[Camera]:
    """Read and validate the inventory. Reports every error at once. Blank passwords are prompted for
    once per distinct username (if prompt is None, blank passwords are an error). Blank new-account passwords
    (new_password) are asked for via new_prompt, once per new username; with new_prompt=None they stay blank
    until the account is actually created (see accounts.fill_passwords)."""
    from .vapix.users import parse_role, password_problem, username_problem
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
        new_names = []
        for sfx in NEW_ACCOUNT_SLOTS:
            new_user = row.get(f"new_username{sfx}", "").strip()
            if new_user:
                prob = username_problem(new_user, row.get("username", "").strip())
                if prob:
                    errors.append(f"Row {i}: new_username{sfx}: {prob}")
                try:
                    parse_role(row.get(f"new_role{sfx}", "") or "viewer")
                except ValueError as e:
                    errors.append(f"Row {i}: new_role{sfx}: {e}")
                if row.get(f"new_password{sfx}", ""):
                    prob = password_problem(row[f"new_password{sfx}"], new_user)
                    if prob:
                        errors.append(f"Row {i}: new_password{sfx}: {prob}")
                if new_user.lower() in new_names:
                    errors.append(f"Row {i}: new_username and new_username2 are the same ({new_user})")
                new_names.append(new_user.lower())
            elif row.get(f"new_password{sfx}", "") or row.get(f"new_role{sfx}", "").strip():
                errors.append(f"Row {i}: new_password{sfx}/new_role{sfx} given but new_username{sfx} is blank")
        errors += [f"Row {i}: {e}" for e in network_problems(row)]
        pending.append((i, row, host, port, ports))

    if errors:
        raise InventoryError(errors)

    # Prompt for blank passwords, once per username.
    prompted: dict[str, str] = {}
    new_prompted: dict[str, str] = {}
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
        new_accounts = []
        for sfx in NEW_ACCOUNT_SLOTS:
            new_user = row.get(f"new_username{sfx}", "").strip()
            if not new_user:
                continue
            npw = row.get(f"new_password{sfx}", "")
            if npw == "":
                if new_prompt is None:
                    pass   # left blank: asked for only when accounts are actually created
                elif new_user not in new_prompted:
                    npw = new_prompt(new_user)
                    prob = password_problem(npw, new_user)
                    if prob:
                        raise InventoryError([f"New account '{new_user}': {prob}"])
                    new_prompted[new_user] = npw
                npw = new_prompted.get(new_user, "")
            role, ptz = parse_role(row.get(f"new_role{sfx}", "") or "viewer")
            new_accounts.append(NewAccount(Credential(new_user, npw), role, ptz))
        cameras.append(Camera(
            host=host, port=port, credential=Credential(user, pw),
            name=row.get("name", ""), customer=row.get("customer", "") or row.get("site", ""),   # old "site" column still read
            protocol=(row.get("protocol") or "https").strip().lower(),
            profile=row.get("profile", ""), ports=ports, notes=row.get("notes", ""), row=i,
            hostname=row.get("hostname", "").strip(), dns=split_list(row.get("dns", "")),
            ntp=row.get("ntp", "").strip(), timezone=row.get("timezone", "").strip(),
            new_accounts=new_accounts,
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


COLUMN_HELP = {
    "ip": ("Required", "Camera IP address or host name, optionally with :port (e.g. 10.0.0.21 or 10.0.0.21:8443)."),
    "username": ("Required", "Administrator account the tool logs in with (e.g. root)."),
    "password": ("Optional", "Leave blank to be asked when the program starts (recommended: the file then holds no "
                             "passwords)."),
    "name": ("Optional", "Friendly camera name shown in the report."),
    "customer": ("Optional", "Customer the camera belongs to. Shown in the report; pick one customer in the program."),
    "protocol": ("Optional", "https (default) or http."),
    "profile": ("Optional", "Hardening profile for this camera only. Blank = the one chosen in the program."),
    "ports": ("Optional", "Reserved for a later version (unused network ports)."),
    "notes": ("Optional", "Free text, shown in the report."),
    "hostname": ("Optional", "Host name to give the camera: letters, digits and '-' only, e.g. gate-cam-1."),
    "dns": ("Optional", "One or two DNS server IP addresses, separated by ';' (e.g. 10.0.0.2;10.0.0.3)."),
    "ntp": ("Optional", "One time server: IP address or host name (e.g. 10.0.0.2 or ntp.example.local)."),
    "timezone": ("Optional", "Pick from the list (e.g. Europe/London)."),
    "new_username": ("Optional", "Account to CREATE on this camera (Create accounts...). Letters and digits only."),
    "new_password": ("Optional", "Password for that account (8+ characters). Blank = asked when the account is "
                                 "created."),
    "new_role": ("Optional", "Privilege level of the new account: pick from the list."),
    "new_username2": ("Optional", "A second account to create on this camera."),
    "new_password2": ("Optional", "Password for the second account (8+ characters). Blank = asked."),
    "new_role2": ("Optional", "Privilege level of the second account: pick from the list."),
}
ROLE_CHOICES = ["viewer", "operator", "admin", "viewer+ptz", "operator+ptz", "admin+ptz"]


def write_templates(out_dir: str | os.PathLike) -> list[Path]:
    """Blank camera lists: a CSV and an Excel file with notes on every column, required columns highlighted and
    drop-down lists for protocol, profile, time zone and account roles."""
    from openpyxl import Workbook
    from openpyxl.comments import Comment
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    from .catalog import BUILTIN_PROFILES
    from .timezones import ZONES

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    example = {"ip": "10.0.0.21", "username": "root", "name": "Gate cam 1", "customer": "Customer A",
               "protocol": "https", "notes": "Leave password blank to be prompted", "hostname": "gate-cam-1",
               "timezone": "Europe/London"}
    row = [example.get(c, "") for c in COLUMNS]
    csv_path = out / "inventory_template.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        w.writerow(row)

    wb = Workbook()
    ws = wb.active
    ws.title = "cameras"
    ws.append(COLUMNS)
    ws.append(row)
    req_fill, opt_fill = PatternFill("solid", fgColor="F4B183"), PatternFill("solid", fgColor="D9E1F2")
    for i, col in enumerate(COLUMNS, start=1):
        cell = ws.cell(row=1, column=i)
        kind, text = COLUMN_HELP.get(col, ("Optional", ""))
        cell.font = Font(bold=True)
        cell.fill = req_fill if kind == "Required" else opt_fill
        cell.alignment = Alignment(vertical="center")
        cell.comment = Comment(f"{kind}. {text}", "axharden", width=300, height=110)
        letter = cell.column_letter
        ws.column_dimensions[letter].width = max(12, min(30, len(col) + 6))
    ws.column_dimensions["A"].width = 18
    ws.freeze_panes = "A2"

    # drop-down source lists on a hidden sheet (Excel limits inline lists to 255 characters)
    lists = wb.create_sheet("lists")
    sources = {"protocol": ["https", "http"],
               "profile": [n for n in BUILTIN_PROFILES if n != "audit-only"],
               "timezone": list(ZONES),
               "role": ROLE_CHOICES}
    ranges = {}
    for j, (key, values) in enumerate(sources.items(), start=1):
        lists.cell(row=1, column=j, value=key).font = Font(bold=True)
        for k, val in enumerate(values, start=2):
            lists.cell(row=k, column=j, value=val)
        letter = lists.cell(row=1, column=j).column_letter
        ranges[key] = f"lists!${letter}$2:${letter}${len(values) + 1}"
    lists.sheet_state = "hidden"
    targets = {"protocol": "protocol", "profile": "profile", "timezone": "timezone", "new_role": "role",
               "new_role2": "role"}
    for col, key in targets.items():
        letter = ws.cell(row=1, column=COLUMNS.index(col) + 1).column_letter
        dv = DataValidation(type="list", formula1=f"={ranges[key]}", allow_blank=True, showDropDown=False)
        dv.error, dv.errorTitle = "Pick a value from the list.", "Not in the list"
        dv.prompt, dv.promptTitle = COLUMN_HELP[col][1], col
        dv.showErrorMessage = col != "profile"            # custom profile names may be typed in
        dv.showInputMessage = True
        ws.add_data_validation(dv)
        dv.add(f"{letter}2:{letter}1000")
    wb.active = 0
    xlsx_path = out / "inventory_template.xlsx"
    wb.save(xlsx_path)
    return [csv_path, xlsx_path]
