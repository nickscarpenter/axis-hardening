"""Camera user accounts via VAPIX pwdgrp.cgi.

Reads with `action=get`; creates/removes with `action=add` / `action=remove`. Writes are sent as a POST
form body, never in the URL, so the new password does not end up in camera or proxy access logs (§9).
"""

from __future__ import annotations

import re
from typing import Any

PWDGRP = "/axis-cgi/pwdgrp.cgi"
ROLES = ("viewer", "operator", "admin")
SGRP = {"viewer": "viewer", "operator": "viewer:operator", "admin": "viewer:operator:admin"}
ROLE_TEXT = {"viewer": "Viewer", "operator": "Operator", "admin": "Administrator"}
ROLE_HELP = {
    "viewer": "Viewer: watch live video only",
    "operator": "Operator: view video and change most settings (no accounts or security settings)",
    "admin": "Administrator: full control of the camera",
}
_ROLE_ALIASES = {"viewer": "viewer", "view": "viewer", "operator": "operator", "op": "operator",
                 "admin": "admin", "administrator": "admin"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")   # AXIS OS 10.12 rejects "_" (tested on M4216-LV)
RESERVED = {"root", "anonymous", "admin", "operator", "viewer", "ptz", "users", "digusers"}
MIN_PASSWORD = 8      # guide p.16
MAX_PASSWORD = 64


class AccountError(Exception):
    pass


def parse_role(text: str) -> tuple[str, bool]:
    """'operator', 'Viewer+PTZ', 'administrator ptz' -> (role, ptz). Raises ValueError."""
    t = (text or "").strip().lower().replace("+", " ").replace(",", " ")
    words = t.split()
    ptz = "ptz" in words
    words = [w for w in words if w != "ptz"]
    if not words:
        raise ValueError("role is empty (use viewer, operator or admin)")
    if len(words) > 1 or words[0] not in _ROLE_ALIASES:
        raise ValueError(f"unknown role {text!r} (use viewer, operator or admin, optionally with +ptz)")
    return _ROLE_ALIASES[words[0]], ptz


def role_label(role: str, ptz: bool = False) -> str:
    return ROLE_TEXT.get(role, role) + (" + PTZ" if ptz else "")


def username_problem(name: str, login_user: str = "") -> str | None:
    if not USERNAME_RE.match(name or ""):
        return "username must be 1-32 letters or numbers only (cameras reject spaces, '_' and other symbols)"
    if name.lower() in RESERVED:
        return f"'{name}' is a reserved name on AXIS cameras"
    if login_user and name.lower() == login_user.lower():
        return "the new account must differ from the account the tool logs in with"
    return None


def password_problem(pw: str, username: str = "") -> str | None:
    if len(pw) < MIN_PASSWORD:
        return f"password must be at least {MIN_PASSWORD} characters (guide p.16)"
    if len(pw) > MAX_PASSWORD:
        return f"password must be at most {MAX_PASSWORD} characters"
    if any(not (0x21 <= ord(ch) <= 0x7E) for ch in pw):
        return "password may only contain printable ASCII characters without spaces"
    if username and pw.lower() == username.lower():
        return "password must not be the same as the username"
    return None


def parse_pwdgrp(text: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([\w-]+)="(.*)"\s*$', line)
        if m:
            groups[m.group(1)] = [x for x in m.group(2).split(",") if x]
    return groups


def roles_from_groups(groups: dict[str, list[str]]) -> dict[str, dict]:
    """{username: {"role": admin|operator|viewer|unknown, "ptz": bool}} for real (digest) accounts."""
    accounts = groups.get("digusers") or groups.get("users") or []
    out = {}
    for acct in accounts:
        if acct in groups.get("admin", []):
            role = "admin"
        elif acct in groups.get("operator", []):
            role = "operator"
        elif acct in groups.get("viewer", []):
            role = "viewer"
        else:
            role = "unknown"
        out[acct] = {"role": role, "ptz": acct in groups.get("ptz", [])}
    return out


def read_accounts(client: Any) -> dict[str, dict]:
    resp = client.get(f"{PWDGRP}?action=get")
    return roles_from_groups(parse_pwdgrp(resp.text))


def _check_reply(text: str, what: str) -> None:
    low = (text or "").lower()
    if "error" in low:
        raise AccountError(f"Camera refused to {what}: {text.strip()[:200]}")


def add_account(client: Any, username: str, password: str, role: str, ptz: bool = False) -> None:
    sgrp = SGRP[role] + (":ptz" if ptz else "")
    resp = client.request("POST", PWDGRP, data={"action": "add", "user": username, "pwd": password,
                                                "grp": "users", "sgrp": sgrp, "comment": "axharden"})
    _check_reply(resp.text, f"create account '{username}'")


def remove_account(client: Any, username: str) -> None:
    resp = client.request("POST", PWDGRP, data={"action": "remove", "user": username})
    _check_reply(resp.text, f"remove account '{username}'")
