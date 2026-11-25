"""Time zones for the inventory `timezone` column.

AXIS OS 10.x stores the zone as a POSIX TZ rule in root.Time.POSIXTimeZone (e.g. GMT0BST,M3.5.0/1,M10.5.0 on the
M4216-LV 10.12.252). The camera list uses readable IANA names from this table; a raw POSIX rule is also accepted.
If a camera also has root.Time.TimeZone (IANA name, newer firmware), that is written too.
"""

from __future__ import annotations

import re

ZONES: dict[str, str] = {
    "UTC": "UTC0",
    "Europe/London": "GMT0BST,M3.5.0/1,M10.5.0",
    "Europe/Dublin": "GMT0IST,M3.5.0/1,M10.5.0",
    "Europe/Lisbon": "WET0WEST,M3.5.0/1,M10.5.0",
    "Europe/Amsterdam": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Berlin": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Brussels": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Copenhagen": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Madrid": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Oslo": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Paris": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Prague": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Rome": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Stockholm": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Vienna": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Warsaw": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Zurich": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Athens": "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Helsinki": "EET-2EEST,M3.5.0/3,M10.5.0/4",
    "Europe/Istanbul": "<+03>-3",
    "Europe/Moscow": "MSK-3",
    "Asia/Dubai": "<+04>-4",
    "Asia/Kolkata": "IST-5:30",
    "Asia/Singapore": "<+08>-8",
    "Asia/Hong_Kong": "HKT-8",
    "Asia/Shanghai": "CST-8",
    "Asia/Tokyo": "JST-9",
    "Australia/Perth": "AWST-8",
    "Australia/Brisbane": "AEST-10",
    "Australia/Sydney": "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "Pacific/Auckland": "NZST-12NZDT,M9.5.0,M4.1.0/3",
    "Africa/Johannesburg": "SAST-2",
    "America/Sao_Paulo": "<-03>3",
    "America/New_York": "EST5EDT,M3.2.0,M11.1.0",
    "America/Toronto": "EST5EDT,M3.2.0,M11.1.0",
    "America/Chicago": "CST6CDT,M3.2.0,M11.1.0",
    "America/Denver": "MST7MDT,M3.2.0,M11.1.0",
    "America/Phoenix": "MST7",
    "America/Los_Angeles": "PST8PDT,M3.2.0,M11.1.0",
}
_POSIX_RE = re.compile(r"^(<[+-]?\w+>|[A-Za-z]{3,})[+-]?\d{1,2}(:\d{2})?((<[+-]?\w+>|[A-Za-z]{3,})([+-]?\d{1,2}(:\d{2})?)?"
                       r"(,M\d{1,2}\.\d\.\d(/\d{1,2})?,M\d{1,2}\.\d\.\d(/\d{1,2})?)?)?$")


def resolve(value: str) -> tuple[str | None, str]:
    """'europe/london' -> ('Europe/London', 'GMT0BST,...'); a raw POSIX rule -> (None, rule). Raises ValueError."""
    v = (value or "").strip()
    for name, posix in ZONES.items():
        if name.lower() == v.lower():
            return name, posix
    if _POSIX_RE.match(v):
        return None, v
    raise ValueError(f"unknown time zone {value!r}: pick one from the list (e.g. Europe/London) or give a POSIX "
                     "rule such as GMT0BST,M3.5.0/1,M10.5.0")


def name_for(posix: str | None) -> str:
    """Readable name for a camera's POSIX rule (first matching zone), else the rule itself."""
    if not posix:
        return "(not set)"
    for name, rule in ZONES.items():
        if rule.lower() == posix.strip().lower():
            return name
    return posix
