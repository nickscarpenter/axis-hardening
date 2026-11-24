"""Logging with a redacting filter: passwords, Authorization headers and URL credentials never reach a log."""

from __future__ import annotations

import logging
import re
import threading

_PATTERNS = [
    # Authorization / Proxy-Authorization headers
    (re.compile(r"(?i)((?:proxy-)?authorization['\"]?\s*[:=]\s*['\"]?)([^'\"\r\n,}]+)"), r"\1***"),
    # Digest header fields that are derived from the password
    (re.compile(r'(?i)(response=")[^"]*(")'), r"\1***\2"),
    # user:pass@host in URLs
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1***:***@"),
    # password=... in query strings / key=value text
    (re.compile(r"(?i)(\b(?:pwd|pass|password|passwd)\s*[=:]\s*)([^&\s,;]+)"), r"\1***"),
]

_secrets: set[str] = set()
_secrets_lock = threading.Lock()


def register_secret(value: str) -> None:
    """Register a literal secret (e.g. a password loaded from the inventory) so any log line containing it is masked."""
    if value and len(value) >= 3:
        with _secrets_lock:
            _secrets.add(value)


def clear_secrets() -> None:
    with _secrets_lock:
        _secrets.clear()


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    with _secrets_lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, "***")
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record
            return True
        record.msg = redact(message)
        record.args = None
        if record.exc_info:
            # Pre-render the traceback so it is redacted too.
            formatter = logging.Formatter()
            record.exc_text = redact(formatter.formatException(record.exc_info))
            record.exc_info = None
        return True


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
        h.addFilter(RedactingFilter())
        root.addHandler(h)
    # urllib3 debug output can include headers; keep it quiet.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
