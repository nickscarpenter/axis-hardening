"""VAPIX HTTP client: auth negotiation, TLS policy, per-camera throttle and safe retry rules (CLAUDE.md §3, §7.5).

Rules enforced here:
- Never retry on 401/403 (would feed the camera's own brute-force protection). Raise AuthFailed.
- Retry only on timeouts and 5xx, at most `retries` times with back-off.
- At most one request in flight per camera (a lock), with a minimum delay between requests.
- Never send Basic credentials over plain HTTP.
- Never put credentials in URLs.
"""

from __future__ import annotations

import logging
import threading
import time
import warnings
from dataclasses import dataclass
from typing import Any

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from ..inventory import Camera

log = logging.getLogger(__name__)

# Protected endpoint used to discover the auth scheme. Reads one harmless parameter.
_PROBE_PATH = "/axis-cgi/param.cgi?action=list&group=root.Brand.Brand"
USER_AGENT = "axharden"


class CameraError(Exception):
    """Base class. `code` is the per-camera status recorded in results."""
    code = "ERROR"


class Unreachable(CameraError):
    code = "UNREACHABLE"


class AuthFailed(CameraError):
    code = "AUTH_FAILED"


class TLSFailed(CameraError):
    code = "TLS_ERROR"


class InsecureAuthRefused(CameraError):
    code = "INSECURE_AUTH_REFUSED"


class VapixHTTPError(CameraError):
    code = "HTTP_ERROR"

    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


@dataclass
class TLSPolicy:
    """verify: True (system/certifi trust), a CA-bundle path, or False (--insecure)."""
    verify: bool | str = True

    @property
    def insecure(self) -> bool:
        return self.verify is False


class CameraClient:
    def __init__(self, camera: Camera, tls: TLSPolicy | None = None, timeout: float = 10.0,
                 min_delay: float = 0.1, retries: int = 2, scheme: str | None = None):
        self.camera = camera
        self.tls = tls or TLSPolicy()
        self.timeout = timeout
        self.min_delay = min_delay
        self.retries = retries
        self.scheme = (scheme or camera.protocol or "https").lower()
        self.auth_scheme: str | None = None  # "digest" | "basic" | "none"
        self.request_count = 0
        self._lock = threading.Lock()
        self._last = 0.0
        self._session = requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT
        self._session.verify = self.tls.verify
        self._session.trust_env = False  # never route camera traffic through a proxy from the environment

    # ------------------------------------------------------------------ helpers
    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.camera.address}"

    def url(self, path: str) -> str:
        return self.base_url + (path if path.startswith("/") else "/" + path)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "CameraClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _throttle(self) -> None:
        wait = self._last + self.min_delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    # ------------------------------------------------------------------ core request
    def _send(self, method: str, url: str, auth: Any, **kwargs: Any) -> requests.Response:
        """One logical request with retry on timeout/5xx only. Caller holds the lock."""
        attempt = 0
        while True:
            self._throttle()
            try:
                with warnings.catch_warnings():
                    if self.tls.insecure:
                        warnings.simplefilter("ignore")  # we warn loudly at the CLI and in the report instead
                    resp = self._session.request(method, url, auth=auth, timeout=self.timeout,
                                                 allow_redirects=False, **kwargs)
                self.request_count += 1
            except requests.exceptions.SSLError as e:
                raise TLSFailed(f"TLS error: {_short(e)}") from None
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
                if attempt < self.retries:
                    attempt += 1
                    log.debug("%s: timeout, retry %d/%d", self.camera.host, attempt, self.retries)
                    time.sleep(0.5 * 2 ** attempt)
                    continue
                raise Unreachable(f"Timed out after {attempt + 1} attempt(s): {_short(e)}") from None
            except requests.exceptions.ConnectionError as e:
                raise Unreachable(f"Connection failed: {_short(e)}") from None
            finally:
                self._last = time.monotonic()

            if resp.status_code >= 500 and attempt < self.retries:
                attempt += 1
                log.debug("%s: HTTP %d, retry %d/%d", self.camera.host, resp.status_code, attempt, self.retries)
                time.sleep(0.5 * 2 ** attempt)
                continue
            return resp

    def negotiate(self) -> str:
        """Pick the auth scheme from the camera's WWW-Authenticate challenge. Sends no credentials."""
        with self._lock:
            resp = self._send("GET", self.url(_PROBE_PATH), auth=None)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if self.scheme == "http" and loc.lower().startswith("https://"):
                raise InsecureAuthRefused("Camera redirects HTTP to HTTPS (HTTPS-only is on). Use protocol https.")
            raise VapixHTTPError(f"Unexpected redirect to {loc!r}", resp.status_code)
        if resp.status_code == 200:
            self.auth_scheme = "none"
            log.warning("%s: parameter API answered without authentication", self.camera.host)
            return self.auth_scheme
        if resp.status_code != 401:
            raise VapixHTTPError(f"Unexpected HTTP {resp.status_code} from auth probe", resp.status_code)
        challenge = resp.headers.get("WWW-Authenticate", "").lower()
        if "digest" in challenge:
            self.auth_scheme = "digest"
        elif "basic" in challenge:
            if self.scheme != "https":
                raise InsecureAuthRefused("Camera only offers Basic auth over plain HTTP; refusing to send the password. "
                                          "Use protocol https.")
            self.auth_scheme = "basic"
        else:
            raise CameraError(f"Unsupported auth challenge: {challenge[:80]!r}")
        return self.auth_scheme

    def _auth(self) -> Any:
        if self.auth_scheme is None:
            self.negotiate()
        cred = self.camera.credential
        if self.auth_scheme == "digest":
            if not hasattr(self, "_digest"):
                self._digest = HTTPDigestAuth(cred.username, cred.password)
            return self._digest
        if self.auth_scheme == "basic":
            if self.scheme != "https":  # belt and braces
                raise InsecureAuthRefused("Refusing Basic auth over HTTP")
            return HTTPBasicAuth(cred.username, cred.password)
        return None

    def request(self, method: str, path: str, *, ok_statuses: tuple[int, ...] = (200,),
                **kwargs: Any) -> requests.Response:
        auth = self._auth()
        with self._lock:
            resp = self._send(method, self.url(path), auth=auth, **kwargs)
        if resp.status_code in (401, 403):
            # Never retry: mark the camera and move on (§7.5).
            raise AuthFailed(f"HTTP {resp.status_code}: credentials rejected or account lacks rights")
        if resp.status_code not in ok_statuses:
            raise VapixHTTPError(f"HTTP {resp.status_code} for {path.split('?')[0]}", resp.status_code)
        return resp

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path, **kwargs)

    def post_json(self, path: str, payload: dict, **kwargs: Any) -> requests.Response:
        return self.request("POST", path, json=payload, **kwargs)

    # ------------------------------------------------------------------ unauthenticated helpers
    def raw_get(self, url: str) -> requests.Response:
        """Unauthenticated GET to an arbitrary URL on this camera (e.g. the HTTP:80 redirect check)."""
        with self._lock:
            return self._send("GET", url, auth=None)


def _short(e: Exception) -> str:
    text = str(e)
    # urllib3 messages are long and nested; keep the useful tail.
    for marker in ("Caused by ", "] "):
        if marker in text:
            text = text.split(marker)[-1]
    return text.strip("()' ")[:200]
