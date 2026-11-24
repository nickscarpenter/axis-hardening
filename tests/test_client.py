"""VAPIX client behaviour, mocked with `responses`."""

import pytest
import requests
import responses

from axharden.inventory import Camera, Credential
from axharden.vapix.client import (AuthFailed, CameraClient, InsecureAuthRefused, TLSPolicy, Unreachable,
                                   VapixHTTPError)
from axharden.vapix.params import list_all

PROBE = "/axis-cgi/param.cgi?action=list&group=root.Brand.Brand"
DIGEST = 'Digest realm="AXIS_X", nonce="abc", algorithm=MD5, qop="auth"'


def cam(protocol="https"):
    return Camera(host="192.0.2.10", port=None, credential=Credential("root", "Not-Logged-123"), protocol=protocol)


def client(protocol="https", **kw):
    return CameraClient(cam(protocol), TLSPolicy(), min_delay=0, **kw)


@responses.activate
def test_digest_negotiation_and_param_list():
    base = "https://192.0.2.10"
    responses.get(base + PROBE, status=401, headers={"WWW-Authenticate": DIGEST})
    responses.get(base + "/axis-cgi/param.cgi?action=list", status=401, headers={"WWW-Authenticate": DIGEST})
    responses.get(base + "/axis-cgi/param.cgi?action=list", body="root.Network.SSH.Enabled=no\n")
    c = client()
    assert c.negotiate() == "digest"
    tree = list_all(c)
    assert tree.get("root.network.ssh.enabled") == "no"
    sent = responses.calls[-1].request.headers["Authorization"]
    assert sent.startswith("Digest ") and "Not-Logged-123" not in sent
    assert "Not-Logged-123" not in responses.calls[-1].request.url


@responses.activate
def test_basic_allowed_over_https_only():
    responses.get("https://192.0.2.10" + PROBE, status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})
    assert client().negotiate() == "basic"


@responses.activate
def test_basic_over_http_refused():
    responses.get("http://192.0.2.10" + PROBE, status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})
    with pytest.raises(InsecureAuthRefused):
        client("http").negotiate()
    assert len(responses.calls) == 1  # no credentials were sent


@responses.activate
def test_http_redirect_to_https_reported():
    responses.get("http://192.0.2.10" + PROBE, status=302, headers={"Location": "https://192.0.2.10/"})
    with pytest.raises(InsecureAuthRefused, match="HTTPS-only"):
        client("http").negotiate()


@responses.activate
def test_401_is_never_retried():
    base = "https://192.0.2.10"
    responses.get(base + PROBE, status=401, headers={"WWW-Authenticate": DIGEST})
    responses.get(base + "/axis-cgi/param.cgi?action=list", status=401, headers={"WWW-Authenticate": DIGEST})
    c = client()
    c.negotiate()
    with pytest.raises(AuthFailed):
        c.get("/axis-cgi/param.cgi?action=list")
    # probe + the digest challenge/response pair from requests itself; no extra retries by us
    assert len(responses.calls) <= 3


@responses.activate
def test_403_raises_auth_failed():
    base = "https://192.0.2.10"
    responses.get(base + PROBE, status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})
    responses.get(base + "/x", status=403)
    c = client()
    with pytest.raises(AuthFailed):
        c.get("/x")
    assert len(responses.calls) == 2


@responses.activate
def test_timeout_retried_then_unreachable(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    url = "https://192.0.2.10" + PROBE
    responses.get(url, body=requests.exceptions.ConnectTimeout("timed out"))
    with pytest.raises(Unreachable):
        client(retries=2).negotiate()
    assert len(responses.calls) == 3


@responses.activate
def test_5xx_retried_then_succeeds(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    url = "https://192.0.2.10" + PROBE
    responses.get(url, status=503)
    responses.get(url, status=401, headers={"WWW-Authenticate": DIGEST})
    assert client().negotiate() == "digest"
    assert len(responses.calls) == 2


@responses.activate
def test_connection_refused_not_retried():
    responses.get("https://192.0.2.10" + PROBE, body=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(Unreachable):
        client().negotiate()
    assert len(responses.calls) == 1


@responses.activate
def test_unexpected_status():
    responses.get("https://192.0.2.10" + PROBE, status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})
    responses.get("https://192.0.2.10/y", status=404)
    with pytest.raises(VapixHTTPError):
        client().get("/y")
