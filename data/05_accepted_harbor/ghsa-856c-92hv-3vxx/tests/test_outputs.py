"""Hidden regression tests: operator control over redirect following.

All outbound traffic is intercepted at the transport adapter level, so the
real redirect machinery of the client library runs, but nothing ever leaves
the process.
"""

import io
from urllib.parse import urlparse

import pytest
import requests
import requests.adapters
from requests.structures import CaseInsensitiveDict

from apprise import Apprise, AppriseAttachment, AppriseConfig, URLBase

ORIGIN = "origin.example"
COLLECTOR = "collector.invalid"
SENTINEL = "hidden-sentinel-7f3a"
OFFSITE = f"http://{COLLECTOR}/catch"


class FakeWeb:
    """Tiny in-process stand-in for remote web servers."""

    def __init__(self):
        self.calls = []
        self.routes = {}

    def route(self, host, path, status=200, headers=None, body=b""):
        hdrs = {"Content-Length": str(len(body))}
        hdrs.update(headers or {})
        self.routes[(host, path)] = (status, hdrs, body)

    def hits(self, host, path=None):
        return [
            c
            for c in self.calls
            if c["host"] == host and (path is None or c["path"] == path)
        ]

    def handle(self, request):
        parsed = urlparse(request.url)
        host = (parsed.hostname or "").lower()
        self.calls.append(
            {
                "host": host,
                "path": parsed.path,
                "method": request.method,
                "headers": CaseInsensitiveDict(request.headers),
            }
        )
        status, headers, body = self.routes.get(
            (host, parsed.path), (404, {"Content-Length": "0"}, b"")
        )
        resp = requests.Response()
        resp.status_code = status
        resp.headers = CaseInsensitiveDict(headers)
        resp._content = body
        resp._content_consumed = True
        resp.raw = io.BytesIO(body)
        resp.encoding = "utf-8"
        resp.reason = "OK" if status < 300 else "Redirect"
        resp.url = request.url
        resp.request = request
        return resp


@pytest.fixture
def web(monkeypatch):
    fake = FakeWeb()

    def fake_send(adapter_self, request, *args, **kwargs):
        return fake.handle(request)

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)
    # never sleep between requests in these tests
    monkeypatch.setattr(URLBase, "throttle", lambda self, *a, **k: None)
    return fake


def _offsite_redirect(web, path, status=307, body=b""):
    web.route(ORIGIN, path, status, {"Location": OFFSITE}, body)
    web.route(
        COLLECTOR,
        "/catch",
        200,
        {"Content-Type": "text/plain"},
        b"json://localhost\n",
    )


def _assert_origin_only(web):
    assert web.hits(ORIGIN), "configured endpoint was never contacted"
    assert not web.hits(COLLECTOR), "request was replayed to redirect target"


def _origin_got_sentinel(web, path):
    calls = web.hits(ORIGIN, path)
    return any(c["headers"].get("X-Api-Key") == SENTINEL for c in calls)


# --------------------------------------------------------------------------
# Security tests
# --------------------------------------------------------------------------


def test_security_json_redirect_disabled(web):
    """JSON webhook with redirect=no must never contact the redirect target."""
    _offsite_redirect(web, "/hook")
    a = Apprise()
    assert a.add(f"json://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}")
    a.notify(body="hello", title="t")
    _assert_origin_only(web)
    assert _origin_got_sentinel(web, "/hook")


def test_security_form_redirect_disabled(web):
    """Form webhook with redirect=no must never contact the redirect target."""
    _offsite_redirect(web, "/hook")
    a = Apprise()
    assert a.add(f"form://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}")
    a.notify(body="hello", title="t")
    _assert_origin_only(web)


def test_security_xml_redirect_disabled(web):
    """XML webhook with redirect=no must never contact the redirect target."""
    _offsite_redirect(web, "/hook")
    a = Apprise()
    assert a.add(f"xml://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}")
    a.notify(body="hello", title="t")
    _assert_origin_only(web)


def test_security_apprise_api_redirect_disabled(web):
    """Apprise API target with redirect=no must not replay to another host."""
    _offsite_redirect(web, "/notify/tok123")
    a = Apprise()
    assert a.add(
        f"apprise://{ORIGIN}/tok123?redirect=no&+X-Api-Key={SENTINEL}"
    )
    a.notify(body="hello", title="t")
    _assert_origin_only(web)


def test_security_remote_attachment_redirect_disabled(web):
    """A remote attachment with redirect=no must not follow nor use the stub."""
    _offsite_redirect(web, "/report.txt", status=302, body=b"STUB")
    att = AppriseAttachment(
        f"http://{ORIGIN}/report.txt?redirect=no&+X-Api-Key={SENTINEL}"
    )
    assert len(att) == 1
    available = att[0].exists()
    _assert_origin_only(web)
    assert not available


def test_security_remote_config_redirect_disabled(web):
    """A remote config source with redirect=no must not follow nor load stub."""
    _offsite_redirect(
        web,
        "/cfg",
        status=308,
        body=b"json://stub.example\n",
    )
    web.routes[(ORIGIN, "/cfg")][1]["Content-Type"] = "text/plain"
    cfg = AppriseConfig(
        f"http://{ORIGIN}/cfg?redirect=no&+X-Api-Key={SENTINEL}"
    )
    servers = cfg.servers()
    _assert_origin_only(web)
    assert len(servers) == 0


def test_security_option_survives_target_roundtrip(web):
    """A target rebuilt from its own exported form must keep redirect=no."""
    _offsite_redirect(web, "/hook")
    first = Apprise.instantiate(
        f"json://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}"
    )
    assert first is not None
    second = Apprise.instantiate(first.url())
    assert second is not None
    second.notify(body="hello", title="t")
    _assert_origin_only(web)


def test_security_yaml_entry_option_honoured(web):
    """redirect: no given as a YAML entry option must be honoured."""
    _offsite_redirect(web, "/hook")
    yaml_text = (
        "urls:\n"
        f"  - json://{ORIGIN}/hook?+X-Api-Key={SENTINEL}:\n"
        "      - redirect: no\n"
    )
    cfg = AppriseConfig()
    assert cfg.add_config(yaml_text, format="yaml")
    a = Apprise()
    assert a.add(cfg)
    a.notify(body="hello", title="t")
    _assert_origin_only(web)


# --------------------------------------------------------------------------
# Functional tests
# --------------------------------------------------------------------------


def test_functional_default_follows_same_host_redirect(web):
    """By default a moved endpoint (same host redirect) still works."""
    web.route(ORIGIN, "/hook", 307, {"Location": f"http://{ORIGIN}/moved"})
    web.route(ORIGIN, "/moved", 200, {}, b"{}")
    a = Apprise()
    assert a.add(f"json://{ORIGIN}/hook?+X-Api-Key={SENTINEL}")
    assert a.notify(body="hello", title="t")
    assert _origin_got_sentinel(web, "/moved")


def test_functional_explicit_redirect_yes_follows(web):
    """redirect=yes keeps following redirects for a form webhook."""
    web.route(ORIGIN, "/hook", 307, {"Location": f"http://{ORIGIN}/moved"})
    web.route(ORIGIN, "/moved", 200, {}, b"ok")
    a = Apprise()
    assert a.add(f"form://{ORIGIN}/hook?redirect=yes&+X-Api-Key={SENTINEL}")
    assert a.notify(body="hello", title="t")
    assert web.hits(ORIGIN, "/moved")


def test_functional_redirect_no_direct_delivery_works(web):
    """redirect=no still delivers normally (with custom headers) on 200."""
    web.route(ORIGIN, "/hook", 200, {}, b"{}")
    a = Apprise()
    assert a.add(f"json://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}")
    assert a.notify(body="hello", title="t")
    assert _origin_got_sentinel(web, "/hook")


def test_functional_attachment_default_follows_redirect(web):
    """A remote attachment behind a same-host redirect is still retrieved."""
    web.route(
        ORIGIN, "/report.txt", 302, {"Location": f"http://{ORIGIN}/m/r.txt"}
    )
    web.route(
        ORIGIN,
        "/m/r.txt",
        200,
        {"Content-Type": "text/plain"},
        b"attachment-body",
    )
    att = AppriseAttachment(f"http://{ORIGIN}/report.txt")
    assert len(att) == 1
    path = att[0].path
    assert path
    with open(path, "rb") as fd:
        assert fd.read() == b"attachment-body"


def test_functional_attachment_redirect_no_direct_ok(web):
    """A remote attachment with redirect=no is retrieved when served directly."""
    web.route(
        ORIGIN,
        "/report.txt",
        200,
        {"Content-Type": "text/plain"},
        b"direct-body",
    )
    att = AppriseAttachment(f"http://{ORIGIN}/report.txt?redirect=no")
    assert len(att) == 1
    path = att[0].path
    assert path
    with open(path, "rb") as fd:
        assert fd.read() == b"direct-body"


def test_functional_config_default_follows_redirect(web):
    """A remote config source behind a same-host redirect still loads."""
    web.route(ORIGIN, "/cfg", 308, {"Location": f"http://{ORIGIN}/m/cfg"})
    web.route(
        ORIGIN,
        "/m/cfg",
        200,
        {"Content-Type": "text/plain"},
        b"json://localhost\n",
    )
    cfg = AppriseConfig(f"http://{ORIGIN}/cfg")
    assert len(cfg.servers()) == 1


def test_functional_config_redirect_no_direct_ok(web):
    """A remote config source with redirect=no loads when served directly."""
    web.route(
        ORIGIN,
        "/cfg",
        200,
        {"Content-Type": "text/plain"},
        b"json://localhost\n",
    )
    cfg = AppriseConfig(f"http://{ORIGIN}/cfg?redirect=no")
    assert len(cfg.servers()) == 1


def test_functional_roundtrip_target_still_delivers(web):
    """A target rebuilt from its exported form still delivers its headers."""
    web.route(ORIGIN, "/hook", 200, {}, b"{}")
    first = Apprise.instantiate(
        f"json://{ORIGIN}/hook?redirect=no&+X-Api-Key={SENTINEL}"
    )
    assert first is not None
    second = Apprise.instantiate(first.url())
    assert second is not None
    assert second.notify(body="hello", title="t")
    assert _origin_got_sentinel(web, "/hook")
