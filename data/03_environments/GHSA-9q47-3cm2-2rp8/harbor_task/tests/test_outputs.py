"""Hidden regression tests: client-supplied forwarding headers must not decide
the client identity used for API throttling and authentication logging.

All requests go through pyLoad's real web application (built by Core) and its
real routes (/api/<func> and /login)."""
import logging

import pytest

from pyload import APPID
from pyload.core import Core

API_PATH = "/api/get_server_version"
API_LIMIT = 100  # documented per-client budget of the HTTP API (calls / minute)
BAD_KEY = "pl_" + "0" * 40


# --------------------------------------------------------------- fixtures

class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        try:
            self.messages.append(record.getMessage())
        except Exception:
            self.messages.append(str(record.msg))

    @property
    def text(self):
        return "\n".join(self.messages)


@pytest.fixture(scope="module")
def pyload_core(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("pyload_hidden_xff")
    core = Core(
        userdir=str(data_dir),
        tempdir=str(data_dir / "tmp"),
        storagedir=None,
        debug=True,
        reset=None,
        dry=False,
        api_spec=False,
    )
    yield core


@pytest.fixture(scope="module")
def app(pyload_core):
    app = pyload_core.webserver.app
    app.config.update({"TESTING": True, "WTF_CSRF_ENABLED": False})
    yield app


@pytest.fixture(scope="module")
def api_key(pyload_core):
    return pyload_core.api.generate_apikey("pyload", "pyload")["data"]["key"]


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def captured_logs(app):
    handler = _ListHandler()
    targets = []
    for lg in (getattr(app.logger, "logger", app.logger), logging.getLogger(APPID), logging.getLogger()):
        if all(lg is not t for t in targets):
            targets.append(lg)
    for lg in targets:
        lg.addHandler(handler)
    yield handler
    for lg in targets:
        lg.removeHandler(handler)


# --------------------------------------------------------------- helpers

def _api_call(client, peer, key, xff=None):
    headers = {"X-API-Key": key}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    return client.get(API_PATH, headers=headers, environ_base={"REMOTE_ADDR": peer})


def _use_budget(client, peer, key, xff_for=None):
    """Spend the full per-client budget from `peer`; none of these may be throttled."""
    for i in range(API_LIMIT):
        xff = xff_for(i) if xff_for else None
        resp = _api_call(client, peer, key, xff)
        assert resp.status_code != 429, f"throttled too early at call {i + 1}"


def _sign_in(client, peer, password, xff=None):
    headers = {}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    return client.post(
        "/login",
        data={"username": "pyload", "password": password},
        headers=headers,
        environ_base={"REMOTE_ADDR": peer},
    )


# --------------------------------------------------------------- security

def test_security_rotating_forwarded_header_does_not_bypass_api_throttle(client, api_key):
    """One peer rotating X-Forwarded-For values is still throttled after its budget."""
    peer = "192.0.2.11"
    _use_budget(client, peer, api_key, xff_for=lambda i: f"10.0.{i // 250}.{i % 250 + 1}")
    resp = _api_call(client, peer, api_key, xff="10.9.9.9")
    assert resp.status_code == 429


def test_security_adding_header_after_exhaustion_does_not_reset_budget(client, api_key):
    """A peer that used up its budget cannot get a fresh one by adding a forged header."""
    peer = "192.0.2.12"
    _use_budget(client, peer, api_key)
    assert _api_call(client, peer, api_key).status_code == 429
    assert _api_call(client, peer, api_key, xff="198.51.100.1").status_code == 429


def test_security_rotating_forwarded_chain_does_not_bypass_api_throttle(client, api_key):
    """Changing a multi-hop forwarded chain must not create new throttling budgets."""
    peer = "192.0.2.13"
    _use_budget(client, peer, api_key, xff_for=lambda i: f"10.1.0.{i + 1}, 172.16.0.{i + 1}")
    resp = _api_call(client, peer, api_key, xff="10.1.0.250, 172.16.0.250")
    assert resp.status_code == 429


def test_security_forged_header_cannot_exhaust_another_hosts_budget(client, api_key):
    """A client naming a victim's address in the header must not use up the victim's budget."""
    attacker, victim = "203.0.113.14", "192.0.2.14"
    for _ in range(API_LIMIT + 1):
        _api_call(client, attacker, api_key, xff=victim)
    assert _api_call(client, victim, api_key).status_code != 429


def test_security_rejected_api_key_logged_with_real_peer(client, captured_logs):
    """A rejected API key is logged with the connecting peer, not the forged header value."""
    peer, spoof = "192.0.2.15", "198.51.100.15"
    resp = client.get(
        API_PATH,
        headers={"X-API-Key": BAD_KEY, "X-Forwarded-For": spoof},
        environ_base={"REMOTE_ADDR": peer},
    )
    assert resp.status_code >= 400
    assert spoof not in captured_logs.text
    assert peer in captured_logs.text


def test_security_rejected_unauthenticated_api_call_logged_with_real_peer(client, captured_logs):
    """An API call with no valid credentials is logged with the connecting peer, not a forged chain."""
    peer, spoof = "192.0.2.16", "198.51.100.16"
    resp = client.get(
        API_PATH,
        headers={"X-Forwarded-For": f"{spoof}, 10.0.0.1"},
        environ_base={"REMOTE_ADDR": peer},
    )
    assert resp.status_code >= 400
    assert spoof not in captured_logs.text
    assert peer in captured_logs.text


def test_security_failed_web_sign_in_logged_with_real_peer(client, captured_logs):
    """A failed sign-in on the web form is logged with the connecting peer, not the forged header."""
    peer, spoof = "192.0.2.17", "198.51.100.17"
    resp = _sign_in(client, peer, "definitely-wrong-password", xff=spoof)
    assert resp.status_code < 500
    assert spoof not in captured_logs.text
    assert peer in captured_logs.text


# --------------------------------------------------------------- functional

def test_functional_api_throttle_still_enforced_for_plain_requests(client, api_key):
    """Plain API calls are allowed up to the budget and then throttled."""
    peer = "192.0.2.31"
    _use_budget(client, peer, api_key)
    assert _api_call(client, peer, api_key).status_code == 429


def test_functional_distinct_hosts_have_independent_budgets(client, api_key):
    """Different real peers are throttled independently."""
    first, second = "192.0.2.32", "192.0.2.33"
    _use_budget(client, first, api_key)
    assert _api_call(client, first, api_key).status_code == 429
    assert _api_call(client, second, api_key).status_code != 429


def test_functional_valid_api_key_with_forwarding_header_is_served(client, api_key):
    """A valid API call carrying a proxy-style header is served just like one without it."""
    peer = "192.0.2.34"
    plain = _api_call(client, peer, api_key)
    proxied = _api_call(client, peer, api_key, xff="198.51.100.34")
    assert plain.status_code not in (400, 401, 403, 429)
    assert proxied.status_code == plain.status_code
    assert proxied.get_data() == plain.get_data()


def test_functional_valid_web_sign_in_works_and_is_logged(client, captured_logs):
    """Correct credentials on the web form still sign in, and the entry names the peer."""
    peer = "192.0.2.35"
    resp = _sign_in(client, peer, "pyload")
    assert resp.status_code in (301, 302, 303, 307, 308)
    assert peer in captured_logs.text


def test_functional_rejected_api_key_without_headers_logged_with_peer(client, captured_logs):
    """A bad API key without proxy headers is rejected and logged with the peer address."""
    peer = "192.0.2.36"
    resp = client.get(API_PATH, headers={"X-API-Key": BAD_KEY}, environ_base={"REMOTE_ADDR": peer})
    assert resp.status_code == 401
    assert peer in captured_logs.text


def test_functional_unauthenticated_api_call_rejected_cleanly(client):
    """An API call with no credentials gets a clean 401."""
    resp = client.get(API_PATH, environ_base={"REMOTE_ADDR": "192.0.2.37"})
    assert resp.status_code == 401
