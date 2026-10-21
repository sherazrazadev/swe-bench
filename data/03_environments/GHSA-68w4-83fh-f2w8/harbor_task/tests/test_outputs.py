import os

import pytest

from pyload.core import Core
from pyload.core.api import Perms, Role

ALL_PERMS = int(
    Perms.ADD | Perms.DELETE | Perms.STATUS | Perms.LIST | Perms.MODIFY
    | Perms.DOWNLOAD | Perms.SETTINGS | Perms.ACCOUNTS | Perms.LOGS
)

USERDATA_FUNCS = ["getUserData", "get_userdata"]

TARGET_USER = "sec_target"
TARGET_PW = "target_secret_pw"
WRONG_PW = "definitely_wrong_pw"
ATTACKER = "sec_attacker"
ATTACKER_PW = "attacker_secret_pw"
ATTACKER_ALL = "sec_attacker_all"
ATTACKER_ALL_PW = "attacker_all_secret_pw"


@pytest.fixture(scope="module")
def pyload_core(tmp_path_factory):
    # Build the real Core once (mirrors the project's own integration conftest).
    data_dir = str(tmp_path_factory.mktemp("pyload_data"))
    core = Core(
        userdir=data_dir,
        tempdir=os.path.join(data_dir, "tmp"),
        storagedir=None,
        debug=True,
        reset=None,
        dry=False,
        api_spec=False,
    )
    yield core


@pytest.fixture(scope="module")
def client(pyload_core):
    # Single app/test-client for the whole module (avoids re-registering blueprints).
    app = pyload_core.webserver.app
    app.config.update({"TESTING": True})
    return app.test_client()


@pytest.fixture(scope="module")
def env(pyload_core, client):
    db = pyload_core.db
    db.add_user(TARGET_USER, TARGET_PW, int(Role.ADMIN), 0, True)
    db.add_user(ATTACKER, ATTACKER_PW, int(Role.USER), 0, True)
    db.add_user(ATTACKER_ALL, ATTACKER_ALL_PW, int(Role.USER), ALL_PERMS, True)

    keys = {}
    for user, pw in (
        ("pyload", "pyload"),         # default administrator
        (ATTACKER, ATTACKER_PW),       # permissionless non-admin
        (ATTACKER_ALL, ATTACKER_ALL_PW),  # non-admin holding every flag
    ):
        res = pyload_core.api.generate_apikey(user, pw)
        keys[user] = res["data"]["key"]

    return {"client": client, "keys": keys}


def _get(client, key, func, **params):
    return client.get(
        "/api/" + func,
        query_string=params,
        headers={"X-API-Key": key},
    )


def _userdata(client, key, func, username, password):
    return _get(client, key, func, username=username, password=password)


def _same_response(r1, r2):
    """True when two responses are indistinguishable to the caller (status + body)."""
    return r1.status_code == r2.status_code and r1.get_data() == r2.get_data()


# --------------------------------------------------------------------------
# Security tests: must FAIL on the vulnerable code and PASS after a correct fix.
# They only observe what the authenticated caller can observe at the HTTP route.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("func", USERDATA_FUNCS)
def test_security_no_password_oracle_for_unprivileged_caller(env, func):
    """A permissionless account must not learn whether a password is valid for another account."""
    client, keys = env["client"], env["keys"]
    wrong = _userdata(client, keys[ATTACKER], func, TARGET_USER, WRONG_PW)
    right = _userdata(client, keys[ATTACKER], func, TARGET_USER, TARGET_PW)
    assert _same_response(wrong, right)


@pytest.mark.parametrize("func", USERDATA_FUNCS)
def test_security_no_password_oracle_for_fully_flagged_caller(env, func):
    """Holding every permission flag (but not admin) still must not expose the password oracle."""
    client, keys = env["client"], env["keys"]
    wrong = _userdata(client, keys[ATTACKER_ALL], func, TARGET_USER, WRONG_PW)
    right = _userdata(client, keys[ATTACKER_ALL], func, TARGET_USER, TARGET_PW)
    assert _same_response(wrong, right)


@pytest.mark.parametrize("func", USERDATA_FUNCS)
def test_security_no_password_oracle_against_non_admin_target(env, func):
    """The oracle must be closed for any target account, not only the administrator's."""
    client, keys = env["client"], env["keys"]
    wrong = _userdata(client, keys[ATTACKER], func, ATTACKER_ALL, WRONG_PW)
    right = _userdata(client, keys[ATTACKER], func, ATTACKER_ALL, ATTACKER_ALL_PW)
    assert _same_response(wrong, right)


def test_security_repeated_guesses_indistinguishable(env):
    """Interleaved wrong/right guesses from a low-privilege caller must all look identical."""
    client, keys = env["client"], env["keys"]
    guesses = [WRONG_PW, TARGET_PW, "another_wrong", TARGET_PW, "yet_another_wrong"]
    responses = [
        _userdata(client, keys[ATTACKER], "get_userdata", TARGET_USER, g)
        for g in guesses
    ]
    for r in responses[1:]:
        assert _same_response(responses[0], r)


# --------------------------------------------------------------------------
# Functional tests: must PASS on both the vulnerable and the fixed code.
# A fix that disables the feature or over-blocks must break at least one.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("func", USERDATA_FUNCS)
def test_functional_admin_can_look_up_account(env, func):
    """An administrator must still retrieve real account data for valid credentials."""
    client, keys = env["client"], env["keys"]
    wrong = _userdata(client, keys["pyload"], func, TARGET_USER, WRONG_PW)
    right = _userdata(client, keys["pyload"], func, TARGET_USER, TARGET_PW)
    assert right.status_code == 200
    # A working lookup returns something different for valid vs invalid credentials.
    assert not _same_response(wrong, right)


def test_functional_open_endpoint_available_to_any_login(env):
    """Endpoints open to any signed-in user stay reachable for a permissionless account."""
    client, keys = env["client"], env["keys"]
    resp = _get(client, keys[ATTACKER], "getServerVersion")
    assert resp.status_code == 200


def test_functional_permission_gating_still_enforced(env):
    """Permission handling for other operations is unchanged: gated stays gated, allowed stays allowed."""
    client, keys = env["client"], env["keys"]
    # A LIST-capable non-admin can still read the queue.
    allowed = _get(client, keys[ATTACKER_ALL], "getQueue")
    assert allowed.status_code == 200
    # A permissionless non-admin still cannot read the full settings.
    denied = _get(client, keys[ATTACKER], "getConfig")
    assert denied.status_code != 200
