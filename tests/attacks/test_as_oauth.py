"""Authorization-code theft against our own AS: PKCE, code replay, redirect matching.

PLAN.md step:      3
OWASP:             MCP01, MCP07
Vulnerable commit: c7ca8e1
Findings:          THREAT_MODEL.md F-15, F-16, F-17, F-18

Every exploit here ran green against the vulnerable code first. The payloads are
unchanged from the break phase -- only the expected outcome moved.

The attacker in all of these holds, or steers, an authorization code. PKCE
exists so that a code stolen from a flow the client started is useless; exact
redirect matching exists so that the code is never sent to the attacker at all.
Neither substitutes for the other: in exploit 4 the *attacker* starts the flow,
so they chose the PKCE verifier and S256 passes.

What was observed before the fix, so "what did this actually prevent?" has an
answer later:

- No `code_challenge` at /authorize: the code alone redeemed at /token. (F-15)
- `code_challenge_method=plain`: the challenge copied from the authorization URL
  redeemed as the verifier. (F-15)
- Method *omitted* with a correctly hashed S256 challenge: the legitimate client
  presenting its real verifier got `invalid_grant`, while a thief presenting the
  challenge from the URL got a token. RFC 7636 defaults the method to `plain`,
  so the control inverted. (F-16)
- A code redeemed twice returned two independent token sets, each with its own
  refresh family; a wrong-verifier attempt left the code redeemable. (F-17)
- Registered `https://client.test/cb`: prefix matching sent the code to five
  other URLs on client.test, but REJECTED `https://evil.test` -- PLAN.md said it
  would be accepted. Registered the bare origin `https://origin.test`: the code
  went to `origin.test.evil.test` and, via userinfo, to `evil.test`. (F-18)
"""

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.as_fixtures import (
    CLIENT_ID,
    ORIGIN_CLIENT_ID,
    authorize_params,
    new_pkce,
    obtain_code,
    redeem,
)

pytestmark = [pytest.mark.attack, pytest.mark.mcp01, pytest.mark.mcp07]

BAD_REQUEST = 400
OK = 200


def _authorize_error(response: httpx.Response) -> str:
    """The `error` an /authorize redirect carries -- and proof it carries no code."""
    assert response.status_code == 303, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert "code" not in query
    return query["error"][0]


def _token_error(response: httpx.Response) -> str:
    assert response.status_code == BAD_REQUEST, response.text
    error: str = response.json()["error"]
    return error


# --- Exploit 1: PKCE omitted ---------------------------------------------------


def test_authorization_without_pkce_is_refused(as_client: TestClient) -> None:
    """Previously issued a code that redeemed with no verifier at all."""
    params = authorize_params(code_challenge=None, code_challenge_method=None)

    response = as_client.get("/authorize", params=params)

    assert _authorize_error(response) == "invalid_request"


def test_challenge_without_verifier_is_refused(as_client: TestClient) -> None:
    """The RFC 9700 PKCE downgrade: challenge at /authorize, no verifier at /token.

    Held at the break too -- `verify` already failed a recorded challenge with no
    verifier. Pinned because it is the downgrade most ASes get wrong.
    """
    code = obtain_code(as_client, authorize_params())

    assert _token_error(redeem(as_client, code, verifier=None)) == "invalid_grant"


# --- Exploit 2: PKCE downgraded to plain ---------------------------------------


def test_plain_method_is_refused(as_client: TestClient) -> None:
    """Previously the challenge in the URL redeemed as the verifier."""
    secret = new_pkce().verifier
    params = authorize_params(code_challenge=secret, code_challenge_method="plain")

    assert _authorize_error(as_client.get("/authorize", params=params)) == "invalid_request"


def test_omitted_method_is_refused_not_defaulted(as_client: TestClient) -> None:
    """Previously defaulted to `plain` (RFC 7636) and the raw challenge redeemed."""
    secret = new_pkce().verifier
    params = authorize_params(code_challenge=secret, code_challenge_method=None)

    assert _authorize_error(as_client.get("/authorize", params=params)) == "invalid_request"


def test_hashed_challenge_with_omitted_method_is_refused(as_client: TestClient) -> None:
    """F-16: the inverted control.

    A correct S256 challenge sent without `code_challenge_method`. At the break
    the AS read it as `plain`: the client's real verifier failed and the
    challenge itself, readable in the URL, succeeded. Now the request is refused
    before a code exists, so neither party gets one.
    """
    params = authorize_params(new_pkce(), code_challenge_method=None)

    assert _authorize_error(as_client.get("/authorize", params=params)) == "invalid_request"


def test_challenge_from_the_url_does_not_redeem(as_client: TestClient) -> None:
    pkce = new_pkce()
    params = authorize_params(pkce)
    code = obtain_code(as_client, params)

    response = redeem(as_client, code, verifier=params["code_challenge"])

    assert _token_error(response) == "invalid_grant"


def test_metadata_advertises_only_s256(as_client: TestClient) -> None:
    metadata = as_client.get("/.well-known/oauth-authorization-server").json()

    assert metadata["code_challenge_methods_supported"] == ["S256"]


# --- Exploit 3: code replay ----------------------------------------------------


def test_code_does_not_redeem_twice(as_client: TestClient) -> None:
    """Previously returned two independent token sets for one login."""
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    legitimate = redeem(as_client, code, verifier=pkce.verifier)
    replayed = redeem(as_client, code, verifier=pkce.verifier)

    assert legitimate.status_code == OK
    assert _token_error(replayed) == "invalid_grant"


def test_replay_revokes_the_refresh_family_the_code_started(as_client: TestClient) -> None:
    """Two holders of one code; the AS cannot tell which is real, so neither keeps it.

    Access tokens already issued from the code are NOT revoked: they are
    self-contained JWTs and stay valid until `exp` (10 minutes). Only the
    refresh family is reachable. See THREAT_MODEL.md F-17.
    """
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))
    legitimate = redeem(as_client, code, verifier=pkce.verifier).json()

    redeem(as_client, code, verifier=pkce.verifier)  # the replay
    refreshed = as_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": legitimate["refresh_token"],
            "client_id": CLIENT_ID,
        },
    )

    assert _token_error(refreshed) == "invalid_grant"


def test_failed_redemption_burns_the_code(as_client: TestClient) -> None:
    """Previously a wrong verifier left the code redeemable, inviting more guesses."""
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    wrong = redeem(as_client, code, verifier=new_pkce().verifier)
    right = redeem(as_client, code, verifier=pkce.verifier)

    assert _token_error(wrong) == "invalid_grant"
    assert _token_error(right) == "invalid_grant"


# --- Exploit 4: redirect_uri prefix matching -----------------------------------
#
# Registered: `https://client.test/cb`. Each payload starts with that string.
# The comment is the host the browser would have delivered the code to.


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://client.test/cb/../../evil",  # client.test, path /evil
        "https://client.test/cb.evil",  # client.test
        "https://client.test/cbx",  # client.test
        "https://client.test/cb?next=https://evil.test",  # client.test
        "https://client.test/cb@evil.test",  # client.test: `@` is in the path
    ],
)
def test_extended_redirect_on_the_client_host_is_refused(
    as_client: TestClient, redirect_uri: str
) -> None:
    """Previously redirected the code to each of these."""
    response = as_client.get("/authorize", params=authorize_params(redirect_uri=redirect_uri))

    assert response.status_code == BAD_REQUEST
    assert "location" not in response.headers


# Registered: the bare origin `https://origin.test`. A prefix of an origin is a
# prefix of a hostname, and the code previously left the client's host entirely.


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://origin.test.evil.test/steal",  # subdomain of the attacker's domain
        "https://origin.test@evil.test/steal",  # userinfo: delivered to evil.test
        "https://origin.test:443@evil.test/steal",  # same, with a port to look legit
    ],
)
def test_off_host_redirect_from_an_origin_registration_is_refused(
    as_client: TestClient, redirect_uri: str
) -> None:
    params = authorize_params(client_id=ORIGIN_CLIENT_ID, redirect_uri=redirect_uri)

    response = as_client.get("/authorize", params=params)

    assert response.status_code == BAD_REQUEST
    assert "location" not in response.headers
