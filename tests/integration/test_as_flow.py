"""The authorization server doing its job: the half that catches an over-tight fix.

Every test here must pass both against the step-3 break commit and after the
fix. If a fix makes one of these fail, it rejected legitimate traffic and did
not just close the exploit.
"""

from datetime import timedelta

import jwt
from fastapi.testclient import TestClient

from rlas.keys import SigningKey
from tests.as_fixtures import (
    CLIENT_ID,
    ISSUER,
    ORIGIN_CLIENT_ID,
    REDIRECT_URI,
    RESOURCE,
    USER_SUB,
    authorize_params,
    new_pkce,
    obtain_code,
    redeem,
    redirect_query,
    sign_in,
)

BAD_REQUEST = 400
UNAUTHORIZED = 401


def _decode(token: str, key: SigningKey, audience: str = RESOURCE) -> dict[str, object]:
    """Verify the way step 4's resource server will: pinned alg, aud, iss."""
    public = jwt.PyJWK(key.public_jwk())
    claims: dict[str, object] = jwt.decode(
        token, public, algorithms=["RS256"], audience=audience, issuer=ISSUER
    )
    return claims


def _full_flow(client: TestClient, **overrides: str | None) -> dict[str, object]:
    pkce = new_pkce()
    code = obtain_code(client, authorize_params(pkce, **overrides))
    response = redeem(client, code, verifier=pkce.verifier)
    assert response.status_code == 200, response.text
    body: dict[str, object] = response.json()
    return body


def test_metadata_advertises_the_security_relevant_capabilities(as_client: TestClient) -> None:
    metadata = as_client.get("/.well-known/oauth-authorization-server").json()

    assert metadata["issuer"] == ISSUER
    assert metadata["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert metadata["token_endpoint"] == f"{ISSUER}/token"
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["client_id_metadata_document_supported"] is True
    assert "S256" in metadata["code_challenge_methods_supported"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert "registration_endpoint" not in metadata  # DCR is deprecated


def test_jwks_publishes_the_signing_key_by_thumbprint(
    as_client: TestClient, signing_key: SigningKey
) -> None:
    (jwk,) = as_client.get("/.well-known/jwks.json").json()["keys"]

    assert jwk["kid"] == signing_key.kid
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert "d" not in jwk  # the private exponent never leaves the AS


def test_code_flow_issues_an_rfc9068_access_token(
    as_client: TestClient, signing_key: SigningKey
) -> None:
    body = _full_flow(as_client)
    token = str(body["access_token"])

    header = jwt.get_unverified_header(token)
    assert header["typ"] == "at+jwt"
    assert header["kid"] == signing_key.kid
    assert header["alg"] == "RS256"

    claims = _decode(token, signing_key)
    assert claims["sub"] == USER_SUB
    assert claims["aud"] == RESOURCE
    assert claims["client_id"] == CLIENT_ID
    assert claims["scope"] == "orders:read"
    assert claims["roles"] == ["customer"]
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["iat"], int)
    assert claims["exp"] - claims["iat"] == timedelta(minutes=10).total_seconds()
    assert claims["jti"]
    assert body["token_type"] == "Bearer"  # noqa: S105  -- false positive: a dict key, not a secret
    assert body["expires_in"] == 600


def test_audience_is_the_requested_resource(as_client: TestClient, signing_key: SigningKey) -> None:
    body = _full_flow(as_client, resource="https://rlmcp.local")

    claims = _decode(str(body["access_token"]), signing_key, audience="https://rlmcp.local")
    assert claims["aud"] == "https://rlmcp.local"


def test_authorization_response_carries_state_and_iss(as_client: TestClient) -> None:
    params = authorize_params(state="opaque-client-state")

    query = redirect_query(sign_in(as_client, params))

    assert query["state"] == "opaque-client-state"
    assert query["iss"] == ISSUER
    assert query["code"]


def test_token_responses_are_not_cacheable(as_client: TestClient) -> None:
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    response = redeem(as_client, code, verifier=pkce.verifier)

    assert response.headers["cache-control"] == "no-store"


def test_login_page_cannot_be_framed_or_leak_its_url(as_client: TestClient) -> None:
    response = as_client.get("/authorize", params=authorize_params())

    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_unknown_resource_is_invalid_target(as_client: TestClient) -> None:
    response = as_client.get(
        "/authorize", params=authorize_params(resource="https://elsewhere.test")
    )

    query = redirect_query(response)
    assert query["error"] == "invalid_target"
    assert query["iss"] == ISSUER


def test_missing_resource_is_invalid_target_not_a_default(as_client: TestClient) -> None:
    """No resource means no audience; there is no default audience to fall back to."""
    response = as_client.get("/authorize", params=authorize_params(resource=None))

    assert redirect_query(response)["error"] == "invalid_target"


def test_unknown_scope_is_rejected(as_client: TestClient) -> None:
    response = as_client.get("/authorize", params=authorize_params(scope="orders:read root"))

    assert redirect_query(response)["error"] == "invalid_scope"


def test_unregistered_client_gets_an_error_page_not_a_redirect(as_client: TestClient) -> None:
    response = as_client.get(
        "/authorize", params=authorize_params(client_id="https://nobody.test/cimd.json")
    )

    assert response.status_code == BAD_REQUEST
    assert "location" not in response.headers


def test_unrelated_host_redirect_is_rejected(as_client: TestClient) -> None:
    """Rejected even by the step-3 break's prefix matcher: a prefix cannot change the host."""
    response = as_client.get(
        "/authorize", params=authorize_params(redirect_uri="https://evil.test/cb")
    )

    assert response.status_code == BAD_REQUEST
    assert "location" not in response.headers


def test_wrong_password_fails_and_burns_the_login(as_client: TestClient) -> None:
    form_page = as_client.get("/authorize", params=authorize_params())
    request_id = form_page.text.split('name="request_id" value="')[1].split('"')[0]

    wrong = as_client.post(
        "/authorize", data={"request_id": request_id, "username": "alice", "password": "nope"}
    )
    retry = as_client.post(
        "/authorize", data={"request_id": request_id, "username": "alice", "password": "nope"}
    )

    assert wrong.status_code == UNAUTHORIZED
    assert retry.status_code == BAD_REQUEST


def test_code_is_bound_to_its_client(as_client: TestClient) -> None:
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    response = redeem(as_client, code, verifier=pkce.verifier, client_id=ORIGIN_CLIENT_ID)

    assert response.status_code == BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


def test_code_is_bound_to_its_redirect_uri(as_client: TestClient) -> None:
    pkce = new_pkce()
    code = obtain_code(as_client, authorize_params(pkce))

    response = redeem(as_client, code, verifier=pkce.verifier, redirect_uri=f"{REDIRECT_URI}/other")

    assert response.json()["error"] == "invalid_grant"


def test_wrong_verifier_fails(as_client: TestClient) -> None:
    code = obtain_code(as_client, authorize_params(new_pkce()))

    response = redeem(as_client, code, verifier=new_pkce().verifier)

    assert response.json()["error"] == "invalid_grant"


def _refresh(client: TestClient, token: str, **extra: str) -> dict[str, object]:
    response = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": token, "client_id": CLIENT_ID}
        | extra,
    )
    body: dict[str, object] = response.json()
    return body


def test_refresh_rotates(as_client: TestClient) -> None:
    first = str(_full_flow(as_client)["refresh_token"])

    second = _refresh(as_client, first)

    assert "access_token" in second
    assert second["refresh_token"] != first


def test_refresh_token_reuse_revokes_the_whole_family(as_client: TestClient) -> None:
    """A rotated token seen twice means two holders. Neither keeps the family."""
    first = str(_full_flow(as_client)["refresh_token"])
    second = str(_refresh(as_client, first)["refresh_token"])

    replay = _refresh(as_client, first)
    after = _refresh(as_client, second)

    assert replay["error"] == "invalid_grant"
    assert after["error"] == "invalid_grant"


def test_refresh_may_narrow_scope_but_not_widen_it(as_client: TestClient) -> None:
    token = str(_full_flow(as_client, scope="orders:read orders:write")["refresh_token"])

    narrowed = _refresh(as_client, token, scope="orders:read")
    widened = _refresh(as_client, str(narrowed["refresh_token"]), scope="orders:read users:admin")

    assert narrowed["scope"] == "orders:read"
    assert widened["error"] == "invalid_scope"
