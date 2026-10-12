"""Fixtures and flow helpers for `rlas`, the authorization server.

Registered from `tests/conftest.py` via `pytest_plugins`. Kept apart from the
`rlapi` fixtures there because the two services share nothing but test layout.

Clients are resolved by the real `MetadataDocumentResolver`, fetching over an
`httpx.MockTransport` instead of the network. That way the Client ID Metadata
Document parsing is the shipped code path, not a stub that always agrees.

Two registered clients, chosen for exploit 4:

- `client.test` registers a full callback URL, `https://client.test/cb`.
- `origin.test` registers a bare origin, `https://origin.test`. Real clients do
  this. Prefix matching is much more dangerous against this shape.
"""

import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from rlas.app import create_app
from rlas.clients import MetadataDocumentResolver
from rlas.keys import GENERATED_KEY_BITS, SigningKey
from rlas.pkce import s256
from rlas.settings import ServerConfig
from rlas.users import UserDirectory, hash_password

ISSUER = "https://rlas.test"
RESOURCE = "https://rlapi.local"

CLIENT_ID = "https://client.test/cimd.json"
REDIRECT_URI = "https://client.test/cb"
ORIGIN_CLIENT_ID = "https://origin.test/cimd.json"
ORIGIN_REDIRECT_URI = "https://origin.test"

USERNAME = "alice"
# Two scanners flag this line, so it carries two suppressions: ruff S105 and
# detect-secrets. Both are per-line on purpose; see SECURITYTEST.md gotcha 2.
PASSWORD = "correct horse battery staple"  # noqa: S105  # pragma: allowlist secret
USER_SUB = "1"

METADATA_DOCUMENTS: dict[str, dict[str, object]] = {
    CLIENT_ID: {
        "client_id": CLIENT_ID,
        "client_name": "Test client",
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
    },
    ORIGIN_CLIENT_ID: {
        "client_id": ORIGIN_CLIENT_ID,
        "client_name": "Origin-registered client",
        "redirect_uris": [ORIGIN_REDIRECT_URI],
    },
}


def _serve_metadata(request: httpx.Request) -> httpx.Response:
    document = METADATA_DOCUMENTS.get(str(request.url))
    if document is None:
        return httpx.Response(404)
    return httpx.Response(200, json=document)


@pytest.fixture(scope="session")
def signing_key() -> SigningKey:
    """One key per session: RSA generation is the slowest thing in the suite."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=GENERATED_KEY_BITS)
    return SigningKey.from_private_key(private_key)


@pytest.fixture(scope="session")
def user_directory() -> UserDirectory:
    return UserDirectory.from_records(
        [
            {
                "username": USERNAME,
                "sub": USER_SUB,
                "roles": ["customer"],
                "password_hash": hash_password(PASSWORD),
            }
        ]
    )


@pytest.fixture
def as_config() -> ServerConfig:
    return ServerConfig(issuer=ISSUER)


@pytest.fixture
def as_app(
    as_config: ServerConfig, signing_key: SigningKey, user_directory: UserDirectory
) -> Iterator[FastAPI]:
    with httpx.Client(transport=httpx.MockTransport(_serve_metadata)) as http:
        yield create_app(
            as_config,
            signing_key=signing_key,
            users=user_directory,
            clients=MetadataDocumentResolver(http),
        )


@pytest.fixture
def as_client(as_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(as_app, base_url=ISSUER, follow_redirects=False) as client:
        yield client


# --- Flow helpers --------------------------------------------------------------


@dataclass(frozen=True)
class Pkce:
    verifier: str
    challenge: str


def new_pkce() -> Pkce:
    verifier = secrets.token_urlsafe(48)  # 64 chars, within RFC 7636's 43-128
    return Pkce(verifier=verifier, challenge=s256(verifier))


def authorize_params(pkce: Pkce | None = None, **overrides: str | None) -> dict[str, str]:
    """A valid S256 authorization request. Override a key with None to omit it."""
    pkce = pkce or new_pkce()
    params: dict[str, str | None] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "orders:read",
        "state": secrets.token_urlsafe(16),
        "resource": RESOURCE,
        "code_challenge": pkce.challenge,
        "code_challenge_method": "S256",
        **overrides,
    }
    return {k: v for k, v in params.items() if v is not None}


_REQUEST_ID = re.compile(r'name="request_id" value="([^"]+)"')


def sign_in(
    client: TestClient,
    params: dict[str, str],
    *,
    username: str = USERNAME,
    password: str = PASSWORD,
) -> httpx.Response:
    """GET /authorize, then submit the login form. Returns the POST's response."""
    form_page = client.get("/authorize", params=params)
    assert form_page.status_code == 200, form_page.text
    match = _REQUEST_ID.search(form_page.text)
    assert match, "login form carried no request_id"
    response: httpx.Response = client.post(
        "/authorize",
        data={"request_id": match.group(1), "username": username, "password": password},
    )
    return response


def redirect_query(response: httpx.Response) -> dict[str, str]:
    assert response.status_code == 303, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return {k: v[0] for k, v in query.items()}


def obtain_code(client: TestClient, params: dict[str, str]) -> str:
    return redirect_query(sign_in(client, params))["code"]


def redeem(
    client: TestClient,
    code: str,
    *,
    verifier: str | None,
    redirect_uri: str = REDIRECT_URI,
    client_id: str = CLIENT_ID,
    **extra: str,
) -> httpx.Response:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        **extra,
    }
    if verifier is not None:
        data["code_verifier"] = verifier
    response: httpx.Response = client.post("/token", data=data)
    return response
