"""The authorization server: metadata, JWKS, /authorize, /token.

The step 3 break (c7ca8e1) shipped four flaws in this flow, each now closed and
pinned by `tests/attacks/test_as_oauth.py`: PKCE optional, `plain` accepted
(and defaulted to), codes redeemable twice, redirect URIs matched by prefix.

The flow, and where each check sits:

1. `GET /authorize` validates the client and redirect URI **first**. If either is
   bad, the answer is an error page and never a redirect: redirecting an error to
   an unverified URI is itself an open redirect. Everything after that point
   fails by redirecting back with `error=` and `iss=`.
2. The request is parked server-side under an unguessable id, and a login form
   is rendered carrying only that id. Nothing in the form is trusted except the
   id, so a tampered hidden field cannot change the client, scope or audience.
3. `POST /authorize` takes the parked request (single use), authenticates the
   user, mints a code, and redirects with `code`, `state` and `iss` (RFC 9207).
4. `POST /token` redeems a code or rotates a refresh token.
"""

import html
import json
import os
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Final
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from rlas import __version__, pkce
from rlas.clients import (
    Client,
    ClientError,
    ClientResolver,
    MetadataDocumentResolver,
    StaticClientResolver,
)
from rlas.keys import SigningKey, load_key_file
from rlas.settings import (
    CLIENTS_ENV_VAR,
    DEFAULT_SIGNING_KEY_FILE,
    DEFAULT_USERS_FILE,
    SIGNING_KEY_ENV_VAR,
    USERS_ENV_VAR,
    ServerConfig,
    config_from_env,
    path_from_env,
)
from rlas.store import ExpiringStore, utc_now
from rlas.tokens import mint_access_token
from rlas.users import User, UserDirectory

#: RFC 6749 section 5.1: token responses must not be cached anywhere.
_NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}

#: The login page holds a password field. It must not be framed (clickjacking),
#: cached, or leak its URL -- which carries `state` and the PKCE challenge -- in
#: a Referer header. No `form-action`: browsers apply it to the redirect that
#: follows the POST, which would block delivering the code to the client.
_PAGE_HEADERS: Final = {
    **_NO_STORE,
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@dataclass(frozen=True)
class AuthorizationRequest:
    client_id: str
    redirect_uri: str
    scope: tuple[str, ...]
    resource: str
    state: str | None
    #: Always S256 -- `/authorize` refuses anything else -- so the method is not stored.
    code_challenge: str


@dataclass(frozen=True)
class IssuedCode:
    request: AuthorizationRequest
    user: User


@dataclass(frozen=True)
class RefreshGrant:
    client_id: str
    user: User
    scope: tuple[str, ...]
    resource: str
    #: Every refresh token descended from one authorization shares a family, so
    #: reuse of any one of them can revoke the lot (OAuth 2.1 section 4.3.1).
    family: str


def _with_query(uri: str, params: Mapping[str, str | None]) -> str:
    parts = urlsplit(uri)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    return urlunsplit(parts._replace(query=f"{parts.query}&{extra}" if parts.query else extra))


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    document = (
        f"<!doctype html><html><head><meta charset=utf-8><title>{html.escape(title)}</title>"
        f"</head><body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    return HTMLResponse(document, status_code=status_code, headers=_PAGE_HEADERS)


def _error_page(message: str, status_code: int = 400) -> HTMLResponse:
    return _page("Authorization failed", f"<p>{html.escape(message)}</p>", status_code)


def _token_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=_NO_STORE,
    )


def create_app(
    config: ServerConfig,
    *,
    signing_key: SigningKey,
    users: UserDirectory,
    clients: ClientResolver,
    clock: Callable[[], datetime] = utc_now,
) -> FastAPI:
    logins: ExpiringStore[AuthorizationRequest] = ExpiringStore(config.login_ttl, clock)
    codes: ExpiringStore[IssuedCode] = ExpiringStore(config.code_ttl, clock)
    refresh_tokens: ExpiringStore[RefreshGrant] = ExpiringStore(config.refresh_token_ttl, clock)
    #: Redeemed codes, mapped to the refresh family each one started. A second use
    #: is then recognised as theft and revokes what the first use issued. Kept as
    #: long as a refresh token lives, because that is what it may need to revoke.
    spent_codes: ExpiringStore[str] = ExpiringStore(config.refresh_token_ttl, clock)
    #: Refresh tokens already rotated, kept so that a second use is recognised as
    #: theft rather than looking like an unknown token.
    spent_refresh: ExpiringStore[str] = ExpiringStore(config.refresh_token_ttl, clock)
    revoked_families: set[str] = set()

    app = FastAPI(title="rlas", version=__version__, summary="Local OAuth 2.1 AS.")

    @app.get("/.well-known/oauth-authorization-server", tags=["metadata"])
    def metadata() -> dict[str, object]:
        """RFC 8414 authorization server metadata."""
        return {
            "issuer": config.issuer,
            "authorization_endpoint": f"{config.issuer}/authorize",
            "token_endpoint": f"{config.issuer}/token",
            "jwks_uri": f"{config.issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": sorted(pkce.SUPPORTED_METHODS),
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": sorted(config.scopes),
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True,
        }

    @app.get("/.well-known/jwks.json", tags=["metadata"])
    def jwks() -> dict[str, list[dict[str, str]]]:
        return signing_key.jwks()

    @app.get("/authorize", tags=["oauth"], response_model=None)
    def authorize(
        client_id: Annotated[str | None, Query()] = None,
        redirect_uri: Annotated[str | None, Query()] = None,
        response_type: Annotated[str | None, Query()] = None,
        scope: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
        resource: Annotated[str | None, Query()] = None,
        code_challenge: Annotated[str | None, Query()] = None,
        code_challenge_method: Annotated[str | None, Query()] = None,
    ) -> HTMLResponse | RedirectResponse:
        # --- Phase 1: who is asking, and where would we send the answer? ------
        # Failures here are pages, never redirects.
        if not client_id or not redirect_uri:
            return _error_page("client_id and redirect_uri are required")
        try:
            client: Client = clients.resolve(client_id)
        except ClientError as exc:
            return _error_page(f"invalid client: {exc}")
        if not client.allows_redirect(redirect_uri):
            return _error_page("redirect_uri is not registered for this client")

        # --- Phase 2: the redirect URI is trusted; errors go back to it. ------
        def fail(error: str, description: str) -> RedirectResponse:
            target = _with_query(
                redirect_uri,
                {
                    "error": error,
                    "error_description": description,
                    "state": state,
                    "iss": config.issuer,
                },
            )
            return RedirectResponse(target, status_code=303)

        if response_type != "code":
            return fail("unsupported_response_type", "only response_type=code is supported")
        # Required, and S256 must be *stated*: an omitted method means `plain` under
        # RFC 7636, which is how a correctly hashed challenge became a public verifier.
        if not code_challenge or code_challenge_method not in pkce.SUPPORTED_METHODS:
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
        if resource not in config.resources:
            return fail("invalid_target", "resource is missing or not served by this AS")
        requested = tuple(dict.fromkeys((scope or "").split()))
        if not requested or not set(requested) <= config.scopes:
            return fail("invalid_scope", "scope is missing or contains an unknown value")

        request_id = secrets.token_urlsafe(32)
        logins.put(
            request_id,
            AuthorizationRequest(
                client_id=client.client_id,
                redirect_uri=redirect_uri,
                scope=requested,
                resource=resource,
                state=state,
                code_challenge=code_challenge,
            ),
        )
        label = html.escape(client.client_name or client.client_id)
        return _page(
            "Sign in",
            f"<p><b>{label}</b> is asking for <code>{html.escape(' '.join(requested))}</code> "
            f"at <code>{html.escape(resource)}</code>.</p>"
            '<form method="post" action="/authorize">'
            f'<input type="hidden" name="request_id" value="{request_id}">'
            '<label>Username <input name="username" autocomplete="username"></label> '
            '<label>Password <input name="password" type="password" '
            'autocomplete="current-password"></label> '
            "<button>Sign in</button></form>",
        )

    @app.post("/authorize", tags=["oauth"], response_model=None)
    def login(
        request_id: Annotated[str, Form()],
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
    ) -> HTMLResponse | RedirectResponse:
        # Single use whether or not the password is right: a failed attempt ends
        # the flow, so one rendered form is one guess.
        request = logins.take(request_id)
        if request is None:
            return _error_page("this sign-in has expired or was already used")
        user = users.authenticate(username, password)
        if user is None:
            return _error_page("sign-in failed; start again from the application", 401)

        code = secrets.token_urlsafe(32)
        codes.put(code, IssuedCode(request=request, user=user))
        target = _with_query(
            request.redirect_uri, {"code": code, "state": request.state, "iss": config.issuer}
        )
        return RedirectResponse(target, status_code=303)

    def issue_tokens(
        *, client_id: str, user: User, scope: tuple[str, ...], resource: str, family: str
    ) -> JSONResponse:
        access_token = mint_access_token(
            signing_key,
            issuer=config.issuer,
            sub=user.sub,
            audience=resource,
            client_id=client_id,
            scope=scope,
            roles=user.roles,
            ttl=config.access_token_ttl,
            now=clock(),
        )
        refresh_token = secrets.token_urlsafe(32)
        refresh_tokens.put(
            refresh_token,
            RefreshGrant(
                client_id=client_id, user=user, scope=scope, resource=resource, family=family
            ),
        )
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": int(config.access_token_ttl.total_seconds()),
                "scope": " ".join(scope),
                "refresh_token": refresh_token,
            },
            headers=_NO_STORE,
        )

    def redeem_code(
        code: str | None,
        client_id: str | None,
        redirect_uri: str | None,
        code_verifier: str | None,
        resource: str | None,
    ) -> JSONResponse:
        if not code or not client_id:
            return _token_error("invalid_request", "code and client_id are required")
        # `take`, not `peek`, and before any other check: this attempt consumes the
        # code whatever its outcome, so a wrong verifier burns it rather than leaving
        # it open to further guesses.
        issued = codes.take(code)
        if issued is None:
            # A code already redeemed means two parties hold it. As with refresh
            # tokens, we cannot tell which is legitimate, so neither keeps the family.
            # Access tokens already issued from it stay valid until they expire:
            # they are self-contained JWTs, and nothing here can recall one.
            family = spent_codes.peek(code)
            if family is not None:
                revoked_families.add(family)
            return _token_error("invalid_grant", "unknown, expired or used code")
        family = secrets.token_urlsafe(16)
        spent_codes.put(code, family)
        request = issued.request
        if client_id != request.client_id:
            return _token_error("invalid_grant", "code was issued to another client")
        if redirect_uri != request.redirect_uri:
            return _token_error("invalid_grant", "redirect_uri does not match the authorization")
        if not pkce.verify(code_verifier, request.code_challenge):
            return _token_error("invalid_grant", "PKCE verification failed")
        if resource is not None and resource != request.resource:
            return _token_error("invalid_target", "resource differs from the authorization")
        return issue_tokens(
            client_id=client_id,
            user=issued.user,
            scope=request.scope,
            resource=request.resource,
            family=family,
        )

    def rotate_refresh(
        refresh_token: str | None,
        client_id: str | None,
        scope: str | None,
        resource: str | None,
    ) -> JSONResponse:
        if not refresh_token or not client_id:
            return _token_error("invalid_request", "refresh_token and client_id are required")
        grant = refresh_tokens.take(refresh_token)
        if grant is None:
            # A rotated token presented again means two parties hold it. We cannot
            # tell which is legitimate, so neither keeps the family.
            family = spent_refresh.peek(refresh_token)
            if family is not None:
                revoked_families.add(family)
            return _token_error("invalid_grant", "unknown, expired or reused refresh token")
        spent_refresh.put(refresh_token, grant.family)
        if grant.family in revoked_families:
            return _token_error("invalid_grant", "refresh token family has been revoked")
        if client_id != grant.client_id:
            revoked_families.add(grant.family)
            return _token_error("invalid_grant", "refresh token was issued to another client")

        narrowed = grant.scope
        if scope is not None:
            narrowed = tuple(dict.fromkeys(scope.split()))
            if not narrowed or not set(narrowed) <= set(grant.scope):
                return _token_error("invalid_scope", "scope may only narrow on refresh")
        if resource is not None and resource != grant.resource:
            return _token_error("invalid_target", "resource differs from the original grant")
        return issue_tokens(
            client_id=client_id,
            user=grant.user,
            scope=narrowed,
            resource=grant.resource,
            family=grant.family,
        )

    @app.post("/token", tags=["oauth"])
    def token(
        grant_type: Annotated[str, Form()],
        code: Annotated[str | None, Form()] = None,
        redirect_uri: Annotated[str | None, Form()] = None,
        client_id: Annotated[str | None, Form()] = None,
        code_verifier: Annotated[str | None, Form()] = None,
        refresh_token: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
        resource: Annotated[str | None, Form()] = None,
    ) -> JSONResponse:
        if grant_type == "authorization_code":
            return redeem_code(code, client_id, redirect_uri, code_verifier, resource)
        if grant_type == "refresh_token":
            return rotate_refresh(refresh_token, client_id, scope, resource)
        return _token_error("unsupported_grant_type", f"grant_type {grant_type!r} not supported")

    return app


def asgi_app_from_env() -> FastAPI:
    """Entrypoint for `uvicorn --factory rlas.app:asgi_app_from_env --port 9000`.

    Fails to boot if the signing key or user file is missing or the key is
    exposed (see `keys.load_key_file`). With `RLAS_CLIENTS_FILE` set, clients come
    from that file of metadata documents and nothing is fetched; without it,
    every /authorize fetches the client_id URL (and is an SSRF primitive until
    step 17, so keep the AS on loopback).
    """
    config = config_from_env()
    signing_key = load_key_file(path_from_env(SIGNING_KEY_ENV_VAR, DEFAULT_SIGNING_KEY_FILE))
    users = UserDirectory.from_file(path_from_env(USERS_ENV_VAR, DEFAULT_USERS_FILE))
    clients_file = os.environ.get(CLIENTS_ENV_VAR)
    clients: ClientResolver
    if clients_file:
        document = json.loads(Path(clients_file).read_text(encoding="utf-8"))
        clients = StaticClientResolver(document["clients"])
    else:
        clients = MetadataDocumentResolver(httpx.Client())
    return create_app(config, signing_key=signing_key, users=users, clients=clients)
