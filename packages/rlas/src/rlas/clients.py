"""Client registration via Client ID Metadata Documents (CIMD).

`2026-07-28` deprecates Dynamic Client Registration. Under CIMD, a `client_id`
*is* an HTTPS URL, and the document served at that URL is the registration. The
AS fetches it, checks that the document names itself (`client_id` inside equals
the URL it came from), and takes `redirect_uris` from it.

**This module makes the AS an HTTP client of attacker-chosen URLs.** Anyone can
send any `client_id` to /authorize, and the AS will fetch it. That is SSRF, and
it is NOT handled here beyond what is cheap: HTTPS only, no redirects followed,
a timeout and a size cap. Blocking private and loopback address ranges is
step 17 (ARCHITECTURE.md boundary 3). Until then, never expose `rlas` beyond
loopback.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlsplit

import httpx

#: A metadata document is a few hundred bytes. Anything near this is not one.
MAX_DOCUMENT_BYTES: Final = 64 * 1024
FETCH_TIMEOUT_SECONDS: Final = 5.0

#: Only public clients. PKCE is their proof of possession; a symmetric secret
#: published in a fetchable document would not be a secret.
_ALLOWED_AUTH_METHODS: Final = frozenset({"none"})


class ClientError(Exception):
    """The client_id or its metadata document is unusable. Never redirect on this."""


@dataclass(frozen=True)
class Client:
    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str | None = None

    def allows_redirect(self, redirect_uri: str) -> bool:
        """Exact string match against a registered URI. Nothing else.

        No prefix, no wildcard, and deliberately no normalisation. Normalising
        (case-folding the host, resolving `..`, dropping a default `:443`) means
        running a URL parser here and trusting that it agrees with the browser's,
        and disagreement between two parsers is how this check was beaten at
        the step 3 break: `https://origin.test@evil.test` starts with
        `https://origin.test` but is delivered to evil.test (THREAT_MODEL.md
        F-18). A client that wants two callbacks registers two URIs.
        """
        return redirect_uri in self.redirect_uris


class ClientResolver(Protocol):
    def resolve(self, client_id: str) -> Client: ...


def validate_client_id_url(client_id: str) -> None:
    """The CIMD draft's constraints on the URL itself, checked before any fetch."""
    parts = urlsplit(client_id)
    if parts.scheme != "https":
        raise ClientError("client_id must be an https URL")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise ClientError("client_id must name a host and carry no credentials")
    if parts.fragment or "#" in client_id:
        raise ClientError("client_id must not contain a fragment")
    segments = parts.path.split("/")
    if parts.path in {"", "/"} or any(seg in {".", ".."} for seg in segments):
        raise ClientError("client_id must have a path with no dot segments")


def parse_metadata(client_id: str, document: Mapping[str, object]) -> Client:
    """Validate a metadata document for `client_id` and build the Client."""
    if document.get("client_id") != client_id:
        raise ClientError("metadata document does not name itself as this client_id")
    if "client_secret" in document or "client_secret_expires_at" in document:
        raise ClientError("metadata document must not carry a client secret")
    auth_method = document.get("token_endpoint_auth_method", "none")
    if auth_method not in _ALLOWED_AUTH_METHODS:
        raise ClientError(f"unsupported token_endpoint_auth_method {auth_method!r}")

    redirect_uris = document.get("redirect_uris")
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or not all(isinstance(uri, str) for uri in redirect_uris)
    ):
        raise ClientError("metadata document must list redirect_uris")
    name = document.get("client_name")
    return Client(
        client_id=client_id,
        redirect_uris=tuple(redirect_uris),
        client_name=name if isinstance(name, str) else None,
    )


class MetadataDocumentResolver:
    """Fetch the metadata document from the client_id URL on every authorization.

    No caching: a fetch per /authorize is slow but means a client that edits its
    document, including to *remove* a redirect URI, takes effect immediately.
    """

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def resolve(self, client_id: str) -> Client:
        validate_client_id_url(client_id)
        try:
            with self._http.stream(
                "GET",
                client_id,
                headers={"Accept": "application/json"},
                follow_redirects=False,
                timeout=FETCH_TIMEOUT_SECONDS,
            ) as response:
                if response.status_code != httpx.codes.OK:
                    msg = f"metadata fetch returned {response.status_code}"
                    raise ClientError(msg)
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_DOCUMENT_BYTES:
                        raise ClientError("metadata document too large")
        except httpx.HTTPError as exc:
            msg = f"metadata fetch failed: {type(exc).__name__}"
            raise ClientError(msg) from exc

        try:
            document = json.loads(body)
        except ValueError as exc:
            raise ClientError("metadata document is not JSON") from exc
        if not isinstance(document, dict):
            raise ClientError("metadata document is not a JSON object")
        return parse_metadata(client_id, document)


class StaticClientResolver:
    """Pre-registered documents, for local development and tests. No network."""

    def __init__(self, documents: list[dict[str, object]]) -> None:
        self._clients: dict[str, Client] = {}
        for document in documents:
            client_id = str(document.get("client_id"))
            validate_client_id_url(client_id)
            self._clients[client_id] = parse_metadata(client_id, document)

    def resolve(self, client_id: str) -> Client:
        try:
            return self._clients[client_id]
        except KeyError:
            raise ClientError("unknown client_id") from None
