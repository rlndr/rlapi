"""rlas building blocks: keys, client metadata, passwords, the expiring store."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from rlas.clients import (
    MAX_DOCUMENT_BYTES,
    ClientError,
    MetadataDocumentResolver,
    parse_metadata,
    validate_client_id_url,
)
from rlas.keys import (
    SigningKey,
    SigningKeyError,
    generate_key_file,
    jwk_thumbprint,
    load_key_file,
)
from rlas.pkce import s256, verify
from rlas.store import ExpiringStore
from rlas.users import hash_password, verify_password

# --- Signing key ---------------------------------------------------------------


@pytest.fixture(scope="module")
def key_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("keys") / "signing.pem"
    generate_key_file(path)
    return path


def test_generated_key_file_is_owner_only(key_file: Path) -> None:
    assert key_file.stat().st_mode & 0o777 == 0o600


def test_generated_key_loads_with_a_thumbprint_kid(key_file: Path) -> None:
    key = load_key_file(key_file)

    assert key.private_key.key_size == 3072
    assert key.kid == jwk_thumbprint(key.private_key.public_key())
    assert key.public_jwk()["kid"] == key.kid


def test_keygen_refuses_to_overwrite(key_file: Path) -> None:
    before = key_file.read_bytes()

    with pytest.raises(FileExistsError):
        generate_key_file(key_file)

    assert key_file.read_bytes() == before


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_exposed_key_file_is_refused(key_file: Path, tmp_path: Path, mode: int) -> None:
    exposed = tmp_path / "exposed.pem"
    exposed.write_bytes(key_file.read_bytes())
    exposed.chmod(mode)

    with pytest.raises(SigningKeyError, match="group/other"):
        load_key_file(exposed)


def test_missing_key_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SigningKeyError, match="keygen"):
        load_key_file(tmp_path / "absent.pem")


def test_weak_key_is_refused() -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505  -- deliberately weak, proves the floor

    with pytest.raises(SigningKeyError, match="minimum is 2048"):
        SigningKey.from_private_key(weak)


# --- Client ID Metadata Documents ----------------------------------------------

CID = "https://client.test/cimd.json"


@pytest.mark.parametrize(
    "client_id",
    [
        "http://client.test/cimd.json",  # not https
        "https://client.test",  # no path
        "https://client.test/",  # root path only
        "https://client.test/a/../cimd.json",  # dot segment
        "https://client.test/./cimd.json",
        "https://client.test/cimd.json#frag",
        "https://user:pw@client.test/cimd.json",  # credentials  # pragma: allowlist secret
        "https:///cimd.json",  # no host
    ],
)
def test_client_id_url_constraints(client_id: str) -> None:
    with pytest.raises(ClientError):
        validate_client_id_url(client_id)


def test_valid_client_id_url_passes() -> None:
    validate_client_id_url(CID)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"client_id": "https://other.test/cimd.json", "redirect_uris": ["https://x"]}, "name"),
        ({"client_id": CID, "redirect_uris": ["https://x"], "client_secret": "s"}, "secret"),
        (
            {
                "client_id": CID,
                "redirect_uris": ["https://x"],
                "token_endpoint_auth_method": "client_secret_basic",
            },
            "auth_method",
        ),
        ({"client_id": CID, "redirect_uris": []}, "redirect_uris"),
        ({"client_id": CID}, "redirect_uris"),
        ({"client_id": CID, "redirect_uris": [7]}, "redirect_uris"),
    ],
)
def test_metadata_document_rejections(document: dict[str, object], message: str) -> None:
    with pytest.raises(ClientError, match=message):
        parse_metadata(CID, document)


def _resolver(handler: httpx.MockTransport) -> MetadataDocumentResolver:
    return MetadataDocumentResolver(httpx.Client(transport=handler))


def test_resolver_does_not_follow_redirects() -> None:
    """A redirect would let the document come from a host the client_id does not name."""
    transport = httpx.MockTransport(
        lambda _: httpx.Response(302, headers={"location": "https://evil.test/cimd.json"})
    )

    with pytest.raises(ClientError, match="302"):
        _resolver(transport).resolve(CID)


def test_resolver_caps_document_size() -> None:
    oversized = b'{"pad": "' + b"x" * MAX_DOCUMENT_BYTES + b'"}'
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=oversized))

    with pytest.raises(ClientError, match="too large"):
        _resolver(transport).resolve(CID)


def test_resolver_rejects_non_object_json() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=[CID]))

    with pytest.raises(ClientError, match="object"):
        _resolver(transport).resolve(CID)


def test_resolver_checks_the_url_before_fetching() -> None:
    def must_not_fetch(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"fetched {request.url}")

    with pytest.raises(ClientError, match="https"):
        _resolver(httpx.MockTransport(must_not_fetch)).resolve("http://client.test/cimd.json")


# --- PKCE verify: the second layer -------------------------------------------
#
# /authorize refusing non-S256 requests is the first layer, and the attack suite
# pins it. These pin the second: even if /authorize were loosened, /token has no
# `plain` comparison to fall back on. Measured at step 3: with only one layer
# removed the exploits still failed, so each layer needs its own test.


def test_verify_accepts_the_s256_preimage() -> None:
    verifier = "v" * 43

    assert verify(verifier, s256(verifier))


def test_verify_never_accepts_the_challenge_as_its_own_verifier() -> None:
    """What `plain` would accept. A 43-char S256 challenge is a well-formed verifier."""
    challenge = s256("v" * 43)

    assert not verify(challenge, challenge)


def test_verify_rejects_a_missing_verifier() -> None:
    assert not verify(None, s256("v" * 43))


# --- Passwords -----------------------------------------------------------------


def test_password_hash_round_trip() -> None:
    encoded = hash_password("hunter2-but-longer")

    assert encoded.startswith("scrypt$")
    assert verify_password("hunter2-but-longer", encoded)
    assert not verify_password("hunter3-but-longer", encoded)


def test_same_password_hashes_differently() -> None:
    assert hash_password("same") != hash_password("same")


# --- Expiring store ------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def test_take_is_single_use() -> None:
    store: ExpiringStore[str] = ExpiringStore(timedelta(minutes=1))
    store.put("k", "v")

    assert store.take("k") == "v"
    assert store.take("k") is None


def test_peek_leaves_the_entry() -> None:
    store: ExpiringStore[str] = ExpiringStore(timedelta(minutes=1))
    store.put("k", "v")

    assert store.peek("k") == "v"
    assert store.peek("k") == "v"


def test_entries_expire() -> None:
    clock = _Clock()
    store: ExpiringStore[str] = ExpiringStore(timedelta(minutes=1), clock)
    store.put("k", "v")

    clock.now += timedelta(minutes=1)

    assert store.peek("k") is None
    assert store.take("k") is None
