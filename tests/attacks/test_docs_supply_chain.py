"""`/docs` executes third-party script fetched from a CDN, unpinned and unverified.

PLAN.md step:      4 (first commit; recorded at step 2)
OWASP:             MCP04
Vulnerable commit: 293619b
Findings:          THREAT_MODEL.md F-14

Observed before the fix, by reading the bytes `/docs` returns: the page is a
~30-line shell whose `<script>` and stylesheet point at
`cdn.jsdelivr.net/npm/swagger-ui-dist@5/...`, its favicon at
`fastapi.tiangolo.com`, and `/redoc` additionally at `redoc@2` and Google
Fonts. No `integrity=` attribute anywhere. These are FastAPI's default
arguments; `create_app` never named them.

`@5` is a range, and it moved while the finding sat open: jsdelivr resolved it
to 5.33.1 when F-14 was written, and to 5.34.0 on 2026-10-21 -- three releases,
no commit here, nothing in `uv.lock`. That is the vulnerability in one line:
the script running beside a bearer token was chosen by someone else, today.

No network is used. The tests read what the app serves, which is the only thing
a browser would act on.
"""

import hashlib
import re
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient

from rlapi.app import SWAGGER_UI_DIR

pytestmark = [pytest.mark.attack, pytest.mark.mcp04]

#: Attributes through which an HTML page makes a browser fetch something.
FETCHING_ATTRS = frozenset({"src", "href", "srcset", "action", "data", "poster"})


class _References(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: ARG002  -- HTMLParser signature; every tag can fetch
        self.urls.extend(value for name, value in attrs if name in FETCHING_ATTRS and value)


def _references(html: str) -> list[str]:
    parser = _References()
    parser.feed(html)
    return parser.urls


def _is_same_origin(url: str) -> bool:
    # An absolute path. `//host/x` is protocol-relative -- another origin.
    return url.startswith("/") and not url.startswith("//")


def test_docs_page_references_no_external_origin(client: TestClient) -> None:
    html = client.get("/docs").text
    refs = _references(html)
    assert refs, "parser found no references at all -- the check would pass vacuously"
    assert [url for url in refs if not _is_same_origin(url)] == []
    # Belt and braces for the inline <script>: a URL built in JS is not an attribute.
    assert re.findall(r"(?:https?:)?//[\w.-]+\.\w+", html) == []


def test_every_docs_asset_is_served_locally(client: TestClient) -> None:
    """The availability half: the page renders with the CDN unreachable."""
    for url in _references(client.get("/docs").text):
        response = client.get(url)
        assert response.status_code == 200, url
        assert int(response.headers["content-length"]) > 0, url


def test_redoc_is_not_served(client: TestClient) -> None:
    """ReDoc pulled a second bundle plus Google Fonts. One docs UI is enough to own."""
    assert client.get("/redoc").status_code == 404


def test_oauth2_redirect_page_references_no_external_origin(client: TestClient) -> None:
    """Step 4's *Authorize* button lands here; it is also served by us, not a CDN."""
    response = client.get("/docs/oauth2-redirect")
    assert response.status_code == 200
    assert [url for url in _references(response.text) if not _is_same_origin(url)] == []


def test_online_validator_is_disabled(client: TestClient) -> None:
    """An egress self-hosting does not remove -- dormant here, pinned off anyway.

    Swagger UI defaults `validatorUrl` to `https://validator.swagger.io/validator`
    and its badge loads `<img src="{validatorUrl}?url={spec URL}">` unless the
    spec URL contains the substring `localhost` or `127.0.0.1`. Predicted from
    the bundle to leak on any real hostname; **refuted in Firefox**: no badge at
    `rlapi.test` even with the setting removed, because only `StandaloneLayout`
    (in `swagger-ui-standalone-preset.js`, which this page does not load)
    renders it. A layout switch would revive it silently, and the URL is built
    in JS, so the HTML-reference tests above could not see it -- only the config.
    """
    assert '"validatorUrl": null' in client.get("/docs").text


def test_vendored_assets_match_their_manifest() -> None:
    """The vendored bytes are what `scripts/vendor_swagger_ui.py` verified against npm.

    Catches a hand-edit, a partial refresh, and -- measured, not hypothetical --
    pre-commit's `end-of-file-fixer`: neither the bundle nor the CSS ends in a
    newline, so the fixer would rewrite both if the vendor directory were not
    excluded from it.
    """
    lines = (SWAGGER_UI_DIR / "SHA256SUMS").read_text().splitlines()
    assert lines, "empty manifest would pass vacuously"
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((SWAGGER_UI_DIR / name).read_bytes()).hexdigest() == digest, name
