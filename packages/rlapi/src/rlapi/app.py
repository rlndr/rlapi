"""Application factory.

`create_app` takes a session factory rather than building one, so tests can
hand it an in-memory database and production can hand it a file. The engine
carries step 1's hardening with it either way.

`assert_hardened` runs at startup and raises. Failing to boot is the correct
response to an unhardened engine: the alternative is serving traffic that
writes corruption nobody notices until much later.
"""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from rlapi import __version__
from rlapi.db import assert_hardened, create_db_engine, create_session_factory
from rlapi.routes import orders, products
from rlapi.settings import database_url

SWAGGER_UI_DIR = Path(__file__).parent / "static" / "swagger-ui"
SWAGGER_UI_MOUNT = "/static/swagger-ui"


def _add_docs(app: FastAPI) -> None:
    """Serve Swagger UI from vendored assets (THREAT_MODEL.md F-14).

    FastAPI's defaults load it from `cdn.jsdelivr.net/npm/swagger-ui-dist@5`:
    a version range, no integrity hash, a third-party origin, on the page that
    holds bearer tokens from step 4. ReDoc is not re-added -- it pulled a second
    bundle and Google Fonts, and one docs UI is enough to keep current.

    `validatorUrl: None` closes a dormant path, not a live one. The bundle can
    send the spec URL to validator.swagger.io, but only `StandaloneLayout`
    renders that badge, and this page uses `BaseLayout` -- measured in Firefox,
    no badge with or without this setting. Kept because switching layouts would
    turn it on silently, and self-hosting would not stop it.
    """
    app.mount(SWAGGER_UI_MOUNT, StaticFiles(directory=SWAGGER_UI_DIR), name="swagger-ui")
    redirect_url = "/docs/oauth2-redirect"

    @app.get("/docs", include_in_schema=False)
    def swagger_ui() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=app.openapi_url or "/openapi.json",
            title=f"{app.title} - Swagger UI",
            swagger_js_url=f"{SWAGGER_UI_MOUNT}/swagger-ui-bundle.js",
            swagger_css_url=f"{SWAGGER_UI_MOUNT}/swagger-ui.css",
            swagger_favicon_url=f"{SWAGGER_UI_MOUNT}/favicon-32x32.png",
            oauth2_redirect_url=redirect_url,
            swagger_ui_parameters={"validatorUrl": None},
        )

    @app.get(redirect_url, include_in_schema=False)
    def swagger_ui_redirect() -> HTMLResponse:
        return get_swagger_ui_oauth2_redirect_html()


def create_app(session_factory: sessionmaker[Session], *, engine: Engine | None = None) -> FastAPI:
    """Build the API around an existing session factory."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if engine is not None:
            assert_hardened(engine)
        app.state.session_factory = session_factory
        yield

    app = FastAPI(
        title="rlapi",
        version=__version__,
        summary="CRUD over inventory and orders.",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    _add_docs(app)
    # Also set outside the lifespan: TestClient usage that never enters the
    # lifespan context still needs the factory present.
    app.state.session_factory = session_factory

    app.include_router(products)
    app.include_router(orders)

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


@contextmanager
def app_from_env() -> Iterator[FastAPI]:
    """Build an app against the database named by the environment, and dispose it.

    For scripts and ad-hoc use. `asgi_app_from_env` is the uvicorn entrypoint.
    """
    engine = create_db_engine(database_url())
    try:
        yield create_app(create_session_factory(engine), engine=engine)
    finally:
        engine.dispose()


def asgi_app_from_env() -> FastAPI:
    """Entrypoint for `uvicorn --factory rlapi.app:asgi_app_from_env`.

    Holds its engine for the process lifetime rather than disposing it, which
    is what a server wants and what makes this a separate function from
    `app_from_env` -- a context manager cannot be a uvicorn factory, since the
    factory must return the app itself.
    """
    engine = create_db_engine(database_url())
    return create_app(create_session_factory(engine), engine=engine)
