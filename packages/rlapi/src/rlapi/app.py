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

from fastapi import FastAPI
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from rlapi import __version__
from rlapi.db import assert_hardened, create_db_engine, create_session_factory
from rlapi.routes import orders, products
from rlapi.settings import database_url


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
    )
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
