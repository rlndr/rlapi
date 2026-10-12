# rlapi — secure MCP server build

A two-project learning track, built **break-then-fix**: a hardened CRUD API (`rlapi`), an
OAuth 2.1 authorization server (`rlas`), and an MCP server in front of them (`rlmcp`) that
is a proper OAuth 2.1 resource server. Each security step writes the vulnerability first,
proves it with an exploit, fixes it, then keeps the exploit as a regression test.

This file is the front door: how to run things. The thinking lives in four other documents,
listed at the bottom — **[PLAN.md](PLAN.md) is the source of truth for status and what to do
next.** Don't trust a status line here over that one.

> **Current status:** steps 0–2 complete, step 3 (local authorization server) is next.
> See [PLAN.md §0](PLAN.md) for the authoritative version.

---

## Setup

Requires [uv](https://docs.astral.sh/uv/) and Python 3.13 (pinned in `.python-version`).

```bash
uv sync                    # create .venv and install the workspace
uv run pre-commit install  # enable the secret-scanning hooks
```

`uv run <cmd>` always works without activating the venv, and syncs against `uv.lock` first.
The three packages in `packages/*` are installed **editable**, so source edits take effect
with no reinstall.

The dev database is gitignored and already exists locally. If `rlapi-dev.db` is missing:

```bash
cd packages/rlapi
RLAPI_DATABASE_URL="sqlite:///$PWD/../../rlapi-dev.db" uv run alembic upgrade head
```

That gives an **empty schema** — there is still no reusable seed script (tracked as an open
item in PLAN.md). The existing dev database holds 5 products and 4 orders and has been
hand-edited, so treat it as scratch, not a fixture. Nothing depends on its contents; the
tests build their own temp databases.

## Run the API

From the repository root:

```bash
RLAPI_DATABASE_URL="sqlite:///$PWD/rlapi-dev.db" \
  uv run uvicorn --factory rlapi.app:asgi_app_from_env --reload
```

Serves on <http://127.0.0.1:8000>. Three things about that command are load-bearing:

- **`RLAPI_DATABASE_URL` is not optional in practice.** The default in
  [`settings.py`](packages/rlapi/src/rlapi/settings.py) is the *relative* `sqlite:///rlapi.db`,
  so omitting the variable silently creates a new empty database in the current directory
  instead of failing. The `$PWD` makes the path absolute, which is why this must be run from
  the repository root.
- **`--factory` is required**, because the target is a callable that returns the app.
- **Use `asgi_app_from_env`, not `app_from_env`.** The first holds its engine for the
  process lifetime (what a server wants); the second is a context manager that disposes the
  engine, for scripts, and cannot be a uvicorn factory.

`create_app` runs `assert_hardened()` at startup, so an unhardened engine **fails to boot**
rather than serving writes that corrupt data. If the server refuses to start, suspect that
check before suspecting your config.

### Endpoints

| Path | What |
|---|---|
| `/healthz` | liveness — returns `{"status":"ok"}` |
| `/docs` | Swagger UI, interactive |
| `/redoc` | ReDoc — nicer for reading |
| `/openapi.json` | the raw OpenAPI 3.1.0 document |
| `/products`, `/products/{id}`, `/products/search` | product CRUD |
| `/orders`, `/orders/{id}`, `/orders/{id}/status` | order CRUD and status transitions |

There is **no authentication yet** — that is steps 4–6, and until then any caller can act
as any customer. The gap is deliberate and tracked, not overlooked.

To get the spec without starting a server (useful for diffing the contract in a commit):

```bash
RLAPI_DATABASE_URL="sqlite:///$PWD/rlapi-dev.db" uv run python -c "
import json
from rlapi.app import app_from_env
with app_from_env() as app:
    print(json.dumps(app.openapi(), indent=2))
" > openapi.json
```

This never opens the database — SQLAlchemy's `create_engine` is lazy.

## Check everything

Run all five before committing. The first four are the resume sanity check in PLAN.md §0;
`ruff format --check` is in the list because `ruff check` passes on code the formatter would
rewrite, and pre-commit runs the formatter — so a commit fails after the other checks are
green.

```bash
uv run pytest -q              # 91 passed
uv run pytest -m attack -q    # 39 passed, 52 deselected
uv run mypy                   # Success: no issues found in 24 source files
uv run ruff check .           # All checks passed
uv run ruff format --check .  # 30 files (24 .py + 6 .md)
```

Those counts are current as of 2026-10-12. The attack suite is the interesting one: each
test proves a specific vulnerability and must **fail to exploit** against fixed code.

Security tooling has its own runbook — **[SECURITYTEST.md](SECURITYTEST.md)** — with the
`ruff --select S` passes, how to audit `# noqa` suppressions, and the known blind spots.
Start there, not here, for anything security-flavoured.

## Layout

```
packages/rlapi/     CRUD API, owns the database (steps 1–6)
packages/rlas/      OAuth 2.1 authorization server (step 3+)
packages/rlmcp/     MCP server, protocol revision 2026-07-28 (steps 7–16)
tests/unit/         models, migrations, scaffold
tests/integration/  CRUD over a real app
tests/attacks/      exploit scripts kept as regression tests
```

Each package is a uv workspace member with its own `pyproject.toml`; the root one holds the
shared ruff / mypy / pytest configuration.

## Gotchas worth re-reading

Hard-won, in rough order of how likely each is to bite you again:

- **Don't browse the database with DBeaver carelessly.** It opens SQLite with
  `foreign_keys = 0`, so writes made there bypass step 1's integrity control and can create
  exactly the orphan rows the hardening defends against. Browse read-only, or issue
  `PRAGMA foreign_keys = ON` first. `journal_mode = WAL` *is* persisted in the file;
  `foreign_keys` is per-connection and is not. Full detail in PLAN.md.
- **`--reload` falls back to polling.** `watchfiles` is not installed, so uvicorn uses
  `StatReload` (mtime polling). It works, just slower and heavier; `uv add --dev watchfiles`
  fixes it. Drop `--reload` for anything production-like.
- **`/docs` loads Swagger UI from a public CDN**, unpinned and without an integrity hash —
  invisible to `uv.lock` and `pip-audit`. Recorded as `THREAT_MODEL.md` F-14, **open**, and
  it needs fixing before step 4 puts real tokens on that page.
- **The pre-commit hooks are bypassable** with `--no-verify`, and they are local-only.
  They also scan Markdown, so writing *about* a secret in these docs can trip
  `detect-secrets` — reword rather than widening the exclude pattern.

## The documents

| File | What it is | Updated |
|---|---|---|
| **[PLAN.md](PLAN.md)** | the build plan, step by step, plus "where we are" and open items | every step — **authoritative for status** |
| **[THREAT_MODEL.md](THREAT_MODEL.md)** | findings F-01…F-14: what was attacked, what actually stopped it, what was theater | every step |
| **[SECURITYTEST.md](SECURITYTEST.md)** | how to run the security checks; real commands with real output shapes | every step |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | components, trust boundaries, token flows | per phase |
| **README.md** | this file — how to run things | when a command or workflow changes |

Keep this file to *how to run it*. Reasoning, findings and status belong in the four above,
and duplicating them here just creates two answers that drift apart.
