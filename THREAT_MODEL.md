# Threat model

A running record, appended at each step in [PLAN.md](PLAN.md). Each entry states what was
attacked, what actually stopped it, and — where relevant — what control turned out to be
theater. The last column is the one worth being honest in.

Severity follows the rubric in PLAN.md: Critical / High / Medium / Low / Informational.

---

## Phase 0 — Foundations

### F-01 · Secrets reachable in git history
- **Severity:** High (if realised) · **Category:** DevSecOps
- **Attacked:** generated a throwaway RSA signing key — the artifact `rlas` will actually
  hold from step 3 — and tried four ways to get it committed, then tried to remove it.

**Prevention layers, as measured:**

| Attempt | `.gitignore` | pre-commit | Result |
|---|---|---|---|
| `git add .env` | **blocked** (`*.env`) | not reached | stopped |
| `git add .env packages/rlas/src/rlas/signing_key.pem` | **blocked** (`*.pem`) | not reached | stopped |
| `git add -f` the same two files | bypassed by `-f` | **blocked** by `detect-private-key` *and* `detect-secrets` | stopped |
| secrets inlined in `packages/rlas/src/rlas/dev_config.py` | **missed entirely** — `.py` is not an ignored pattern | **blocked** by `detect-private-key`, `detect-secrets`, and ruff `S105` ×2 | stopped |

The fourth row is the realistic one. `.gitignore` matches *names*, so it only ever catches
the filenames someone anticipated. A secret pasted into a legitimately-tracked source file
is invisible to it. Content-based scanning is the layer that generalises — and ruff's
`S105` caught the non-PEM secrets (`AS_CLIENT_SECRET`, a JWT-shaped token) that a
name-based rule never would.

**Remediation, as measured.** The interesting half. Committed with `--no-verify`, then:

| Remediation | Secret still retrievable? |
|---|---|
| `git rm --cached` + commit | **yes** — `git cat-file -p <blob>` returns it verbatim; `git log -p -S` occurrences went *up* from 1 to 2, since the removal commit shows the content as a deletion diff |
| `git filter-branch --index-filter` (full history rewrite) | **yes** — kept alive by `refs/original` and 8 reflog entries |
| `rm -rf .git/refs/original && git reflog expire --expire=now --all && git gc --prune=now` | no — blob finally unreachable |

- **Control that works:** rotation. A committed key is a compromised key, and three commands
  deep into remediation it was still readable. Everything above is damage limitation.
- **Residual risk:** every clone, fork, CI cache, and backup taken before the prune still
  has it, and no local command reaches those. Also: the hooks are local and bypassable with
  `--no-verify` (which is exactly how this demo committed the secret). Server-side scanning
  is the only layer that does not depend on developer cooperation — out of scope here since
  there is no remote, but recorded as the real gap.
- **Status:** controls in place and verified (`.gitignore`, `detect-private-key`,
  `detect-secrets`, ruff `S105`). No key material entered this repo's history —
  verified with `git log --all -p -S` for the PEM private-key header and each demo
  literal: 0 hits.

- **Footnote worth keeping.** Writing this entry tripped the controls it describes: quoting
  the PEM header literally in prose made `detect-private-key` and `detect-secrets` fail on
  `THREAT_MODEL.md` itself. Resolved by rewording, not by allowlisting — a documentation
  false positive is not worth an entry in `.secrets.baseline`, and widening the `exclude`
  pattern to cover Markdown would have blinded the hook to secrets pasted into docs, which
  is a real way they leak. Where a *fixture* legitimately trips a hook later, audit it into
  the baseline (`uv run detect-secrets audit .secrets.baseline`) so the decision is
  recorded, or use an inline `pragma: allowlist secret`.

### F-02 · SAST as an early signal
- **Severity:** Informational · **Category:** DevSecOps
- **Note:** ruff's `S` ruleset (flake8-bandit) is enabled workspace-wide. Several later
  steps introduce vulnerable code deliberately; ruff should flag much of it *before* the
  exploit is written. Where vulnerable code is committed on purpose it must carry an
  explicit `# noqa: S###  -- intentional, see PLAN.md step N`, so the suppression is
  auditable. An unexplained `noqa` is itself a finding.
- **Expectation to test later:** SAST will catch the SQL injection in step 2 (`S608`) but
  will **not** catch the IDOR in step 5, the audience-validation gap in step 4, or the
  state-handle hijack in step 12. Authorization flaws are invisible to pattern-matching
  linters. Worth confirming empirically rather than asserting.
- **Step 2 result — the SQLi half is CONFIRMED, with a caveat that matters more than the
  prediction.** Ruff flagged the search endpoint (F-11), and `RUF100` independently
  confirmed the rule was live by not reporting the `# noqa: S608` as unused. But the
  prediction was only right because the query happened to begin with `SELECT`: F-05 showed
  the rule covers four keywords, and F-08 showed the keyword must sit in the *same string
  expression* as the interpolation, so moving `SELECT` into a variable one line up hides the
  same bug completely. The mass-assignment half of step 2 (F-10) was flagged by **nothing**.
  Running total: of the two step-2 vulnerabilities, SAST found one.
- **Still open:** the step 4, 5 and 12 predictions.

---

## Phase 1 — The CRUD API

### F-03 · SQLite does not enforce foreign keys by default
- **Severity:** High · **Category:** AppSec / data integrity
- **Attacked:** inserted an `order_item` referencing order `99999`; deleted a product that
  order items referenced, with `ON DELETE RESTRICT` declared on the column.
- **Finding:** both succeeded. `PRAGMA foreign_keys` defaults to `0`, so every
  `ON DELETE CASCADE`/`RESTRICT` in the schema was decorative. A schema that reads as fully
  constrained was half enforced.
- **Control:** `PRAGMA foreign_keys = ON` applied from a SQLAlchemy `connect` event
  listener in `rlapi.db`, plus `assert_hardened()` as a startup check.
- **Two traps that make this easy to get wrong**, both verified:
  1. **The pragma is a no-op inside a transaction, and raises no error.** Setting it via
     `Session.execute` or `engine.execute` appears to succeed and changes nothing, because
     SQLAlchemy has already opened a transaction. This is why the `connect` event is the
     only correct hook — it fires before any transaction exists.
  2. **It is per *connection*, not per database.** Hardening once at startup leaves every
     subsequent pooled connection unprotected. Of the four hardening pragmas, only
     `journal_mode` persists in the database file; the other three reset on every connect.
- **Verified by removal:** with the listener commented out, exactly the 5 tests asserting
  hardened behaviour failed and the 9 asserting SQLite's defaults still passed. The control
  is load-bearing, not incidental.
- **Deliberate omission:** `create_db_engine` has **no** `enforce_foreign_keys=False`
  option. A flag that disables an integrity control is a footgun; the attack suite builds
  its own unhardened engine instead, so the shipped API cannot be misconfigured into the
  vulnerable state.
- **Tests:** `tests/attacks/test_fk_enforcement.py` (14)

### F-04 · `users.role` accepted arbitrary values
- **Severity:** High · **Category:** AppSec / IAM · **OWASP:** MCP07 (precursor)
- **Attacked:** wrote `'root'`, `'ADMIN'`, `'admin '`, `''`, `'customer,admin'` and a
  64-character string into the column that step 5's authorization will read.
- **Finding:** all accepted. Three compounding causes:
  1. **`SQLAlchemy.Enum.create_constraint` defaults to `False`** (since 1.4), so
     `Enum(Role)` emitted a bare `VARCHAR(8)` with no CHECK constraint at all.
  2. **SQLite ignores VARCHAR length.** A 64-character value went into `VARCHAR(8)`
     without complaint, so column width is never a control on SQLite.
  3. **The enum stored member *names*, not values** — `Role.CUSTOMER` landed as
     `'CUSTOMER'` while the API, the JWT `roles` claim and the codebase all say
     `'customer'`.
- **Why it matters beyond tidiness:** cause 3 is the dangerous one. A role column holding
  `'CUSTOMER'` while the token claim says `'customer'` fails a strict comparison — and
  whether that fails open or closed depends entirely on which side gets normalised. The
  `'admin '` variant is worse: it is not `== 'admin'`, but it survives a `TRIM()` or `LIKE`
  comparison and reads as `admin` in a log.
- **Control:** `rlapi.models.strict_enum()` — `create_constraint=True` for the DDL CHECK,
  `values_callable` to store values, `validate_strings=True` so the ORM rejects unknown
  strings before SQL is emitted. Two independent layers, since raw SQL and migrations
  bypass the ORM one.
- **Residual risk:** the CHECK constraint is a backstop. Step 5's authorization logic is
  the control, and it must still never trust this column's contents to be a valid `Role`
  without parsing it.
- **Tests:** `tests/attacks/test_role_column_integrity.py` (26)

### F-05 · ruff S608 misses most interpolated SQL — F-02's prediction, partly refuted
- **Severity:** Medium · **Category:** DevSecOps
- **Attacked:** probed which statement keywords `S608` recognises in an f-string.
- **Finding:** of `PRAGMA {name}`, `SELECT * FROM {name}`, `VACUUM {name}` and
  `ATTACH DATABASE '{name}' AS x`, **only `SELECT` was flagged.** `S608` matches on
  SELECT/INSERT/UPDATE/DELETE, so the other three pass clean — and `ATTACH DATABASE` is a
  file read/write primitive, arguably the most dangerous of the four.
- **Consequence here:** `rlapi.db.effective_pragmas` must interpolate a pragma name
  (pragmas take no bound parameters). Ruff reported nothing. The `_READABLE_PRAGMAS`
  allowlist is therefore a control **no linter will ever remind us to keep**, which is now
  stated in the code comment and covered by a test.
- **Correction to F-02:** that entry predicted ruff would "catch step 2's SQLi". Refine
  that: it catches *some* SQL injection, specifically statements whose first keyword is one
  of four. SAST coverage is narrower than the rule name suggests.
- **Tests:** `test_effective_pragmas_rejects_names_outside_the_allowlist`

### F-06 · Autogenerated migrations need review, not trust
- **Severity:** Low · **Category:** DevSecOps / data integrity
- **Finding:** `alembic revision --autogenerate` rendered each enum CHECK constraint
  **explicitly twice**, on top of the implicit one from `sa.Enum(create_constraint=True)`
  — three identical CHECK constraints per column in the emitted DDL. Functionally harmless,
  but it means autogenerate output is not a faithful translation of the models.
- **Control:** the redundant lines were removed by hand and the migration carries a note to
  re-check on every future autogenerate run. `tests/unit/test_migrations.py` asserts zero
  drift against `Base.metadata` via `compare_metadata`, plus exactly one CHECK per enum
  column and a working `downgrade base`.
- **Related risk recorded for later:** SQLite cannot `ALTER COLUMN`, so Alembic's
  `render_as_batch` rebuilds tables. A rebuild drops and recreates constraints, making
  batch migrations a moment when a CHECK or FK can silently go missing. Verify the schema
  after one; do not assume.

### F-07 · Alembic's default environment bypassed the hardening
- **Severity:** Medium · **Category:** AppSec / data integrity
- **Finding:** the generated `env.py` calls `engine_from_config` and builds its own
  connection, which never passes through `rlapi.db`'s `connect` listener. Data migrations
  would therefore have run with foreign key enforcement **off** — precisely the condition
  F-03 exists to prevent, in the one context that rewrites data in bulk.
- **Control:** `env.py` now builds its engine with `create_db_engine`. Migrations are held
  to the same integrity rules as the application.
- **Also changed:** the database URL moved out of `alembic.ini` into
  `$RLAPI_DATABASE_URL`. Harmless for a local SQLite path, but by step 18 that line would
  be a credential, and a test now asserts the ini pins no URL.

### F-08 · ruff S608 is defeated by splitting the query across two variables
- **Severity:** Medium · **Category:** DevSecOps
- **Attacked:** wrote the same injectable product search eight ways and ran `ruff --select
  S608` over all of them (ruff 0.16.9).
- **Finding:** **seven of eight were flagged** — f-string assigned to a variable, f-string
  inline in `text()`, `+` concatenation, `.format()`, `%`-formatting, an interpolated
  `ORDER BY` column, and `" AND ".join()` of a list containing an f-string. The one miss:

  ```python
  base = "SELECT id, sku, name, price_cents, stock_qty FROM products"
  session.execute(text(f"{base} WHERE name LIKE '%{q}%'"))  # not flagged
  ```

- **Why:** `S608` matches on the literal text of the string expression being interpolated.
  No dataflow. The f-string above contains no SQL keyword, so moving `SELECT` one line up
  into a variable makes the rule blind — while `ORDER BY {column}` *is* flagged, because
  `SELECT` is still in the same literal.
- **Why this is the bad case:** it is not an exotic evasion. Building a base query and
  appending optional clauses is the ordinary way an endpoint with filters is written, so
  the pattern SAST misses is the pattern a growing codebase drifts into.
- **Refines F-02 and F-05 a third time.** F-02 predicted ruff would catch step 2's SQLi; it
  did (see F-11). F-05 narrowed the rule to four statement keywords. F-08 narrows it again:
  the keyword must appear *in the same string expression as the interpolation*. A clean
  `S608` run means "no interpolation next to a SQL keyword", which is a much weaker claim
  than "no SQL injection".
- **Tests:** `tests/attacks/test_sqli.py::test_the_search_endpoint_no_longer_builds_sql_strings`
  asserts the absence over the AST and token stream rather than by substring search — a
  first attempt grepped the source and matched the module's own docstring discussing
  `text()`.

### F-09 · FK enforcement blocked PK reassignment, but only by accident
- **Severity:** Informational · **Category:** AppSec / control attribution
- **Attacked:** `PATCH /products/{id}` with `{"id": 9999}` against the vulnerable step-2
  code, on two products: one referenced by an order item, one not.
- **Finding:** the **referenced** product's update failed with `FOREIGN KEY constraint
  failed` (step 1's `ON DELETE RESTRICT` plus the pragma from F-03). The **unreferenced**
  product's primary key was reassigned without complaint.
- **Why it is not mitigation:**
  1. The API accepted the field and issued the `UPDATE`. The application-layer flaw was
     entirely present; the database caught the consequence.
  2. Coverage was "products that happen to have been ordered". *Has this row been
     referenced yet* is not a security boundary.
  3. It surfaced as an unhandled 500, not a 4xx.
- **Worth recording because** a half-passing exploit is the easiest kind of finding to
  misread as a control working. The planned exploit "partly failed", and the reason was a
  control from a different step firing for a reason nobody designed.
- **Now:** both cases return an identical 422 from the schema. Pinned by
  `test_referenced_product_is_now_protected_by_the_schema_not_the_database`, which asserts
  the two statuses are *equal* — so the outcome no longer depends on order history.

### F-10 · Mass assignment: clients wrote every server-owned field
- **Severity:** High · **Category:** AppSec · **OWASP:** MCP05 (MCP07 is the sharper fit)
- **Attacked:** one Pydantic model per entity used for input and output, spread into the
  ORM with `**payload.model_dump()`.
- **Findings, all confirmed by request:**
  | Payload | Result |
  |---|---|
  | `PATCH /products/1 {"id": 9999}` | primary key reassigned |
  | `POST /orders {"status": "shipped", "total_cents": 0}` | order created shipped and free |
  | `POST /orders {... "unit_price_cents": 1}` | 4950c product bought for 1c |
  | `PATCH /orders/1 {"total_cents": 0}` | existing order zeroed |
  | `PATCH /orders/1 {"status": "shipped"}` | draft → shipped, skipping placed and paid |
  | `PATCH /products/1 {"stok_qty": 0}` | **200, and nothing changed** |
- **The last row is the quiet one.** Pydantic v2 defaults to `extra="ignore"`, so a typo in
  a security-relevant field is a silent success. The caller is told it worked.
- **Control:** direction-specific models in `schemas.py` (`*Create` / `*Update` / `*Read`)
  where server-owned fields are **absent**, `extra="forbid"` on every input model via a
  shared `STRICT_INPUT`, and `total_cents` / `unit_price_cents` computed in the handler from
  the product row. `status` has no writable field at all: `PATCH /orders/{id}` was removed
  in favour of `POST /orders/{id}/status` gated by an explicit `ALLOWED_TRANSITIONS` table,
  because a field can express "a value from this enum" but not "draft may become placed but
  not shipped".
- **Verified by removal:** emptying `STRICT_INPUT` fails exactly 5 attack tests; bypassing
  the transition check fails exactly 2. No happy-path test fails in either case, so the
  controls reject only what they should.
- **Tests:** `tests/attacks/test_mass_assignment.py` (10)

### F-11 · SQL injection in the product search
- **Severity:** Critical · **Category:** AppSec · **OWASP:** MCP05
- **Attacked:** `GET /products/search?q=` built as
  `f"SELECT * FROM products WHERE name LIKE '%{q}%'"`.
- **Findings:**
  - `' UNION SELECT id, email, role, 0, 0 FROM users --` returned every user's email **and
    role**, serialised as products. UNION result columns are named by the first select, so
    emails arrived as `sku` and roles as `name`, and the response model accepted them —
    it constrains types, not provenance.
  - `' OR 1=1 --` returned the whole catalogue.
  - `' UNION SELECT 0, name, sql, 0, 0 FROM sqlite_master WHERE type='table' --` returned
    every table name and its DDL, turning blind injection into targeted injection.
  - A bare `'` raised an unhandled `OperationalError`, **and SQLAlchemy embeds the failed
    statement in the exception message**: `[SQL: SELECT * FROM products WHERE name LIKE
    '%'%']`. Any handler that echoes exception detail, or any log shipped somewhere less
    trusted than the database, hands over the column count rather than making an attacker
    guess it.
- **Control:** the endpoint is now an ORM `select()` with
  `Product.name.contains(q, autoescape=True)`. Parameterising the `text()` query would have
  stopped the injection; removing the string-building removes the shape of the bug, which
  is why that was preferred. Ruff flagged this one (`S608`) — confirming F-02's prediction —
  but see F-08 for what it would not have flagged.
- **Tests:** `tests/attacks/test_sqli.py` (7)

### F-12 · Bound parameters do not escape LIKE wildcards
- **Severity:** Low · **Category:** AppSec
- **Finding:** parameterisation stops injection but `%` and `_` remain LIKE metacharacters
  *inside* a bound value. A correctly parameterised `name LIKE :pattern` with `q="%"` still
  returns the entire catalogue, and `q="W_dget"` still matches `Widget`.
- **Why it matters:** this is not SQL injection, but it is the same end state as the `' OR
  1=1 --` tautology — a filter switched off by its own input. An endpoint that paginates on
  the assumption the filter narrows results is then trivially made to scan everything.
- **Control:** `.contains(q, autoescape=True)`.
- **Verified by removal:** dropping `autoescape=True` fails exactly one test,
  `test_like_wildcards_in_the_search_term_are_escaped`, and nothing else — so no other test
  was silently depending on it.

### F-13 · "Field absent" and `extra="forbid"` are two different controls
- **Severity:** Informational · **Category:** AppSec / control attribution
- **Attacked:** removed `extra="forbid"` from every input model and replayed
  `PATCH /products/{id}` with `{"id": 9999, "price_cents": 7}`.
- **Finding:** **the primary key did not move.** The response was 200, `price_cents` was
  applied, and `id` was dropped before the handler ever saw it, because `id` is not a field
  on `ProductUpdate` at all.
- **So the two controls do different jobs:**
  - **Field absence** prevents the write. This is the real control against mass assignment.
  - **`extra="forbid"`** prevents the *silence*. Without it the attempt is a 200 that looks
    like success.
- **Why worth a ledger entry:** the obvious reading of the inverted exploit test — it
  expects 422, 422 comes from `extra="forbid"` — credits the wrong control for the property
  that actually matters. Both are needed, for different reasons, and a future refactor that
  keeps one while dropping the other has not kept "the" fix.
- **Tests:** `test_input_schemas_do_not_expose_server_owned_fields` asserts the absence
  directly against the OpenAPI document, so re-adding `status` to `OrderCreate` fails
  immediately even if no exploit test covers that field.

### F-14 · `/docs` loads Swagger UI from a third-party CDN, unpinned and unverified
- **Severity:** Low today · High from step 4 · **Category:** Supply chain (MCP04) / AppSec
- **Found:** by reading the bytes `/docs` actually returns, rather than the page it draws.
  Not an attack — an inventory gap, which is why it surfaced during documentation work and
  not from the attack suite.

**Nothing in this repo renders the API documentation.** The `/docs` response is a ~30-line
HTML shell; the rendering is done by JavaScript fetched from a public CDN at page-view time:

| Asset | URL in the served HTML | Resolved to, when checked |
|---|---|---|
| Swagger UI JS | `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js` | 5.33.1 |
| Swagger UI CSS | `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css` | 5.33.1 |
| ReDoc JS (`/redoc`) | `cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js` | 2.5.4 |
| favicon | `fastapi.tiangolo.com/img/favicon.png` | — |

These are FastAPI's **default argument values**, not choices made here — see
`fastapi/openapi/docs.py` lines 79, 92 and 236 in the installed 0.142.2. `create_app` never
mentions them, which is exactly why they are easy to miss.

**What is wrong with it:**

- **The version floats.** `@5` is a major-version *range*, not a pin. jsdelivr answered
  `x-jsd-version: 5.33.1` with `cache-control: max-age=604800`, so the code executing in a
  browser can change — within 5.x, at the CDN's discretion — with no commit here, no
  lockfile diff, and nothing to review. Same for `redoc@2`.
- **No integrity check.** Grepping the served HTML for `integrity=` returns **0**. With no
  subresource-integrity hash the browser cannot detect substituted content, so the floating
  range and a CDN compromise are the same event from our side.
- **Invisible to this project's tooling.** `uv.lock` pins the Python tree and `pip-audit`
  reads the installed tree; neither knows these two files exist. §6 of `SECURITYTEST.md`
  says *"ruff reads our code, `pip-audit` reads everyone else's"* — the honest version is
  that `pip-audit` reads everyone else's **Python**. Browser assets referenced by a
  server-rendered page fall between both tools.
- **It is also an availability dependency.** Offline or with the CDN blocked, `/docs` is a
  blank shell. Confirmed: the HTML loads, the page renders nothing.

**Why the severity rises at step 4.** Today `/docs` is unauthenticated, the API has no auth
at all, and uvicorn binds `127.0.0.1` — third-party JS on that page can reach a local API
holding four dev orders, so the blast radius is close to nil. From step 4 the same page
becomes a credential-bearing surface: *Try it out* sends real bearer tokens, and
`swagger_ui_init_oauth` (FastAPI's `init_oauth`) puts OAuth client configuration into the
document itself. Arbitrary, unverified, silently-updating third-party script then shares an
origin with a page that holds tokens — MCP01 (Token Mismanagement) as much as MCP04. The
control must therefore land **before** step 4 wires auth into the docs page, not after.

- **Control:** *none yet — recorded, not fixed.* The fix is `docs_url=None` / `redoc_url=None`
  plus a local route calling `get_swagger_ui_html(swagger_js_url=..., swagger_css_url=...)`
  against self-hosted assets. Pinning to an exact version (`@5.33.1`) is strictly better than
  `@5` but keeps both the third-party origin and the availability dependency, so it is a
  stopgap, not the fix.
- **Residual risk after self-hosting:** the assets become *our* supply chain — vendored
  files age out of security updates, and nothing in `pip-audit` will mention them either.
  Whoever self-hosts owns a refresh cadence.
- **Worth noting about blame.** This is a framework default doing something reasonable for a
  getting-started experience and wrong for a resource server. No linter flagged it, no test
  covers it, and `/docs` worked perfectly throughout step 2 — the failure mode of a default
  is that it never asks to be reviewed.
- **Status:** open. Revisit at **step 4** (before `/docs` carries tokens) and **step 17**
  (dependency scanning).
- **Tests:** none yet. The cheap one needs no network: assert the `/docs` HTML references no
  external origin. It *fails today*, so it belongs with the fix rather than before it.

## Phase 2 — Identity
*(steps 3–6)*

## Phase 3 — The MCP server
*(steps 7–8)*

## Phase 4 — The MCP/API boundary
*(steps 9–11)*

## Phase 5 — The `2026-07-28` attack surface
*(steps 12–15)*

## Phase 6 — Operations
*(steps 16–18)*

---

## Control effectiveness ledger

Filled in as steps land. The question each row answers: *when the attack was run, what
actually stopped it?* Controls that stopped nothing get recorded too.

| # | Attack | Control that stopped it | Controls that did not help |
|---|---|---|---|
| F-01 | Secret committed via an ignored filename | `.gitignore` | — |
| F-01 | Secret committed via a *tracked* filename (`.py`) | `detect-private-key`, `detect-secrets`, ruff `S105` | `.gitignore` — matches names, not content |
| F-01 | Secret already in history | rotation | `git rm`, `filter-branch`; and `gc` only after `refs/original` + reflog were cleared |
| F-03 | Orphan `order_item`; deleting a referenced product | `PRAGMA foreign_keys = ON` via the `connect` event | the declared `ON DELETE RESTRICT`/`CASCADE` — inert without the pragma; setting the pragma in a transaction or once at startup |
| F-04 | Writing `'root'` / `'admin '` / 64 chars into `users.role` | `create_constraint=True` CHECK, plus ORM `validate_strings` | `VARCHAR(8)` — SQLite ignores length; `Enum(Role)` alone — emits no constraint |
| F-05 | Interpolated `PRAGMA` / `ATTACH DATABASE` | hand-written `_READABLE_PRAGMAS` allowlist | ruff `S608` — matches only SELECT/INSERT/UPDATE/DELETE |
| F-07 | Migrations running without FK enforcement | `env.py` using `create_db_engine` | Alembic's generated `env.py` |
| F-08 | Interpolated SQL with the `SELECT` held in a separate variable | nothing — ruff `S608` does not flag it | ruff `S608`; 7 of 8 other interpolation shapes *were* flagged |
| F-09 | `PATCH /products/{id}` reassigning a primary key (pre-fix) | `PRAGMA foreign_keys` — for referenced rows only, as a 500 | nothing else; unreferenced products were reassigned freely |
| F-10 | Writing `id` / `status` / `total_cents` / `unit_price_cents` from a request | fields **absent** from the input models (the write), `extra="forbid"` (the silence), server-side pricing, `ALLOWED_TRANSITIONS` | a shared input/output model; `extra="ignore"` — turns a typo into a silent 200 |
| F-10 | draft → shipped in one PATCH | removing the writable `status` field and the `PATCH /orders/{id}` route | enum validation — `shipped` is a valid value, just not a valid *transition* |
| F-11 | `UNION SELECT` exfiltrating `users.email` + `role`; `sqlite_master` recon; error-message oracle | ORM `select()` with no SQL string | the `ProductRead` response model — constrains types, not provenance |
| F-12 | `q="%"` returning the whole catalogue through a *parameterised* LIKE | `.contains(autoescape=True)` | bound parameters — stop injection, not wildcards |
| F-13 | `{"id": 9999}` with `extra="forbid"` removed | field absence from `ProductUpdate` — the write never happened | `extra="forbid"` — governs the 422, not the write |
| F-14 | Third-party JS executing on `/docs`, unpinned and unhashed | nothing — recorded, unfixed | `uv.lock` and `pip-audit` — neither sees browser assets; SRI absent, so the browser cannot check either |
