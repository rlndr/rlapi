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

## Phase 2 — Identity
*(steps 3–6)*

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
