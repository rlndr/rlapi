# Security testing runbook

How to run the security checks in this repo. Every command here has been run against this
workspace; output shapes are real, not illustrative.

**Scope today:** static analysis (ruff / flake8-bandit) and the attack suite. Dependency
scanning fills in at step 17 — see [Coming later](#5-coming-later).

| Layer | Finds | Status |
|---|---|---|
| SAST — ruff `S` rules | taint-shaped and API-misuse-shaped defects in our code | **active** |
| Attack suite — `pytest -m attack` | authorization and protocol flaws SAST cannot see | **active** (step 1) |
| SCA — `pip-audit` | known CVEs in dependencies | from step 17 |
| Secret scanning — pre-commit | credentials heading for a commit | **active** (see `THREAT_MODEL.md` F-01) |

---

## 1. Quick reference

```bash
# Security-only pass over the workspace
uv run ruff check --select S .

# Summary by rule — best first look
uv run ruff check --select S --statistics .

# Audit every suppression: reports findings even where a # noqa silences them
uv run ruff check --select S --ignore-noqa .

# Explain any rule
uv run ruff rule S608

# Scope to one package
uv run ruff check --select S packages/rlmcp

# Ignore repo config entirely (see gotcha 2)
uv run ruff check --isolated --select S tests/

# Machine-readable for CI or a dashboard
uv run ruff check --select S --output-format sarif -o ruff-sast.sarif .
```

Exit codes: `0` clean, `1` findings. `--output-format` still exits `1` when it writes
findings to a file, so CI treats a non-empty report as a failure without extra wiring.

Available formats: `concise, full, json, json-lines, junit, grouped, github, gitlab,
pylint, rdjson, azure, sarif`. SARIF output is 2.1.0 and contains only the rules that
fired, not the whole catalogue.

### List what is available

```bash
# All 73 flake8-bandit rules ruff implements
uv run ruff rule --all --output-format json \
  | python3 -c "import json,sys; [print(r['code'], r['name']) for r in json.load(sys.stdin) if r.get('linter')=='flake8-bandit']"
```

## 2. How SAST is wired in

`S` (flake8-bandit, 73 rules) is in `select` in [pyproject.toml](pyproject.toml), so it is
**not** an opt-in extra pass:

- `uv run ruff check` includes it, as part of ordinary linting.
- `uv run pre-commit run --all-files` includes it, via the `ruff-check` hook.
- Every `git commit` includes it, on staged files.

`--select S` only *narrows output* to security findings. Useful for a deliberate review,
but understand that a clean security run is already a precondition of committing.

### Rules that matter in this project

Of the 73, these are the ones the plan is expected to trip. Use this as the "is my control
working" index — if a step lands and its rule never fired, check why.

| Rule | Name | Expected at |
|---|---|---|
| `S608` | hardcoded-sql-expression | **Confirmed step 2** — fired on the product-search f-string. **Narrower than it looks:** the statement keyword must sit in the *same string expression* as the interpolation (see §4) |
| `S105` `S106` `S107` | hardcoded-password string / arg / default | **Confirmed step 0.** Step 3 AS secrets |
| `S104` | hardcoded-bind-all-interfaces | Step 8 — binding `rlmcp` to `0.0.0.0` |
| `S311` | suspicious-non-cryptographic-random | Step 12 — state handles built with `random` |
| `S113` | request-without-timeout | Step 9 — JWKS / token-exchange fetches |
| `S501` `S323` | no cert validation / unverified SSL context | Step 17 — TLS |
| `S310` | suspicious-url-open-usage | Step 17 — SSRF on OAuth metadata fetches |
| `S324` `S303` | insecure hash function | Steps 11, 16 — `arguments_hash` |
| `S505` | weak-cryptographic-key | Step 3 — RSA key size for the AS signing key |
| `S110` `S112` | try-except-pass / -continue | Anywhere a failed authz check gets swallowed |
| `S602`–`S607` | subprocess / shell | Step 11, if any tool ever shells out |

`S101` (assert) matters only in that it is exempted under `tests/**`.

## 3. Gotchas

Both of these were found by testing, not by reading docs.

### Gotcha 1 — `# noqa` must sit on the line the diagnostic points at

The plan commits deliberately vulnerable code, suppressed with
`# noqa: S###  -- intentional, see PLAN.md step N`. Placement is load-bearing.

**Does not suppress** — the diagnostic is on the f-string line, not the call line:

```python
return conn.execute(  # noqa: S608   <- ignored
    f"SELECT * FROM products WHERE sku = '{q}'"
)
```

**Does suppress:**

```python
return conn.execute(
    f"SELECT * FROM products WHERE sku = '{q}'"  # noqa: S608  -- intentional, step 2
)
```

The failure is in the safe direction — you see a finding you thought you had silenced,
rather than losing one — but it means a suppression you believe is active may not be.
`--ignore-noqa` is how you check: on a three-case probe it reported 1 finding normally and
3 with the flag, confirming two were genuinely suppressed.

### Gotcha 2 — `tests/**` is a partial SAST blind spot, deliberately

`[tool.ruff.lint.per-file-ignores]` exempts `S101`, `S105`, `S106`, `S311` and `ANN` under
`tests/**`, because an attack script cannot be written without asserts, fake credentials
and generated input.

**These per-file-ignores still apply when you pass `--select S` on the command line.** A
probe file under `tests/` containing a hardcoded secret and `random.randint` reported only
`S608`; `S105` and `S311` were silently exempt. `--per-file-ignores=''` does not clear them
(it rejects an empty value). To audit tests fully, bypass config:

```bash
uv run ruff check --isolated --select S tests/
```

That reported both suppressed findings. Occasionally useful; too noisy as a default.

## 4. Per-step workflow

Run at the end of each step in PLAN.md.

```bash
# 1. Unsuppressed findings — must be zero to commit
uv run ruff check --select S .

# 2. Inventory of deliberate weaknesses: the gap between these two numbers
uv run ruff check --select S --ignore-noqa . | grep -c '^S' || true
uv run ruff check --select S .              | grep -c '^S' || true

# 3. Every suppression justified? Each must name a PLAN.md step
grep -rn 'noqa: S' packages/ tests/
```

`THREAT_MODEL.md` F-02 records the rule that an **unexplained `noqa` is itself a finding**.
Step 3 is how that gets enforced — nothing else checks it.

### What ruff cannot find

The limits matter more than the coverage, and F-02 records this as a prediction to confirm
empirically rather than assume.

**Confirmed at step 1 — `S608` is much narrower than its name suggests.** Probing which
statement keywords it recognises inside an f-string:

| Interpolated statement | Flagged? |
|---|---|
| `f"SELECT * FROM {name}"` | yes |
| `f"PRAGMA {name}"` | **no** |
| `f"VACUUM {name}"` | **no** |
| `f"ATTACH DATABASE '{name}' AS x"` | **no** |

`S608` matches on SELECT/INSERT/UPDATE/DELETE. Everything else passes clean — including
`ATTACH DATABASE`, which is a file read/write primitive. This bit in real code:
`rlapi.db.effective_pragmas` must interpolate a pragma name (pragmas take no bound
parameters) and ruff reported nothing, so its `_READABLE_PRAGMAS` allowlist is a control
**no linter will ever remind us to keep**. Recorded as `THREAT_MODEL.md` F-05.

**Confirmed again at step 2 — the keyword must be in the same string expression.**
Eight injectable spellings of the *same* product search, ruff 0.16.9:

| How the query is built | Flagged? |
|---|---|
| `sql = f"SELECT ... LIKE '%{q}%'"`, then `text(sql)` | yes |
| `text(f"SELECT ... LIKE '%{q}%'")` inline | yes |
| `text("SELECT ... LIKE '%" + q + "%'")` | yes |
| `text("SELECT ... '%{}%'".format(q))` | yes |
| `text("SELECT ... '%%%s%%'" % q)` | yes |
| `text(f"SELECT * FROM products ORDER BY {column}")` | yes |
| `text("SELECT ... WHERE " + " AND ".join([..., f"name LIKE '%{q}%'"]))` | yes |
| `base = "SELECT ... FROM products"`; `text(f"{base} WHERE name LIKE '%{q}%'")` | **no** |

Seven of eight. The miss is the one that matters: `S608` matches the literal text of the
string being interpolated and does no dataflow, so holding the `SELECT` in a variable one
line up makes it blind — while `ORDER BY {column}` *is* flagged, because `SELECT` is still
in the same literal. That is not an exotic evasion; a base query plus appended optional
clauses is how a filterable endpoint is ordinarily written. Recorded as F-08.

Reproduce it: the eight-variant probe is reconstructible from the F-08 table, and
`--select S608 --isolated` over a scratch file is the whole method.

Take-away for the rest of the project: do not read a clean `--select S` run as "no
injection". Read it as "no injection where ruff can see a SQL keyword next to an
interpolation".

**Step 2's scorecard: two vulnerabilities, SAST found one.** It flagged the SQL injection
(F-11) and said nothing whatsoever about the mass assignment (F-10) — no rule covers
"this Pydantic model lets a client write a field the server owns". Ruff caught none of
these either:

- **Step 4** — audience validation gap. `jwt.decode(token, key)` without `audience=` is a
  syntactically correct API call.
- **Step 5** — IDOR / BOLA. The vulnerable and correct queries are structurally identical;
  the difference is a missing `WHERE customer_id = ?`.
- **Step 9** — token passthrough / confused deputy. An architectural property, not a code
  pattern.
- **Step 10** — scope over-publication in `scopes_supported`.
- **Step 12** — state handle *binding*. Ruff catches weak randomness (`S311`); it cannot
  see a missing ownership check.
- **Steps 13, 14** — `requestState` tampering, header/body mismatch.

Pattern-matching SAST finds taint-shaped and API-misuse-shaped defects. **Authorization
flaws are invisible to it**, because vulnerable code looks exactly like correct code minus a
comparison against state the linter has no model of. That is why `tests/attacks/` exists.

## 5. The attack suite

Active since step 1. This is the layer that covers what §4 says SAST cannot.

```bash
uv run pytest -m attack              # every exploit
uv run pytest -m mcp07               # one OWASP risk
uv run pytest -m "attack and mcp02"
uv run pytest                        # everything
```

Current counts (step 2): **91 tests, 39 marked `attack`.** Breakdown:

Note the two numbers are easy to confuse: `pytest tests/attacks/ -q` reports **54**,
because the step-1 modules also hold tests asserting SQLite's *unhardened* defaults,
which are not themselves exploits and carry no `attack` marker. `pytest -m attack` is
the number that means "exploits".


| Module | Covers | `THREAT_MODEL.md` |
|---|---|---|
| `attacks/test_fk_enforcement.py` | SQLite FK enforcement off by default; pragma no-op in a transaction; per-connection scope | F-03 |
| `attacks/test_role_column_integrity.py` | `users.role` accepting arbitrary values; enum stored as name vs value | F-04 |
| `unit/test_models.py` | CHECK-constraint backstops for negative money/quantities | F-03/F-04 support |
| `attacks/test_mass_assignment.py` | client writing `id` / `status` / `total_cents` / `unit_price_cents`; unknown fields silently ignored; status skipping the workflow | F-09, F-10, F-13 |
| `attacks/test_sqli.py` | `UNION SELECT` exfiltration, `sqlite_master` recon, error-message oracle, LIKE-wildcard abuse, absence of raw SQL | F-08, F-11, F-12 |
| `integration/test_crud.py` | the endpoints still working — the half that catches a "fix" which rejects everything | — |
| `unit/test_migrations.py` | migration/model drift, reversibility, no pinned DB URL | F-06, F-07 |

### Proving a control is load-bearing

A test that has never failed against vulnerable code proves nothing. Two ways to establish
that, both used at step 1:

1. **Keep the vulnerable configuration as a fixture.** `test_fk_enforcement.py` has both
   `hardened_engine` and `unhardened_engine` and asserts opposite outcomes against each, so
   the contrast is permanent rather than historical.
2. **Remove the control and watch the right tests fail.** Comment out the one line that
   registers the hardening listener and re-run:

   ```bash
   uv run pytest tests/attacks/test_fk_enforcement.py -q
   ```

   At step 1 this produced exactly `5 failed, 9 passed` — the 5 asserting hardened
   behaviour, with the 9 asserting SQLite's *defaults* correctly unaffected. If removing a
   control does not break anything, the control is untested.

**Step 2's three measurements**, each by editing one thing and running the whole suite
(90 tests at the time):

| Control removed | How | Result |
|---|---|---|
| `extra="forbid"` | `STRICT_INPUT = ConfigDict()` in `schemas.py` | `5 failed, 85 passed` |
| LIKE escaping | drop `autoescape=True` from `.contains()` | `1 failed, 89 passed` |
| Status transition table | replace the guard with `if False:` | `2 failed, 88 passed` |

**No happy-path test failed in any of the three**, which is the half of the measurement
that is easy to skip: it shows each control rejects only what it should, rather than
passing its exploit test by being broadly restrictive.

**One removal was more informative than the test it broke.** Emptying `STRICT_INPUT` fails
`test_product_id_is_not_an_accepted_input_field`, which reads as "`extra="forbid"` stops
primary-key reassignment". It does not. Replaying the request with the control gone shows a
**200 and the primary key unmoved** — `id` is not a field on `ProductUpdate`, so Pydantic
drops it before the handler runs. Field *absence* prevents the write; `extra="forbid"`
prevents the silent 200. Two controls, two different jobs, one test that looked like it
covered both. Recorded as F-13, and now pinned separately by
`test_input_schemas_do_not_expose_server_owned_fields`, which asserts against the OpenAPI
document instead of a payload.

The general lesson for later steps: when a removal makes a test fail, confirm the
vulnerability is actually back, not just that the assertion is unhappy.

Markers are declared in `pyproject.toml` (`mcp01`–`mcp10`, plus `attack`). Conventions and
the per-module header format are in [tests/attacks/README.md](tests/attacks/README.md).

## 6. Coming later

### Dependency scanning — from step 17

```bash
uv run pip-audit                                  # installed tree
uv run pip-audit --strict --desc
uv sync --locked                                  # verify lockfile is authoritative
```

`pip-audit` is already a dev dependency. Note it answers a different question from ruff:
ruff reads our code, `pip-audit` reads everyone else's.

### Type checking as a security control

```bash
uv run mypy
```

Not a security tool, but `--strict` over `packages/` and `tests/` catches the
`Optional`-handling mistakes that turn into auth bypasses — an unchecked `None` from a
token verifier being the obvious one.

---

## Maintenance

This file is updated as each step in PLAN.md lands. When updating:

- Only document commands that have actually been run here. Note real exit codes and output
  shapes.
- When a rule in the §2 table fires for the first time, mark it confirmed.
- When a predicted blind spot in §4 is confirmed or refuted, update it and record the
  result in `THREAT_MODEL.md` F-02.
