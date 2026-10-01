# Security testing runbook

How to run the security checks in this repo. Every command here has been run against this
workspace; output shapes are real, not illustrative.

**Scope today:** static analysis (ruff / flake8-bandit). The attack suite and dependency
scanning sections are stubbed and fill in as [PLAN.md](PLAN.md) progresses — see
[Coming later](#5-coming-later).

| Layer | Finds | Status |
|---|---|---|
| SAST — ruff `S` rules | taint-shaped and API-misuse-shaped defects in our code | **active** |
| Attack suite — `pytest -m attack` | authorization and protocol flaws SAST cannot see | from step 1 |
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
| `S608` | hardcoded-sql-expression | Step 2 — SQL injection in product search |
| `S105` `S106` `S107` | hardcoded-password string / arg / default | Step 0 (fired), step 3 AS secrets |
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
empirically rather than assume. Ruff is expected to catch step 2's SQL injection and
**none** of these:

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

## 5. Coming later

### Attack suite — from step 1

```bash
uv run pytest -m attack              # every exploit
uv run pytest -m mcp07               # one OWASP risk
uv run pytest -m "attack and mcp02"
```

Markers are declared in `pyproject.toml` (`mcp01`–`mcp10`, plus `attack`). Conventions and
the per-module header format are in [tests/attacks/README.md](tests/attacks/README.md). The
rule that gives these tests meaning: each must have been observed to **succeed** against
the vulnerable commit before the fix landed.

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
