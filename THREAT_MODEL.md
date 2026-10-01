# Threat model

A running record, appended at each step in [PLAN.md](PLAN.md). Each entry states what was
attacked, what actually stopped it, and — where relevant — what control turned out to be
theater. The last column is the one worth being honest in.

Severity follows the rubric in PLAN.md: Critical / High / Medium / Low / Informational.

---

## Phase 0 — Foundations

### F-01 · Secrets reachable in git history
- **Severity:** High (if realised) · **Category:** DevSecOps
- **Attacked:** committed a file containing a signing key, then tried to remove it.
- **Finding:** `.gitignore` and `detect-secrets` are **preventative only**. Once an object
  reaches the database it is reachable via `git log -p`, `git cat-file`, reflogs, and any
  clone or fork that already pulled it. `git rm` does not remove it; history rewriting does
  not remove it from existing clones.
- **Control that works:** rotation. A committed key is a compromised key. The pre-commit
  hook reduces the *rate* of this incident; it cannot remediate one.
- **Residual risk:** a hook is bypassable with `--no-verify`, and only runs locally. Server-
  side scanning is the control that does not depend on developer cooperation. Not in scope
  here (no remote), but noted as the gap.
- **Status:** control in place (`detect-private-key`, `detect-secrets`, `.gitignore`).

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
*(steps 1–6; entries added as each lands)*

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
| F-01 | Secret in git history | — (rotation only) | `.gitignore`, pre-commit hook (both preventative) |
