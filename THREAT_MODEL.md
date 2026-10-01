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
| F-01 | Secret committed via an ignored filename | `.gitignore` | — |
| F-01 | Secret committed via a *tracked* filename (`.py`) | `detect-private-key`, `detect-secrets`, ruff `S105` | `.gitignore` — matches names, not content |
| F-01 | Secret already in history | rotation | `git rm`, `filter-branch`; and `gc` only after `refs/original` + reflog were cleared |
