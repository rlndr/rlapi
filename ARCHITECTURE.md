# Architecture

Status: **step 0 baseline.** Components are declared here before they exist; each phase in
[PLAN.md](PLAN.md) amends this file as it lands. Treat anything marked *(planned)* as a
design commitment, not a description of running code.

## 1. Components

| Component | Package | Role | Status |
|---|---|---|---|
| `rlapi` | `packages/rlapi` | CRUD API over inventory/orders. OAuth 2.1 **resource server**. Owns the database. | *(planned, steps 1–6)* |
| `rlas` | `packages/rlas` | OAuth 2.1 **authorization server**. Issues and exchanges tokens. Replaced by Keycloak in step 18. | *(planned, step 3)* |
| `rlmcp` | `packages/rlmcp` | MCP server, revision `2026-07-28`. OAuth 2.1 **resource server** to the client, OAuth 2.1 **client** to `rlapi`. | *(planned, steps 7–16)* |

`rlmcp` holds no data. It is a protocol adapter with an authorization decision point. Every
fact it returns comes from `rlapi`.

## 2. Trust boundaries

```
   ╔═══════════════╗   ╔═════════════════════╗   ╔══════════════════════╗
   ║  Zone H       ║   ║  Zone M             ║   ║  Zone A              ║
   ║  Host + LLM   ║   ║  rlmcp              ║   ║  rlapi + SQLite      ║
   ║               ║   ║                     ║   ║                      ║
   ║  UNTRUSTED    ║──▶║  SEMI-TRUSTED       ║──▶║  AUTHORITATIVE       ║
   ║  model output ║ 1 ║  enforces authz,    ║ 2 ║  enforces authz      ║
   ║  is attacker- ║   ║  holds no data      ║   ║  independently,      ║
   ║  influenced   ║   ║                     ║   ║  owns the data       ║
   ╚═══════════════╝   ╚═════════════════════╝   ╚══════════════════════╝
            │                     │                         │
            │  aud=rlmcp          │  aud=rlapi              │
            │  Bearer JWT         │  Bearer JWT             │
            │                     │  (RFC 8693 exchange)    │
            └─────────────────────┴─────────────────────────┘
                                  │
                        ╔═════════▼═══════════╗
                        ║  Zone I  —  rlas    ║
                        ║  issues all tokens  ║
                        ║  signing key = the  ║
                        ║  crown jewel        ║
                        ╚═════════════════════╝
```

**Boundary 1 — client → `rlmcp`.** Authentication: OAuth 2.1 bearer token, `aud=rlmcp`,
validated against `rlas`'s JWKS. Authorization: scope gate per tool, then row and field
gates derived from the token's `sub`.

The defining assumption: **everything crossing boundary 1 is attacker-influenced.** Tool
arguments are chosen by a model whose context may contain text written by a hostile user
(see MCP06 in step 15). The authenticated *principal* is trustworthy because the token is
cryptographically bound to it; the *arguments* never are. This is the asymmetry the whole
design rests on.

**Boundary 2 — `rlmcp` → `rlapi`.** Authentication: a *different* token, `aud=rlapi`,
obtained by RFC 8693 token exchange, carrying the original end user as `sub` and downscoped
to the single operation in flight. `rlmcp` never forwards the token it received —
the MCP specification forbids it, and audience validation at `rlapi` enforces it.

**Boundary 3 — both services → `rlas`.** Outbound JWKS and metadata fetches. These make
both services HTTP *clients*, which puts them in SSRF scope (step 17).

## 3. Principals

| Principal | Authenticates with | Identified by |
|---|---|---|
| End user (`customer`/`clerk`/`manager`/`admin`) | Authorization code + PKCE at `rlas` | `sub` claim |
| MCP client application | `client_id` via Client ID Metadata Document | `client_id` claim |
| `rlmcp` as a service | Its own credential at `rlas`, for token exchange only | `client_id` |

Note the deliberate absence: **no service account with standing access to `rlapi`.** Step 9
builds one specifically to demonstrate why it is a confused-deputy hazard, then removes it.

## 4. Authorization model

Three gates, independently testable, applied in order. Conflating them is the most common
real-world failure.

1. **Scope gate** — *may this operation be performed at all with this token?*
   Derived from the token's `scope` claim. Answers 403 `insufficient_scope`.
2. **Row gate** — *may this subject reach this specific row?*
   Expressed as a query filter, so unauthorized rows are never loaded. Answers 404
   (not 403 — a 403/404 split leaks row existence; see step 5).
3. **Field gate** — *which attributes of this row may this subject see?*
   A response projection per role.

Both `rlmcp` and `rlapi` run all three. Two policy decision points, one policy definition.
Step 11 asserts they agree by replaying step 5's role × operation matrix through the MCP
tool surface.

## 5. Protocol posture (`2026-07-28`)

Revision-specific decisions, with the security reason for each:

| Decision | Reason |
|---|---|
| Streamable HTTP for real deployment; stdio only for step 7 | The SDK applies authorization **only** to HTTP transports. stdio has no `Authorization` header; there the process boundary is the security boundary. |
| `validate_token_resource=True`, always | Without it, `rlmcp` accepts tokens minted for other resources — the forbidden passthrough case. Step 17 makes startup fail if this is off. |
| State handles bound server-side as `<user_id>:<handle>` | The revision removed sessions; handles now arrive as ordinary tool arguments. Possession MUST NOT imply authentication. |
| `requestState` signed or server-side | Under MRTR it round-trips through the client, so it is attacker-controlled input. |
| Headers validated against body | `Mcp-Method`/`Mcp-Name` let intermediaries police traffic; disagreement with the body is a split-brain authorization risk. `HeaderMismatchError` = `-32020`. |
| `cacheScope: "private"` for anything subject-specific | `"public"` permits shared intermediaries to serve one user's data to another. |
| Not adopted: Roots, Sampling, Logging, HTTP+SSE, Dynamic Client Registration | All Deprecated in this revision. Client registration uses Client ID Metadata Documents. |

## 6. Failure modes

What an attacker gets from compromising each component. This table is the point of the
two-service split — if any row reads "everything", the architecture has failed.

| Compromised | Attacker gains | Contained by |
|---|---|---|
| MCP client / host | One user's scopes, for that token's ~10 min lifetime | Short TTL; audience binding; scope minimization |
| `rlmcp` | Ability to request exchanged tokens for *authenticated* users only, downscoped per call. **Not** blanket API access. | `rlapi`'s independent authz; no standing service credential; exchange scope limits |
| `rlapi` | Full database read/write | Nothing above it — this is the authoritative zone, which is why it is the smallest and most-tested component |
| `rlas` signing key | Mint any token for any user at any audience: total compromise | Key never leaves the AS; short token TTL limits replay only, not forgery. **This is the crown jewel.** |

## 7. Out of scope

Deliberate omissions, recorded so they are choices rather than oversights:

- **Transport crypto for real.** Steps 1–16 run on loopback HTTP. TLS arrives in step 17.
  Until then, bearer tokens cross the loopback interface in cleartext.
- **Rate limiting / DoS.** Not modelled.
- **Multi-tenancy.** Single logical tenant; `customer_id` segregation is row-level authz,
  not tenant isolation.
- **Secret management.** Local files and environment variables, with the exposure documented
  in step 7's `/proc/<pid>/environ` finding. No KMS or vault.
- **Host-side consent UX.** The MCP host owns user consent; we can only annotate tools and
  must assume annotations are hints, never controls.
