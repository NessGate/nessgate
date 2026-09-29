# Proposal — promote the Connection-Readiness layer toward production

Status: **STAGES 1 + 2 IMPLEMENTED (working tree; not committed, not deployed).** Date: 2026-09-27.

## Implementation status (Stage 2 — the connection plan)

The client-matched verdict, additive on top of Stage 1:

- **Library** (`public/resolver.mjs` → `packages/resolver/index.mjs`, version → **1.14.0**): pure `matchClient(readiness, entry)`
  (deterministic tri-state intersection — a fact, not a score) + `canonClientProtocol` + IO `plan(domain, clientCaps, opts)`
  returning `{ outcome, connection, alternatives, compatibility, unmatched }`.
- **Hosted**: `POST /connect/{domain}` with a body `{ client: { supports:[{protocol,versions?,transports?,auth?}], prefer? } }`.
  Discovers via the `/explore` path (delegation + federation, reusing its cache + rate limit), matches, assesses readiness of
  the matches, returns one outcome. `no-store` (client-specific). `matchClient`/`canonClientProtocol` are byte-identical to the
  library (parity-tested). Reuses the bounded, SSRF-guarded `readinessForResource` — no new fetch primitive.
- **Gate**: `test-readiness-checker.mjs` now 59 checks (adds matcher parity + outcome cases).
- **Verified live** (`wrangler dev`): MCP client → supabase → `credentials-required` (endpoint + oauth2 + token URL); a
  UCP-only client → `no-compatible-method` with `unmatched.serviceOffered`/`clientOnly` populated; `GET /connect` → helpful 405.

**Audit (B):** neutral (no scores); client caps are input-only (nothing stored); `/connect` inherits the explore rate-limit and
adds no new outbound-fetch primitive; bounded by `READINESS_MAX` + `READINESS_DEADLINE_MS`. Note: cold `/connect` = explore
time + readiness time (~≤ explore + 17s) — acceptable for an opt-in endpoint; a warm explore cache makes it fast.

---


## Implementation status (Stage 1 — the readiness checker)

Landed as a strictly additive, opt-in feature; the default `/discover`, default `/explore`, and default
`resolve()` outputs are byte-unchanged (proven: `test.mjs` + `test-v2.mjs` pass; live plain `/explore` carried
no readiness field).

- **Library** (`public/resolver.mjs`, byte-mirrored to `packages/resolver/index.mjs`, version → 1.13.0):
  pure assessors `assessOpenApiReadiness` / `assessA2aReadiness` / `assessMcpReadiness` / `readinessProtocol` /
  `extractProtocolVersion`, plus IO `assessReadiness(resource, {fetch})` and an opt-in `resolve(domain,{readiness:true})`.
- **Hosted** (`src/worker.js`): `GET|POST /explore?readiness=1` attaches a `readiness` block per connectable
  resource. The five pure assessors are byte-identical to the library (parity-tested); the fetch IO reuses the
  worker's SSRF guards (`isForbiddenHost` + `assertPublicDns`, HTTPS-only). Bounded to `READINESS_MAX=4` unique
  endpoints; unique-URL dedup; the flag is part of the cache key.
- **Gate**: `scripts/test-readiness-checker.mjs` (44 checks — worker/library parity, outcomes, the full MCP
  OAuth chain against a mock fetch, SSRF-guard, neutrality) wired into `npm run check` and `npm run test:readiness`.
- **Verified live** via `wrangler dev`: `mcp.supabase.com/mcp → credentials-required` with the token/authorize
  endpoints resolved through the RFC 9728→8414 chain *inside the worker*; plain `/explore` unchanged.

**Audit:** additive-only; byte-parity holds (packages == public; worker↔library pure fns parity-tested); no
scores (enums + `missing[]`); every readiness fetch is SSRF-guarded; no credential/Authorization header is ever
sent; full offline gate (10 scripts) green.

**Deliberate scope decision on gate #2 (fixtures):** the permanent regression corpus for readiness lives in
`scripts/test-readiness-checker.mjs` (deterministic, in the gate). The `compat/` JSON-fixture harness is
normalization-document-shaped; adding a new `readiness` fixture kind would require extending `contract.mjs` +
`test-compat.mjs` — deferred as a follow-up to avoid harness surgery in the same change.

**Not done (correctly gated / owner actions):** committing, deploying, publishing npm 1.13.0, the live
`smoke`/prod-equality checks (need a deploy), and a charter read-scope confirmation for one-hop OAuth-metadata
following (§3). Stage 2 (`POST /connect` + library `plan()`) remains future work.

---

_Original proposal follows._

Scope prior to implementation: an ADDITIVE readiness layer on top of the existing resolver. Date: 2026-09-26.
Scope: an ADDITIVE readiness layer on top of the existing resolver. No change to `/discover`, the current
`/explore` contract, the npm library's default behavior, or the active Charter is proposed here.

## 1. What was tested and what it showed

A four-stage pipeline was prototyped entirely under `lab/connection-plan/`:

```
discover / explore  →  compatibility match (client caps × service surfaces)
                    →  fill connection details (safe read-only metadata following)
                    →  safe handshake
                    →  ONE outcome: ready | credentials-required | incomplete | no-compatible-method
```

**It works, end-to-end, on real services, and stays honest.** Proven live (ready or credentials-required):
supabase, elevenlabs, vercel, huggingface, sentry, linear, zapier, thisispaper, cleartracedata, upres — each with
a concrete plan (endpoint, transport, and — where published — OAuth authorize/token endpoints, scopes, dynamic
client registration), every element carrying its source. The MCP OAuth chain (RFC 9728 → RFC 8414) and the OpenAPI
`servers[]`+`securitySchemes` path are the two resolvers that most often reach `credentials-required`.

**Measured market rate (large, unbiased samples):**

| Population | Publishes anything | ready-or-creds |
|---|---|---|
| Tranco top-100 (infra/CDN/media) | ~0% | 0% |
| Public-APIs-100 (legacy/hobby) | 29% | 3% |
| Modern AI-tooling cohort (/explore) | ~92% | 58% |

**Honest read:** readiness is **near-zero across the general web** and **~58% in the modern AI-tooling segment**
adopting MCP+OAuth. It tracks MCP+OAuth uptake. Two capabilities fall out, with different maturity:

- **Connection-readiness** — high value *now* for the agentic/MCP segment (which is precisely NessGate's audience), low elsewhere.
- **Readiness-checker** — universal *now*: 100% of `incomplete` cases named the exact missing field per the service's own protocol. It gives the ~90–100% not yet complete an exact, actionable fix.

## 2. Recommendation

Promote in **two stages**, smaller/safer first, because their value/maturity differ:

**Stage 1 (recommended first): the readiness-CHECKER, additive on `/explore`.**
A `?readiness=1` flag on `/explore` that adds, per connectable resource, a `readiness` block: `outcome`,
`missing[]` (the exact under-published fields), and `provenance`. No new endpoint, no behavior change when the
flag is absent. This ships the universally-valuable half and creates the publish-more feedback loop, with minimal
surface area. It performs only the bounded, read-only metadata GETs already characteristic of `/explore`.

**Stage 2 (after A proves out): the connection-PLAN output.**
The full `ready | credentials-required | incomplete | no-compatible-method` verdict + connection plan, exposed as
`POST /connect {domain, client}` (client capabilities are required input, so a body is natural) and as a library
`plan(domain, clientCaps, {tier})`. Library-first is the natural home (the client's own vantage gives a truer
`ready`, and integrator compute absorbs the extra fetches).

## 3. Why this fits NessGate (and where it strains)

Fits:
- **Additive**: `/discover` and today's `/explore` are untouched; readiness is opt-in.
- **No new protocol / no publishing format** — it reads standards that already exist (the Charter's "no proprietary format" holds).
- **Neutral**: outcomes are enums, never scores; all compatible plans returned in a documented deterministic order; a single winner only when the *client* supplies a preference; auth/transport never guessed (`declared` / `inferred` / `undeclared`).
- **Reuses hardened machinery**: the safe handshake is the existing opt-in MCP introspection + verify pass (read-only, no secrets, SSRF-guarded). Credentials never touch NessGate.
- Maps cleanly onto the v2 tier model (`docs/v2-architecture.md`): readiness ≈ the `balanced`/`deep` tiers.

Strains / must-decide:
- **"ready" is a stronger claim** than "here is what's published." Gate it on an actual successful handshake with no auth required; everything authed tops out at `credentials-required`. Readiness is **vantage-relative** — say so.
- **Hosted cost/abuse**: readiness adds per-resource fetches (OAuth chains, spec fetches). Keep hosted readiness within existing `/explore` budgets (depth/host/request/byte caps, rate limits); deep per-candidate work belongs in the library or async refresh, never the synchronous hosted path.
- **Charter wording**: readiness reads a publisher's *own* declared metadata one hop further (OAuth AS metadata the publisher points to). This is within "reads what the domain declares," but the charter's read-scope language should be checked and, if needed, clarified — not silently exceeded.

## 4. Honest caveats (do not oversell)

- The correct summary is **not** "58% of the web is connectable." It is "58% of the *agentic segment*; ~0–3% of the general/legacy web." The aggregate rate is low and will stay low until adoption rises — which the checker is designed to accelerate.
- Live MCP `version` is frequently `?` (servers gate `initialize` behind auth, or return non-standard bodies). Honest, unavoidable without credentials.
- `/explore`-sourced A2A loses the inline card body, forcing a re-fetch that a target's bot protection can block. A production build should carry the card body through (as `/discover` already fetches it) rather than re-fetch.

## 5. Gates before any production behavior

1. Keep it **library-first and opt-in**; hosted only behind an explicit flag, within current `/explore` budgets.
2. Add a fixture corpus for each readiness resolver under `compat/` (per the repo rule: every real behavior gets a permanent fixture) — MCP OAuth chain, OpenAPI security, A2A schema, and reject/недо cases.
3. Confirm charter read-scope covers one-hop OAuth-metadata following; amend/clarify if required (transparency-first, per the v2 sequencing).
4. Neutrality CI: outcomes identical from identical captured evidence regardless of source (discover vs explore vs stored).
5. Ship **Stage 1** (checker) first; measure usage before **Stage 2** (plans).

## 6. What stays out of scope

No proxying, no protocol translation, no credential storage, no AI, no new publishing format — all as design review
constrained. NessGate prepares the plan; the client connects directly.

---

Artifacts backing this proposal (all under `lab/connection-plan/`): `plan.mjs`, `readiness.mjs`, `delegate.mjs`,
`explore.mjs`; 103 offline tests (`test-offline` 31, `test-readiness` 40, `test-delegate` 16, `test-explore` 16);
live scorecards `last-run*.json`, `market-*.json`; full write-up in `README.md`.
