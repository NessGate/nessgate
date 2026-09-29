# NessGate — developer walkthrough

Onboarding for anyone continuing this work. Pairs with `README.md` (product) and
`CONTRIBUTING.md` (process). Current release: **1.15.0**.

## What NessGate does (four things, one worker)

1. **Discover** — `GET /discover/{domain}`: read what a domain publishes across ~14
   standards, return one normalized list. Stateless, no crawling, no guessing.
2. **Explore** — `GET /explore/{domain}`: discover + bounded delegation (declared
   pointers, org/related hosts) + MCP-Registry federation, with evidence classes.
3. **Readiness** *(new)* — `GET /explore/{domain}?readiness=1`: per connectable
   resource, "how ready is this to connect to?" → `ready | credentials-required |
   incomplete` (+ the exact missing field), from the service's own metadata.
4. **Connect** *(new)* — `POST /connect/{domain}` with the client's capabilities:
   "how can THIS client connect?" → `ready | credentials-required | incomplete |
   no-compatible-method` + a connection plan (endpoint, transport, version, auth).

All four are also MCP tools at `POST /mcp`: `discover_domain`, `connect_domain`,
`check_readiness` (the registry-published, framework-neutral bridge — see
`examples/langchain/`).

## Repo map (the files that matter)

| Path | What |
|---|---|
| `src/worker.js` | The whole Cloudflare Worker: routing, discover/explore/connect, MCP, readiness IO, SSRF guards, metrics. |
| `public/resolver.mjs` | The embeddable library (discover + readiness + `plan()`). **Byte-identical** to `packages/resolver/index.mjs`. |
| `packages/resolver/` | npm `@nessgate/resolver`; `index.mjs` is a byte-copy of `public/resolver.mjs`. Bump `package.json` version to publish. |
| `public/` | Static site + `openapi.json` + `llms.txt` (served by the worker). |
| `compat/` | The permanent compatibility corpus (fixtures, matrix, adapter manifests). |
| `lab/connection-plan/` | The R&D that produced readiness/connect: prototype, market measurement, `PROPOSAL.md`. Isolated (never imported by prod). |
| `scripts/` | Tests, deploy, smoke. See below. |
| `examples/langchain/` | LangChain tools (`connect_domain`, `discover_domain`) + MCP-adapter usage. |

## The parity model (read this before editing resolver/worker)

Normalization + the readiness assessors + the client matcher exist **twice** — in
`public/resolver.mjs` (library) and `src/worker.js` (worker) — and must stay
**byte-identical per function**. Enforced by:

- `scripts/test.mjs` — compares each pure function `lib.fn` vs the worker's `fn`.
- `scripts/test-readiness-checker.mjs` — parity for the 7 readiness/match pure fns
  (`extractProtocolVersion`, `readinessProtocol`, `assessOpenApiReadiness`,
  `assessA2aReadiness`, `assessMcpReadiness`, `matchClient`, `canonClientProtocol`).
- `packages/resolver/index.mjs` must be a byte-for-byte copy of `public/resolver.mjs`.

**Workflow when you change shared logic:** edit `public/resolver.mjs`, copy the SAME
text into `src/worker.js`, then `cp public/resolver.mjs packages/resolver/index.mjs`
and bump `packages/resolver/package.json`. Run `node scripts/test-readiness-checker.mjs`
and `node scripts/test.mjs` — they'll catch any drift.

Worker-only IO (the fetch orchestration: `readinessForResource`, `connectData`,
`attachReadiness`, MCP handlers) is NOT parity-checked — only the pure functions are.

## Readiness / connect architecture

- **Pure assessors** (parity'd): take already-fetched docs → a verdict. E.g.
  `assessMcpReadiness({init, prm, as})` turns an MCP `initialize` result + the OAuth
  metadata chain (RFC 9728 protected-resource → RFC 8414 authorization-server) into
  `credentials-required` with the authorize/token endpoints + scopes.
- **IO** (per runtime): library uses `fetchBounded`/its own MCP init; the worker uses
  its SSRF-guarded fetch (`isForbiddenHost` + `assertPublicDns`, HTTPS-only, manual
  redirects). Both are **bounded**: `READINESS_MAX` endpoints, `READINESS_DEADLINE_MS`
  total, `READINESS_FETCH_TIMEOUT_MS` per hop.
- **Matcher** (parity'd): `matchClient(readiness, clientEntry)` — deterministic set
  intersection, tri-state per dimension (`true`/`"any"`/`"unknown"`/`false`). Only a
  declared-vs-declared conflict is a hard incompatibility.
- **`readinessProtocol(r)`**: decides if a resource is a connectable endpoint. Trusts
  explicit adapter/type labels; the fuzzy path/host heuristics require the protocol
  word as a **bounded path segment** and reject doc extensions (so `/mcp` matches,
  `/mcp-guide` and `…/mcp.md` don't). Add regression cases to `test-readiness-checker.mjs`.

## Invariants (do not break)

- **Additive/opt-in.** Default `/discover`, default `/explore`, and default
  `resolve()` output are byte-unchanged. Readiness runs only under `?readiness=1` /
  `opts.readiness`; connect is its own endpoint.
- **No scores, ever.** Outcomes are enums; there is `missing[]`, never a number.
- **Credentials never touch NessGate.** Readiness/connect send no `Authorization`
  header; the plan tells the caller how to auth, and the caller does it directly.
- **SSRF.** Every outbound fetch is HTTPS-only + host-guarded; redirects not followed
  for readiness metadata.
- **Charter.** Reads what a domain declares; no crawling/indexing, no guessing. An
  empty answer stays honest (outcome + `checked[]` + missing fields), never fabricated.
- **Every real compatibility fix adds a `compat/` fixture** (see `compat/README.md`).

## Metrics (privacy-preserving)

One categorical label per call via the single site `recordDiscovery(env, label)`
(→ one `writeDataPoint`), enforced by `scripts/test-metrics-isolation.mjs`. Labels:
`resources`/`empty`/`error` (discover), `connect:<outcome>`, `readiness:<aggregate>`.
**No domains, IPs, client payloads, or identifiers** — the emitter takes no `request`.
Query via the `nessgate_discovery_v1` Analytics Engine dataset (`scripts/mcp-metrics.mjs`).

## Build / test / ship

```bash
npm test                 # offline regression (parity, normalization, SSRF, …)
npm run test:readiness   # readiness/connect: parity + outcomes + MCP OAuth chain + neutrality
npm run check            # full offline suite + live smoke + npm parity
npm run deploy           # HARD pre-deploy gate (offline suite incl. test:readiness) → wrangler deploy (stamps BUILD_ID=git SHA)
npm run smoke            # post-deploy: prod health + /connect + readiness e2e (dogfooded on nessgate.com)
```

**Deploy flow:** commit → `npm run deploy` → `npm run smoke` (verifies prod `/version`
== local HEAD) → `git push`. **Publish library:** bump `packages/resolver/package.json`,
push, then `gh workflow run publish-resolver.yml` (OIDC, tokenless); verify with
`node scripts/check-npm-parity.mjs`. Rollback: `npx wrangler rollback`.

Versioning: keep the npm package, `public/openapi.json` `info.version`, and the MCP
`serverInfo.version` in step (all `1.15.0` now).

## Where to look next

- `lab/connection-plan/PROPOSAL.md` — the tranche plan, remaining follow-ups
  (A2A `securitySchemes` depth, version-string preservation, charter read-scope note).
- `lab/connection-plan/README.md` — the market-rate findings (readiness is
  concentrated in the modern MCP/OAuth segment; ~0% of the general web).
- Adoption follow-ups discussed: keep the bridge **MCP-first** (already done — 3 tools);
  refresh `examples/langchain`; do **not** add a "fallback scan" that guesses (charter
  conflict); measure real usage via the new `connect:`/`readiness:` metrics.
