# Second validation — NessGate vs the best available SDK stack (frozen unseen set)

Question: after a developer already uses the official SDKs and established
tooling, does NessGate still remove a substantial recurring layer (domain
discovery, cross-protocol normalization, readiness, auth/transport/version
resolution, registry handling, provenance, inbound identity evidence)?

Method: three implementations on identical inputs.
A = DIY glue (../validation/baseline/glue.mjs, unchanged).
B = best available stack, used as documented: @modelcontextprotocol/client
2.3.0 — the CURRENT official v2 client package (published 2026-10-02; the 1.x
monolith @modelcontextprotocol/sdk is not the newest client, a baseline error
in the first edition of this report, corrected below) — plus @a2a-js/sdk 1.3.0
(DefaultAgentCardResolver), @apidevtools/swagger-parser 13.1.0, and
web-bot-auth 0.2.0 (all re-audited as current at rerun time). Only
application-owned lines count against B.
C = NessGate published packages for the layer + the SAME official MCP SDK used
only for execution.

Scoring set: 14 live domains, frozen before any run, selected by a mechanical
rule (a-priori candidate pool filtered to domains with zero occurrences in
this repository's content or git history — see frozen-set.json). nessgate.com
excluded. The historical TRAP suite ran separately as a regression benchmark
only.

## Frozen-set results (usable interfaces / auth fully resolved / hard errors)

| Stack | Usable | Auth resolved | Errors | Protocols reached |
|---|---|---|---|---|
| A (DIY) | 6 → **5 real** (one was a false positive, below) | 5 | 0 | mcp, openapi |
| B (best SDKs) | **3** | 3 | 0 | openapi, (a2a card found but incomplete) |
| C (NessGate + SDK) | **12** | 12 | 0 | mcp, openapi, a2a |

Highlights from the per-domain matrix (full output: `node run2.mjs`):

- knock.app, novu.co, axiom.co, tavily.com: C resolved live **MCP OAuth chains
  to the token endpoint** on four unseen domains; B found none of these MCP
  endpoints at all — its only MCP discovery channel (the official registry)
  does not list them. Domain→endpoint discovery is the structural gap SDKs do
  not address.
- tavily.com: C surfaced a live **A2A card as credentials-required**; B fetched
  the same card (official resolver) but classified it only "incomplete" —
  readiness semantics remain app glue even with the official resolver.
- exa.ai: C's plan said an MCP endpoint was **ready**, and the official SDK
  then connected and listed its tools (`web_search_exa`, `web_fetch_exa`) —
  the layer→SDK handoff demonstrated live on an unseen domain. (This endpoint
  appeared on a re-resolve but not the first pass of the same run — recorded
  as run-to-run variance, not counted in C's 12.)
- meilisearch.com: the unseen set produced a natural false-positive trap. Its
  llms.txt links a marketing page under /integrations/mcp; the DIY baseline
  POSTed initialize at it, got 200, and reported a usable MCP server. C
  correctly surfaces no connectable endpoint there (documentation-section
  paths are never endpoints). A's headline count is adjusted accordingly.
- 6 of 14 domains publish nothing any stack can use — a property of today's
  publication rates, identical across stacks.

## Application-owned integration cost

| | A (DIY) | B (best SDKs) | C (NessGate + SDK) |
|---|---|---|---|
| glue lines | 142 | **104** | **26** |
| protocol-specific branches | 18 | **12** | **0** |
| packages to coordinate | 0 | 4 | 3 (one of them execution-only) |
| domain-discovery logic owned by the app | all of it | all of it (registry query, card probe, spec probe, selection) | none |
| version/auth/transport classification owned by the app | all | most (SDK helpers fetch OAuth metadata; mapping errors→states, choosing endpoints, cross-protocol normalization stay app-side) | none |

## Correction and rerun (same frozen set, B upgraded to the official v2 client)

The first edition claimed "the latest official MCP SDK is 1.32.0". That was
stale: a separate stable v2 client package exists
(@modelcontextprotocol/client, 2.3.0 at rerun). B's MCP engine was replaced
with it and the EXACT frozen 14-domain set was rerun, unchanged. Two facts,
both from the package's own exports at 2.3.0:
`SUPPORTED_PROTOCOL_VERSIONS = 2024-11-05 … 2025-11-25` (plus 2024-10-07) and
`LATEST_PROTOCOL_VERSION = 2025-11-25` — so revision 2026-07-28 is NOT yet
supported by any official client package either; the earlier substance stands
with the corrected package name.

Rerun totals (same scoring rules; live-set run-to-run variance is about ±1
interface and is recorded as F4):

| Stack | Usable | Auth resolved | False positives | Errors | Protocols |
|---|---|---|---|---|---|
| A (DIY) | 7 raw → **5 real** | 5 | **2** (meilisearch AND novu: llms-linked marketing pages answering 200 to initialize) | 0 | mcp, openapi |
| B (v2 client + SDKs) | **4** | 4 | 0 | 0 | mcp (1), openapi (3) |
| C (NessGate + v2 for execution) | **13** | 13 | 0 | 0 | mcp, openapi, a2a |

What the v2 upgrade changed for B, split as required:

- **Endpoint known, SDK speaks it:** exa.ai — the registry lists it, and the
  v2 client connected (B's one MCP success). The v1 SDK could also speak this
  revision, so the upgrade itself changed no outcome on this set; B's earlier
  exa miss was registry-response variance, not SDK capability.
- **Endpoint known, classification still app glue:** axiom.co — the registry
  lists it, v2 reached it, and B's error→state mapping still failed to
  classify the OAuth wall (C: credentials-required with the token endpoint).
- **Endpoint never discovered, so no SDK could be invoked:** openrouter.ai,
  tavily.com, novu.co, knock.app — four live MCP services with full OAuth
  chains (C resolved each to the token endpoint) that are absent from the
  registry and invisible to every official tool. No client version fixes
  discovery.

Live handoff, re-proven with v2 (three consecutive successes):
exa.ai → NessGate plan: ready → @modelcontextprotocol/client 2.3.0 connected
and listed `web_search_exa, web_fetch_exa`.

## Maintenance and currency (measured, not estimated)

- The current official v2 client (2.3.0, 2026-10-02) supports protocol
  revisions through 2025-11-25 — not 2026-07-28, per its own exported
  constants. A B-stack application cannot assess a current-revision stateless
  server today and must wait for a client release or write glue; C already
  classifies it (`ok:server-discover`).
- One recorded week of protocol events cost this repository's own maintainers
  +599/+247/+597/+435 lines (see ../validation/REPORT.md); a B-stack app
  absorbs the SDK-covered share of such events via upgrades but keeps every
  discovery/normalization/readiness change on its own books; a C app's diff
  for all of them was 0.

## Historical regression traps against B (separate benchmark, not scoring)

- T1 (docs page answers 200): B's SDK fails the JSON-RPC parse — no false
  "open" (SDKs genuinely help here); the readiness *label* still comes from
  app glue.
- T3 (bare 403): B's glue guesses an OAuth wall exactly like DIY —
  classification is not an SDK concern.
- T4 (registry multi-version): B passes only because its app glue implemented
  isLatest selection; the registry client behavior is still app-owned.
- T6 (2026-07-28 stateless): B structurally cannot — confirmed against the v2
  client's own version constants above.
- T8 (llms doc link): not applicable — B has no llms.txt/ARD visibility at
  all; whole discovery channels are invisible to the best-stack approach.

## Findings (recorded only)

- F4: run-to-run discovery variance on exa.ai (an endpoint surfaced on
  re-resolve only) — source likely upstream content/timing; worth a
  repeat-observation note in docs rather than a code change.
- F5: @apidevtools/swagger-parser's strict validate() rejects some live specs
  that are usable in practice; B under-detects OpenAPI through no fault of its
  wiring. (A B developer would eventually write laxer glue — more lines.)
- F6: web-bot-auth@0.2.0 hands key DISCOVERY to the application (resolver
  callback): directory/type semantics, JWKS fetching, and transport hardening
  remain app-side even with the published verifier.
- F7: a second DIY false positive surfaced on rerun (novu.co, same
  marketing-page class as meilisearch) — the unseen set keeps generating this
  failure mode naturally.
- F8: B's registry responses varied between runs (exa absent once, present
  once) — registry-querying glue needs retry/variance handling, also app-side.

Run: `cd lab/validation2 && npm install && node run2.mjs [--traps]`.
