# Validation 2 (authoritative) — NessGate vs the best current SDK stack, frozen unseen set

Question: after a developer adopts the best current official SDKs and tooling,
does NessGate still remove a substantial recurring layer — domain→interface
discovery, cross-protocol normalization, readiness, auth/transport/version
interpretation, registry handling, provenance, inbound identity evidence?
Protocol execution itself is not the claimed layer.

This document supersedes two earlier editions. Corrections log:
1. The first edition benchmarked `@modelcontextprotocol/sdk` 1.x as "the
   latest official MCP SDK". Stale — the current official client is the
   separate `@modelcontextprotocol/client` v2 package.
2. The second edition then claimed no official client supports protocol
   revision 2026-07-28, citing `SUPPORTED_PROTOCOL_VERSIONS`. Also wrong:
   that constant describes only the LEGACY (initialize-era) list. The v2
   client separates the eras — opt-in
   `versionNegotiation: { mode: 'auto' }` probes `server/discover` for the
   modern 2026-07-28 era and falls back to the legacy handshake
   conservatively (`'legacy'` is the default, which is what the earlier
   measurements exercised). Both B and C's execution now run with
   `mode: 'auto'`.

## Setup

Stacks, identical inputs, application-owned lines only counted:
A = DIY glue (fair first implementation; passes all mainstream mock cases).
B = best current stack: `@modelcontextprotocol/client@2.3.0` with
`versionNegotiation: { mode: 'auto' }` and its official OAuth discovery
helpers; `@a2a-js/sdk@1.3.0` (DefaultAgentCardResolver);
`@apidevtools/swagger-parser@13.1.0`; `web-bot-auth@0.2.0` (all current at run
time).
C = NessGate published packages (`@nessgate/resolver@1.22.1`,
`@nessgate/inspect@0.1.4`) for the layer + the same v2 client (auto mode) for
execution only. B never receives NessGate-derived endpoints.

Scoring set: 14 live domains frozen before any comparison (mechanical
selection rule, zero prior occurrences in this repository or its history —
frozen-set.json), unchanged across all editions. The historical TRAP suite is
a separate regression benchmark, never the scoring set.

## Authoritative frozen-set result

| Stack | Usable | Auth resolved | False positives | Errors | Protocols |
|---|---|---|---|---|---|
| A (DIY) | 7 raw → **5 real** | 5 | **2** (meilisearch, novu: llms-linked marketing pages answering 200 to initialize) | 0 | mcp, openapi |
| B (best current stack, auto mode) | **5** | 5 | 0 | 0 | mcp (2), openapi (3) |
| C (NessGate + v2 execution) | **13** | 13 | 0 | 0 | mcp, openapi, a2a |

Auto mode changed B by exactly one domain: axiom.co (registry-listed; the
negotiation probe surfaced the 401 in a form B's mapping classified, and the
official helpers then resolved the OAuth chain). Nothing else moved — every
other prior miss was a discovery miss, which no client capability affects.

## The five MCP lanes (frozen set, as required)

| Lane | Domains | Evidence |
|---|---|---|
| 1 — endpoint not discovered | openrouter.ai, tavily.com, novu.co, knock.app | absent from the registry; invisible to every official tool; C resolved each OAuth chain to the token endpoint |
| 2 — discovered, legacy MCP works | exa.ai | B(auto): open; C: ready; live handoff below |
| 3 — discovered, modern 2026-07-28 works | none observed in the wild on this set | proven deterministically: against a real localhost stateless 2026-07-28 server, B(auto) negotiates and connects (`open`), and falls back cleanly on a legacy server |
| 4 — discovered, authentication blocks negotiation | axiom.co | B(auto) + official helpers → needs-credentials with the token endpoint |
| 5 — readiness/auth classification still application glue | all of the above | the open/needs-credentials/broken taxonomy, error→state mapping, and cross-protocol normalization live in B's 102 app-owned lines; no SDK emits them |

## Integration cost (application-owned)

| | A | B | C |
|---|---|---|---|
| glue lines | 142 | 102 | **25** |
| protocol-specific branches | 18 | 12 | **0** |
| packages/configuration surfaces | 0 | 4 | 3 (one execution-only) |
| domain-discovery logic owned by the app | all | all (registry query + selection, card probe, spec probe) | none |
| version/auth/transport interpretation owned by the app | all | classification and normalization (SDKs fetch, apps interpret) | none |

## Live handoff (required chain, re-proven under auto mode)

domain → NessGate (plan: `ready`) → official `@modelcontextprotocol/client`
2.3.0 with `versionNegotiation: { mode: 'auto' }` → real tools:
exa.ai → `https://mcp.exa.ai/mcp` → `web_search_exa, web_fetch_exa`
(four consecutive successes; the endpoint is intermittently undiscoverable
upstream between runs — recorded as F4, variance ±1 across the set).

## Regression traps (historical benchmark, separate from scoring)

T1 docs-page-200: B's SDK errors rather than false-positives (SDKs help);
the readiness label is still app glue. T3 bare-403: B guesses an OAuth wall
exactly like DIY. T4 registry multi-version: correct only because B's app
glue implements isLatest. T6: B(auto) now negotiates the modern era against
the real stateless mock — corrected from earlier editions — and T6b confirms
clean legacy fallback. T8: B has no llms.txt/ARD visibility at all.

## Findings (recorded only)

- F4 run-to-run live variance (exa discoverability) — upstream, ±1 interface.
- F5 swagger-parser strict validate() under-detects usable OpenAPI.
- F6 web-bot-auth leaves key discovery/type semantics/transport hardening to
  the application.
- F7 second natural DIY false positive (novu) — the marketing-page class
  recurs in the wild.
- F8 registry responses varied between runs; retry handling is app glue.
- F9 (method) two successive baseline-capability errors in earlier editions
  came from auditing exported constants instead of option-gated modes;
  corrected by exercising behavior (real localhost era servers) rather than
  reading constants.

Run: `cd lab/validation2 && npm install && node run2.mjs [--traps]`.
