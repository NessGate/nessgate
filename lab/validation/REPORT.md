# Compatibility-layer validation — measured comparison

Question under test: does one NessGate integration replace the per-protocol
discovery/compatibility glue (MCP, A2A, OpenAPI, inbound Web Bot Auth) a
developer otherwise writes and maintains — without replacing the protocol SDKs
themselves?

Method: `baseline/glue.mjs` is a fair first implementation written from the
specifications (it passes every STRAIGHT case below, including the full
RFC 9728 → RFC 8414 chain). `with-nessgate.mjs` is the complete consumer
integration using the published packages (`@nessgate/resolver@1.22.1`,
`@nessgate/inspect@0.1.4`, installed normally). `run-validation.mjs` runs both
against identical inputs. Every TRAP case reproduces a bug class recorded in
this repository's own history (each one was hit in production or by an external
audit before being fixture-pinned); none was invented for this comparison.

## Results

STRAIGHT (mainstream paths — both implementations succeed): 4/4.
OpenAPI + bearer; the full MCP OAuth metadata chain (both resolve the token
endpoint); an A2A 0.3.x card; a valid legacy Web Bot Auth round trip.

TRAP (edge cases — the sides diverge): 9/9, baseline wrong in every one.

| Case | Baseline | NessGate |
|---|---|---|
| T1 documentation page answers 200 to MCP initialize | usable (false positive) | incomplete / http-200-not-mcp |
| T2 valid OpenAPI larger than the read cap | broken (false) | incomplete / oversized |
| T3 bare 403 on an MCP endpoint | invents an OAuth requirement | incomplete / denied:403 (undetermined) |
| T4 registry lists several versions, oldest first | routes to the stale v1.0.0 | isLatest v2.0.0 |
| T5 A2A v1 card (protocolBinding, per-interface version) | card unreadable | ready / jsonrpc |
| T6 stateless 2026-07-28 MCP server (no initialize) | error:400, unusable | ready / ok:server-discover |
| T7a legacy Signature-Agent full URL as key location | fetched and verified | refused (origins only) |
| T7b signature without expires/tag | verified | refused (profile) |
| T8 llms.txt doc link containing /mcp | handshakes a web page | never treated as an endpoint |

LIVE (real domains, identical inputs):

| Domain | Baseline | NessGate |
|---|---|---|
| supabase.com | 1 usable; reports the OpenAPI document and one MCP entry as broken (T2 class, live) | 3 connectable: mcp + 2× openapi, all credentials-required with resolved auth metadata |
| nessgate.com | openapi + mcp usable | openapi ready, mcp ready (protocol-level evidence) |
| replicate.com | 0 found (requests refused at the edge) | found; openapi credentials-required, mcp incomplete (error:405) |
| huggingface.co | 0 found | found; the declared-but-404 card reported broken, an oversized spec reported honestly, one mcp credentials-required |

## Quantification

| Measure | Without NessGate | With NessGate |
|---|---|---|
| integration code (non-blank, non-comment lines) | 142 — and this baseline only covers the matrix | 19 |
| protocol-conditional branches | 18 | 0 |
| specifications the application developer must read | ≈13 (three MCP revisions, RFC 9728, RFC 8414, OpenAPI security, two A2A generations, RFC 9421, RFC 9651, RFC 7638/8037, the Web Bot Auth draft, llms.txt/ARD, the registry API) | 1 (the NessGate data model) plus the SDK of the protocol actually used |
| maintenance when protocols change (measured from this repo's own git history, one week of real events) | MCP 2026-07-28: +599 lines · registry isLatest: +247 · Web Bot Auth hardening: +597 · normative label/multi-signature: +435 | 0 lines (two `npm update`s) |
| edge cases handled centrally | each must be discovered and fixed locally | 59-fixture corpus, 139 readiness checks, 119 inspection checks, spec-watch pipeline |

## What the developer still owns

- Executing the connection: NessGate returns the plan (protocol, endpoint,
  transport, version, auth metadata); wiring it into the chosen SDK and running
  the OAuth dance with the caller's own credentials remains application code
  (a few lines per protocol, by design — credentials never pass through
  NessGate).
- Policy: inbound inspection returns tiered evidence, never a decision.
- Business logic, retries, caching strategy, and any protocol features beyond
  discovery/readiness/identity evidence.

## Boundary

NessGate owns: discovery across the published standards; normalization into one
data model; readiness/usability classification with named gaps; client-capability
matching; registry federation with attributed version selection; inbound
identity evidence (signature, network, directory tiers) with provenance.

NessGate must never own: credentials or token exchange; protocol session
execution (the SDKs' job); allow/deny or trust decisions; ranking or scoring;
content rehosting.

Complementary positioning, verified by construction: read-only toward services,
attributed toward registries, evidence-not-policy toward bot-management
infrastructure, and SDK-agnostic (the LangChain/LlamaIndex examples feed the
plan into ordinary clients).

## Findings (recorded, not implemented)

- F1: `@nessgate/inspect`'s package `exports` map only exposes `.` and
  `./middleware`, but its README lists lower-level helpers as importable;
  consumers cannot reach them. Documentation/packaging mismatch.
- F2: the baseline's live failures on replicate.com / huggingface.co came from
  edge refusals of its plain requests — request shaping (headers, protocol
  detail) is part of the glue cost this comparison under-counts for the
  baseline, since the baseline was allowed to stay simple.
- F3: no public A2A v1 production deployment was available for a live A2A case;
  v1 behavior is validated against the authoritative schema only (mocked).

Run: `cd lab/validation && npm install && node run-validation.mjs` (add
`--no-live` for the deterministic subset).
