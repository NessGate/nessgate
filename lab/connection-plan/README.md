# Connection-Plan prototype (EXPERIMENTAL — lab-only)

An **isolated** experiment testing one added layer for NessGate:

> Current NessGate: *"This is what I found."*
> Proposed: *"This is what I found, and this is how your client can connect to it."*

Given a domain **and the client's own capabilities** (protocols, versions, transports,
auth it supports), it runs the existing resolver, compares both sides, and returns
**connection plans** — the compatible `{protocol, version, transport, auth}` combos,
each with the source that proves it. It does **not** proxy, translate, or connect:
*discovery → comparison → selection → plan*.

## Isolation (nothing published changes)

- Lives entirely under `lab/`. Production (`src/`, `public/`, `packages/`) never imports it —
  `scripts/test-lab-isolation.mjs` enforces this and passes with these files present.
- Reads the resolver's **own** output; defines no protocol, stores nothing, changes no API or charter.

## Files

| File | What |
|---|---|
| `plan.mjs` | The planner: `buildConnectionPlan(discovery, clientCaps)` + fact extractor. Pure, no I/O. |
| `profiles.mjs` | Sample client-capability profiles (mcp-agent, rest-tool, a2a-agent, polyglot). |
| `test-offline.mjs` | 31 deterministic no-network tests (the proof the matching is correct). |
| `run-live.mjs` | Best-effort live run against real domains; writes `last-run.json` scorecard. |
| `readiness.mjs` | **Readiness layer** — fill connection details + safe handshake → one of 4 outcomes. Per-protocol resolvers (MCP OAuth chain, OpenAPI, A2A). |
| `test-readiness.mjs` | 32 deterministic tests for the readiness assessors + pipeline. |
| `run-readiness.mjs` | Live readiness run (with delegation); writes `last-run-readiness.json`. |
| `delegate.mjs` | **Bounded delegation** — follow pointer surfaces (api-catalog, llms.txt) ONE level to the endpoints they declare. |
| `test-delegate.mjs` | 16 deterministic tests for the delegation extractors. |
| `explore.mjs` | Adapter feeding the HOSTED `/explore` (deeper delegation + MCP-Registry federation) into the pipeline. |
| `test-explore.mjs` | 16 deterministic tests for the `/explore` adapter. |
| `run-readiness-explore.mjs` | Live readiness run sourced from `/explore`; writes `last-run-explore.json`. |

Run: `node lab/connection-plan/test-offline.mjs` · `node lab/connection-plan/test-readiness.mjs` · `node lab/connection-plan/run-readiness.mjs [domain ...]`

## Neutrality (mirrors the live charter)

- No scores, ever — every judgment is an enum (`outcome`, `completeness`), never a number.
- Matching is deterministic set intersection (a fact), returned in a **documented, stable order**.
- A single winner (`selectedPlan`) is named **only** when the *client* supplies a preference; NessGate expresses none of its own.
- Auth/transport that the service did not declare are marked `undeclared`/`inferred`, **never guessed**.

## Findings (first live run — 8 groundtruth-positive domains, polyglot client)

Outcomes: **4 protocol-only · 3 pointers-only · 1 none-found.**

| Question | Result | Read |
|---|---|---|
| Q1 found a usable connection path | **50%** | openapi (supabase, vercel) + mcp (huggingface, zapier) |
| Q2 version confirmed (of matched) | **0%** | resolver discards OpenAPI/MCP version strings → fixable extractor gap |
| Q3 **complete** plan (dev need NOT read specs) | **0%** | the declaration gap, confirmed: no real service declared protocol+version+transport+auth turnkey |
| Q3 protocol-only (dev STILL reads specs) | **50%** | value is real but partial today |
| Q4 produced a verdict beyond `/discover` | **88%** | a plan/verdict discover does not emit |

**Conclusions:**

1. **The idea works mechanically** — plans are produced, provenance preserved, neutrality held, honesty explicit (`inferred` vs `declared`, `undeclared`, `pointers-only`).
2. **The declaration gap dominates** (Q3 complete = 0%), exactly as predicted. Today the layer's honest promise is *"here is the compatible protocol + where to connect + what it proves,"* not *"connect turnkey."* Still meaningfully more than a resource list.
3. **The MCP + introspection path is where "complete" will come from** (zapier already reaches transport-known + auth-observed). Preserving the OpenAPI/MCP **version** string in the resolver would move Q2 off 0% immediately.
4. **Run the planner on `/explore`, not `/discover`.** 3 of 8 domains published only pointer/catalog surfaces (`llms.txt`, `api-catalog`); reaching their real endpoints needs delegation, which `/explore` already does. The planner belongs on top of `/explore` output.

## Findings — readiness layer (extended requirements)

Pipeline: compatibility plan → **fill connection details (safe read-only GETs)** → **safe handshake** → one of
**ready / credentials-required / incomplete / no-compatible-method**. Live run, 12 domains, polyglot client:

| Outcome | Count | Notes |
|---|---|---|
| ready | 0 | (a public, no-auth endpoint — none in this cohort) |
| **credentials-required** | **1** | **supabase.com**: OpenAPI resolver fetched the spec, extracted `servers[]`=`api.supabase.com`, `v=3.0.0`, `http:bearer` → connect with your own bearer token. **Thesis proven end-to-end.** |
| incomplete | 11 | **all 11 name exactly what is missing** (the readiness-checker) |
| no-compatible-method | 0 | |

**Connection-ready-or-creds: 8%. Incomplete cases that name the missing field: 11/11.**

Representative readiness-checker output (real services, unmodified):
- **cloudflare.com** (A2A): *"supportedInterfaces[].transport not declared; version not declared."*
- **zapier.com** (MCP): endpoint returned a bare `403` → honestly reported *"undetermined: authorization OR bot/WAF — a safe probe cannot distinguish"* (does NOT falsely prescribe OAuth metadata).
- **6/12** publish only pointer/catalog surfaces → *"follow them (delegation) to reach an endpoint."*

The **MCP OAuth chain** (RFC 9728 protected-resource metadata → RFC 8414 authorization-server metadata → `authorization_endpoint` / `token_endpoint` / `scopes` / dynamic client registration) is implemented and unit-proven offline (see `test-readiness.mjs`); no seed domain exposed a clean public MCP-with-OAuth server to exercise it live, but the assessor turns that exact chain into a `credentials-required` plan when present.

### Conclusions

1. **The extended pipeline works** — supabase reached `credentials-required` with a complete, sourced plan a developer can act on without reading the OpenAPI/OAuth specs.
2. **The declaration gap still dominates today** (8% ready-or-creds), so the highest-value capability is the **readiness-checker**: 11/11 incomplete cases produced a precise, protocol-specific missing-field reason. It tells service owners exactly how to fix their *existing* publication.
3. **Honesty held under real conditions** — the bare-403 case is reported as undetermined, not as a false OAuth requirement; unreachable handshakes are reported as such; nothing is guessed.

## Findings — bounded delegation (following pointers one level)

`delegate.mjs` follows pointer/catalog surfaces ONE level (depth 1, read-only, host-guarded, capped at 8,
publisher-declared targets only): RFC 9727 api-catalog `service-desc` → OpenAPI; and STRICT machine-spec
links in llms.txt (doc/marketing links ignored, `.md`/`.html`/etc. excluded). Same 12 domains:

| Metric | No delegation | With delegation |
|---|---|---|
| ready | 0 | **1** (elevenlabs.io — delegation found a public MCP at `/mcp`; handshake OK, no auth) |
| credentials-required | 1 | 1 (supabase.com) |
| **connection-ready-or-creds** | **8%** | **17%** |
| incomplete cases naming the gap | 11/11 | 10/10 |

**Honesty under delegation held:** llms.txt links that are really documentation pages (e.g. `linear.app/docs/mcp.md`,
`…/mcp-connector.md`) either fail their safe handshake → reported `incomplete/unreachable`, or (after tightening)
are excluded as non-endpoints — **never** promoted to a false `ready`/`credentials-required`. Tightening the
extractor removed the spurious candidates (anthropic +8→0, zapier +5→1) with no loss of real signal.

### Overall conclusions

1. **The full pipeline works and is honest** — discovery → compatibility → fill details → safe verify → 4 clear outcomes, with provenance on every claim and no scores. Two real successes (elevenlabs `ready`, supabase `credentials-required`) are connect-ready results a developer can act on without reading specs.
2. **Delegation is worth it** — it doubled the connection-ready rate (8%→17%) by reaching endpoints that pointer-only domains merely name. The hosted `/explore` already does richer delegation; this proves the value locally.
3. **The declaration gap remains the ceiling**, so the **readiness-checker** (10/10 incomplete cases name the exact missing field per the service's own protocol) is the broadly applicable capability: it tells publishers exactly what to fix, which raises that ceiling over time.

## Findings — sourcing from the hosted `/explore` (the recall ceiling)

`explore.mjs` feeds `/explore?org=1&related=1` (declared pointers to depth 2, org/related hosts, and official
**MCP-Registry federation**) into the *same* readiness pipeline. Same 12 domains, same client. This trades the
"no dependency on nessgate.com" property for recall, purely to measure the ceiling.

| Source | ready | credentials-required | **ready-or-creds** |
|---|---|---|---|
| resolve() only (no delegation) | 0 | 1 | **8%** |
| resolve() + local delegation | 1 | 1 | **17%** |
| **hosted `/explore`** | **1** | **6** | **58%** |

**The MCP OAuth metadata chain is now proven end-to-end on 6 real services** (supabase, elevenlabs, vercel,
huggingface, sentry, linear) — each returned a full `credentials-required` plan with `authorization_endpoint`,
`token_endpoint`, `scopes`, and (mostly) dynamic client registration, e.g.:

```
supabase.com → CREDENTIALS-REQUIRED
  mcp  streamable-http  https://mcp.supabase.com/mcp
  oauth2  token=https://api.supabase.com/v1/oauth/token  authorize=https://api.supabase.com/v1/oauth/authorize
  scopes: organizations:read projects:read projects:write database:write … (dynamic client registration: yes)
```

One service (zapier) was **READY** — `mcp.zapier.com/mcp` accepted the initialize handshake with no auth. The
remaining 5 Incomplete cases still named the exact gap (stripe: authorization-server metadata unreachable per
RFC 8414; cloudflare: A2A transport+version; mintlify/notion: pointer-only; anthropic: nothing published).

### Overall conclusion

With `/explore`'s recall, the extended requirements are fully met on real services: **"this is compatible, I
verified what I safely can, and the connection is ready except for the credentials only you can provide."**
58% of a positive cohort reached ready-or-credentials, and 100% of the rest were told exactly what to publish
to get there. The two capabilities are complementary: connection-readiness for the well-published,
precise readiness-checker feedback for everyone else. Recall (delegation depth) is the dominant lever;
per-protocol readiness resolvers (MCP OAuth done; OpenAPI done; A2A partial) convert that recall into plans.

## Findings — market rate (large random samples)

To estimate the *true* real-world rate (not the groundtruth-positive cohort), the pipeline was run over
large, unbiased samples. The rate is strongly **segment-dependent**:

| Population | n | Path | Publishes anything | ready-or-creds |
|---|---|---|---|---|
| Tranco top-100 (popularity → CDN/infra/media) | 100 | local | ~0% | **0%** |
| Public-APIs (publicapis-style; legacy/hobby) | 100 | local | 29% | **3%** (10% of publishers) |
| Public-APIs subsample | 25 | /explore | 24% | **0%** |
| Modern AI-developer-tooling (MCP-Registry participants) | 12 | /explore | ~92% | **58%** |

Real connection-ready hits even via the dependency-free local path: `thisispaper.com`, `cleartracedata.com`
(public MCP → **ready**), `upres.ai` (complete OpenAPI → **credentials-required**).

**Conclusion:** full connection-readiness is **near-zero across the general and legacy-API web today**
and **concentrated (~58%) among services that have adopted MCP + OAuth**. The readiness-checker
applies regardless: it names the precise missing field for publishers that are not yet complete.

### Step-2/3 note (metadata coverage)

A2A extraction now supports the modern schema (`protocolVersion` / `preferredTransport` / `additionalInterfaces`,
JSON-RPC default), and MCP `initialize` version parsing is SSE-frame-aware. Live, MCP `version` often remains `?`
because servers gate `initialize` behind auth (unknowable without credentials — honestly reported), and the
`/explore` path loses the inline A2A card body (must re-fetch, occasionally blocked by the target's own bot
protection). These are honest ceilings, not defects; the fixes are unit-proven (40 readiness tests).

## Findings — verdict stability (the certification question)

Can a readiness verdict be a *standing* claim? `run-stability.mjs` measured it:
3 full local runs × 12 domains + a production-vantage `/connect` pass, then a controlled follow-up
(3× assessment on ONE frozen discovery snapshot — pure assessment-layer variance).

**Raw outcome stability was 25% — but decomposition shows the verdict rules are sound and the
observations are the problem, with separable causes:**

| Cause | Evidence | Implication |
|---|---|---|
| Experiment vantage (local machine) | 6 `fetch failed` errors — including to nessgate.com itself | vantage quality dominates; a laptop is not a certification vantage |
| Self-inflicted rate limiting | prod `/connect` 429s late in the run (`outcome=null` rows) | budget the observation plan |
| Per-vantage deterministic walls | elevenlabs/vercel OpenAPI fetch fails **3/3 consistently** locally, differs at the edge | verdicts are vantage-relative; a badge must name its vantage |
| One dropped hop in an AND-chain | sentry run2: a single failed OAuth-metadata fetch flipped `credentials-required` → `incomplete` | per-hop retries required |
| **Service-side variance** | zapier, frozen discovery: `ready(ok)` 2/3, MCP handshake rejected 1/3 | **single observations can never ground a badge — N-of-M majority is mandatory** |
| Stable when network cooperates | supabase & sentry frozen-discovery: **3/3 identical** `credentials-required` with full OAuth chain | the chain itself is reliable; the predicate is certifiable *given* observation semantics |

Bonus: the broken-vs-under-published classifier cleanly split **all** incompletes (5 broken-style /
7 under-published) — evidence for adding a distinct `broken` outcome ("declared but fails") as the
next small product increment.

**Conclusion for readiness verification:** NessGate is already a deterministic judge of
*rules* (CI-proven: same evidence → same verdict). It is NOT yet a deterministic judge of
*observations*, and no single-shot verdict can be. A certification predicate is viable only with:
(1) a reliable, named vantage (edge, not laptop), (2) N-of-M majority verdicts with defined
observation windows, (3) per-hop retries in metadata chains — i.e., exactly the re-verification
machinery that the v2 plan gates behind Charter v2 activation. Measurement supports the sequencing: the self-check is usable now; hosted standing verdicts only after Charter v2 + observation semantics exist. Those semantics are now drafted: **`docs/readiness-certification-draft.md`** (N-of-M
majority, named vantage classes, per-hop retries, `undetermined`/`unstable` as first-class results —
every rule traceable to a finding in this experiment).

**Production proposal:** see [`PROPOSAL.md`](PROPOSAL.md).
