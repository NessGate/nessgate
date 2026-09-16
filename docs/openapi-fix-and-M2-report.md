# OpenAPI-size fix + M2 (official conformance) — report

Date: 2026-09-16 · Reference implementation changed (the OpenAPI fix) but **not deployed** — held for
explicit approval. No Charter-v2 activation. M4/M5, storage, registration NOT started.

## Part 1 — OpenAPI-size fix (the weakness the unseen benchmark found)

**Gap:** OpenAPI specs >1 MB (vercel 10.8 MB, posthog 6.5 MB) exceeded the resolver's `maxBytes`
cap and were dropped → 2 recall misses in the M0.5 baseline.

**Holdout discipline (preserved, in order):**
1. **Retired** vercel.com + posthog.com from the holdout *before* designing the fix.
2. Turned the failure into **permanent compat fixtures** (`compat/fixtures/openapi/3.0/detect-large-truncated`, `detect-small-full`, `reject/detect-html`, `reject/detect-no-marker`).
3. **Replaced** with fresh unseen domains — workos.com (llms.txt + **1.1 MB** OpenAPI) and redocly.com (llms.txt + a2a) — and **re-froze** the holdout (still 19/16/12/5).
4. Fixed generally; did **not** optimize around vercel/posthog.

**Fix (general, protocol-aware, no hardcoding):** OpenAPI detection + our pointer-only record need
only the document HEAD (the `openapi`/`swagger` marker + `info.title`, conventionally first). The
resolver now reads a bounded **64 KB prefix** for `/openapi.json` and detects from it — the generic
1 MB cap is unchanged for every other protocol (no loosening). `fetchText` (library) and `safeFetch`
(worker) now **stream and stop at the cap** (never buffer beyond it). Applied byte-identically in
`packages/resolver/index.mjs` + `public/resolver.mjs`, and mirrored in `src/worker.js`
(`detectOpenApi` parity verified). Timeout + SSRF protections untouched.

**Tests (`scripts/test-openapi.mjs`, wired into the gate):** valid large (10 MB) OpenAPI found with
a bounded read (131 KB pulled, stream canceled); oversized/hostile 50 MB payload rejected + bounded;
redirect (post-redirect body detected); wrong content-type (HTML) rejected; truncated document with
a head marker detected; small OpenAPI unchanged; swagger 2.0 + empty.

**Before → after (refreshed frozen unseen benchmark):**

| Metric | Before (M0.5 baseline) | After (re-frozen holdout) |
|---|---|---|
| Authoritative recall | 67/69 (97.1%) | **67/67 (100%)** |
| — OpenAPI | 7/9 (missed vercel, posthog) | **8/8** (incl. unseen workos 1.1 MB) |
| False positives (negatives) | 0/12 | 0/12 |
| Classification / provenance | 100% / 100% | 100% / 100% |
| Parser failures | 0 | 0 |
| Latency / cost | p50 1.7 s / 17 req | **p50 1.5 s / 17 req** (prefix read is cheaper) |

Independent confirmation on the exact retired domains (one-off, no longer the ruler): vercel.com →
"Vercel API", posthog.com → "PostHog API" now both found.

**Security/resource trade-offs:** strictly *safer* — reads are now bounded by streaming (previously
the library downloaded the full body before checking size); the worker's per-invocation CPU is lower
for large specs (64 KB scan vs a 1 MB download+parse). No new outbound behavior; SSRF/timeout/redirect
caps preserved. Residual: prefix detection is head-based, so a spec that places the version marker
after 64 KB (contrary to convention) would be missed — recorded as a matrix deviation, and it would
become a fixture if ever observed.

## Part 2 — M2: official conformance ingestion (layer 1)

Vendored the ecosystems' **own** canonical material (each with `SOURCE.md`: origin, license, date),
run through the resolver by `scripts/test-conformance.mjs`:

| Protocol | Vendored vector | License |
|---|---|---|
| OpenAPI 3.0 | OAI `petstore.json` (OpenAPI Initiative `learn.openapis.org`) | Apache-2.0 |
| api-catalog | RFC 9727 §A linkset example | IETF Trust (BSD code components) |
| host-meta | RFC 6415 §A JRD example | IETF Trust (BSD code components) |

Layer-1 checks the resolver against these canonical documents (e.g. RFC 9727 `service-desc`
extraction; RFC 6415 correctly emits only the href link, skipping a template-only link). Two test
layers now exist: **official correctness** (`test-conformance`) + **real-world compatibility**
(`test-compat`, 25 fixtures).

**Honest gaps:** official machine-readable examples for **A2A** and **ARD/ai-catalog** were not
reliably fetchable (A2A repo sample paths 404; the ARD spec site is a JS-rendered SPA). They are
*not* vendored yet — documented here rather than faked. Both remain covered by layer-2 fixtures
(synthetic + a real-world ARD/UCP case) and by the unseen benchmark (a2a 3/3, ard 10/10). Adding
their official vectors is a follow-up when a stable, licensed source is available.

## CI now (all gate deploys, offline)

regression · v2 alpha · compatibility corpus (25 fixtures) · **openapi size handling** ·
**official conformance (3 vectors)** · matrix consistency. Plus the frozen unseen benchmark as the
separate moat ruler.

## Not started (awaiting review)

M4 (adapter contract in code), M5 (Compatibility Lab), storage, registration, Charter-v2 activation.
Open decision: whether to **deploy** the OpenAPI fix to production (`/discover`) — it is committed,
fully tested, and safe, but production deploy was held per the review cadence.
