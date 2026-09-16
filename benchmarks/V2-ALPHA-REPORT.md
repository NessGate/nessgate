# NessGate v2 alpha (Stage 1) — implementation results & benchmark

Date: 2026-09-15 · **Experimental. Exercises capabilities PROPOSED under Charter v2, which is NOT active.**
Scope: library-only (`packages/resolver/v2.mjs`). Production hosted resolver, `index.mjs`/`public/resolver.mjs`,
storage, registration, and the active Charter v1 are all **untouched**.

## Implementation summary

| Requirement | Status |
|---|---|
| Two-axis / two-level model | Done — `verification` × `relationship` → `level`; `level` derives ONLY from the evidence class (frozen `LEVEL` map). |
| Formalized adapter architecture | Done — self-describing `V2_ADAPTERS` (id, standard, discovers, evidenceClass, canEstablishAuthority, tier, external, run). |
| Deterministic CT-subdomain + sitemap-host adapters | Done — balanced tier; each verifies discovered hosts through the full v1 resolver. |
| Provenance on every result | Done — `classify()` throws if provenance is empty; CT items record the CT query **and** the verifying resolve. |
| Conformance + regression tests | Done — `npm run test:v2` (all pass); v1 `npm test` incl. byte-parity still green. |
| Opt-in + clearly experimental | Done — nothing runs without an explicit `tier`; every result stamped "Charter v2 NOT active". |

**Invariant proven structurally, not just by test:** the only adapter with `canEstablishAuthority: true`
is `exact-host` (reading the domain's own well-known files → `publisher-hosted`, Level 1). CT and sitemap
adapters can only name Level-2 classes, and `classify()` computes level from the relationship regardless of
verification. Tests confirm a fully *verified* CT subdomain stays Level 2 for all verification values.

## Benchmark method

Same frozen 200-domain cohorts as every prior run (Tranco top-100 = A, public-apis first-100 = B). Library
run directly in Node against the live web (no hosted-service change). Bounded caps per domain: ≤8 CT names,
≤8 sitemap hosts, ≤5 host verifications; 6 s per fetch, 20 s dedicated for the (slow) CT query. Paced with
cool-downs; resume-by-domain. Authoritative data: `v2alpha-results.jsonl`. No domain hardcoding.

- Integrity: 200/200 unique, **0 offline events**, 1 hard-timeout (googledomains.com — a giant-CT domain).

## 1. Additional useful results found

- **Useless-empty rate: v1 82.4% → balanced 78.4%** (199 scored; 1 errored). balancedPositive 21.6% vs v1 17.6%.
- **8 domains that returned NOTHING in v1 now return verified resources** via a subdomain: dzen.ru
  (ms.dzen.ru), nginx.org (lxr.nginx.org), nginx.com (docs.nginx.com), yandex.ru (cloud.yandex.ru), fixer.io,
  exchangerate.host, urlscan.io, api.amethyste.moe.
- **7 more domains that already had v1 results gained additional Level-2 items** (e.g. ipstack.com, sentry.io,
  screenshotlayer.com, mojoauth.com).
- Total: **15/199 seeds gained Level-2 (7.5%); 24 Level-2 items across 18 distinct new hosts.**
  By source: **same-registrable-domain (CT) 21**, publisher-linked (sitemap) 3.
- Cohort split: A (Tranco) v1 11 → balanced 15 positive; B (public-apis) v1 24 → balanced 28 positive. The
  gains skew to developer/API domains, as expected.

## 2. False / noisy associations

**Zero.** All 24 Level-2 associations are legitimate:
- 23 are `same-registrable-domain` — genuine subdomains of the seed (ms.dzen.ru, docs.nginx.com,
  api.exchangerate.host, …).
- 1 is cross-registrable: **fastly.net → fastly.com** (`publisher-linked`, via fastly.net's sitemap). This is
  Fastly's own alternate domain — a real relationship, correctly held at **Level 2 (not authoritative)**.

The noise-prone case the design worried about (a sitemap/link naming an unrelated high-degree host) occurred
**once in 200 domains, and it was legitimate**. No generic destinations (github.com, social platforms, CDNs)
were surfaced as results. (This is partly because Stage-1 sitemap discovery reads only sitemap `<loc>` hosts,
not an HTML footer link-graph — the link-graph is the deep tier, out of scope here.)

## 3. Classification mistakes

**Zero.** Level is structural (derives only from the evidence class), so no item can carry a wrong level;
`hosts appearing in both Level 1 and Level 2 = 0`. Every `same-registrable-domain` label was on an actual
subdomain; the one cross-registrable host was correctly `publisher-linked`, not `same-registrable-domain`.

## 4. Latency & request cost

| Metric | v1 | balanced |
|---|---|---|
| Requests (typical) | ~14–16 (one exact-host pass) | p50 **16**, mean 41, p90 **91** |
| Wall time | ~exact-host pass | p50 **~17 s**, p90 **~43 s** |
| Hosts verified/domain | — | mean 1.7 |

When CT/sitemap yield nothing (or CT aborts), balanced collapses to ≈ v1 cost (p50 = 16 requests). When it
does find hosts, it costs 40–90 requests and 20–40 s. **This confirms the plan's decision to keep
balanced/deep in the library (integrator compute) or async refresh — it is too slow/heavy for the synchronous
hosted path**, which must stay fast and bounded.

## 5. Authority ambiguity

**None found.** Level 1 and Level 2 are separate arrays; verification never promotes; 0 hosts appear in both.
The only cross-organization result (fastly.net→fastly.com) is unambiguously Level 2 `publisher-linked` with
provenance, never presented as authoritative or as "same organization".

## 6. Limitations (disclosed, not worked around)

- **CT coverage is partial: crt.sh aborted for 41.7% of seeds** (83/199) — flakiness and very-large cert sets
  (e.g. cloudflare.com, googledomains.com exceed even a 20 s timeout). This **understates** the CT adapter's
  real contribution; a more reliable CT source (CertSpotter, an operator's own log mirror) would find more.
- **Sitemap coverage is partial: 53.3% of seeds** had no apex `sitemap.xml` / robots-declared sitemap. Also
  an understatement.
- Per-domain caps (≤8 CT names, ≤5 verifications) bound cost; a few large domains have more subdomains than
  we probed. Every truncation/skip is recorded per row in `skipped`.

## Verdict

The balanced tier works, is honest, and is **clean**: +8 previously-empty domains rescued, 24 real Level-2
results, **zero false associations, zero classification mistakes, zero authority ambiguity**. The gain is
modest (useless-empty 82.4% → 78.4%) and would be somewhat larger with a reliable CT source — but it does
**not** approach the 60–80% ambition, which remains gated on **publisher adoption**, not discovery power. This
is consistent with every prior measurement. The two-axis model and provenance make the added results safe to
show precisely because each one says exactly why it exists and none claims authority it hasn't earned.

Nothing here changes production. Recommendation for review: the model and adapters are sound; before Stage 2
(which requires Charter v2 to be active), decide whether the modest, honest coverage gain justifies the
storage/registration machinery — and consider a more reliable CT source to raise the ceiling of this tier.
