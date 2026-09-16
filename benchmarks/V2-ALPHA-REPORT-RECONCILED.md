# NessGate v2 alpha (Stage 1) — RECONCILED benchmark & audit

Date: 2026-09-15 · **Experimental. Charter v2 is NOT active.** Supersedes the coverage claims in
`V2-ALPHA-REPORT.md`, which compared against the wrong (exact-host-only) baseline. That file is kept
in git history; this one corrects it openly.

> Correction, stated plainly: the first Stage-1 report measured the discovery adapters against
> exact-host-only resolution (~35/200), not against the full v1.6 strict+explore capability
> (57/200). This report re-measures apples-to-apples and reports the **true incremental** of CT +
> sitemap **over the full existing capability**.

## 1. Audit — why the old baseline was 57/200 but the Stage-1 "v1" was ~35/199

From the frozen v1.6 baseline (`results2-a/b.jsonl`, the same run that produced the 57 figure):

| Layer | Positive domains |
|---|---|
| exact-host (`/discover`) | **33 / 200** |
| + Organization Discovery (`?org=1`, same-registrable subdomains) | +12 → 45 |
| + Related Discovery (`?related=1`, cross-domain declared/registry) | +12 → **57 / 200** |

- The Stage-1 library `resolve()` is **exact-host only** — it reproduces the 33 (my run got 35,
  network drift + the canonical-host fallback). **It never included `/explore`.**
- Therefore the ~35-vs-57 gap is **entirely the `/explore` contribution** (org + related discovery,
  registry evidence, redirect candidates), which lives in `src/worker.js` and depends on the worker
  `env` (KV cache, rate limits) — it is not a pure importable function.

**Conclusion:** the first benchmark proved the new adapters are structurally safe and add *some*
results, but measured them against a baseline 24 domains weaker than the real one. Fixed below.

## 2. Did the Stage-1 "balanced" tier include the `/explore` capabilities? No.

The architecture defines `balanced` = fast + `/explore` (declared pointers, org discovery, related
discovery, registry evidence, redirect candidates) + CT + sitemap. The Stage-1 library tier had only
**exact-host + CT + sitemap** — it was missing every `/explore` capability.

## 3. Resolution — renamed, not silently redefined (your option 3b)

- The Stage-1 library tier is renamed **`discovery`** (exact-host + CT + sitemap). `balanced` and
  `deep` now **throw NotImplemented** (they require `/explore` delegation, not yet in the library),
  so nobody can receive a partial "balanced". Committed `4545e8a`, tests updated.
- Integrating `/explore` into a true library `balanced` is the deferred next experimental step.
- For this benchmark, **B is measured with the REAL `/explore`** (unchanged production code, run via
  a local worker) composed with the library's CT/sitemap adapters — a faithful measurement of the
  capability set, not a reimplementation that could diverge.

## 4. Method (apples-to-apples, one run per domain)

Same frozen 200-domain cohorts. Per domain, a single execution produced both:
- **A** = `GET /explore/{domain}?org=1&related=1` against a **local `wrangler dev`** worker of
  unchanged `src/worker.js` (per-domain `CF-Connecting-IP` to avoid self-throttling).
- **B** = A's explore output ∪ the library `discovery` tier's CT + sitemap Level-2 items, deduped by
  host. The **incremental** = discovery hosts explore did **not** already find.

Bounded caps (≤8 CT names, ≤5 host verifications, 6 s/fetch, 20 s CT). Paced, resumable, detached,
worker-health-monitored. No domain hardcoding. Authoritative data: `v2reconcile-results.jsonl`.

## 5. Results

200/200 domains, **0 explore failures** (local worker stayed up throughout), 1 hard-timeout
(googledomains.com — giant CT set). Analyzer: `v2reconcile-analysis.json`.

- **Coverage:** A (strict+explore, fresh) = **55/200 (27.5%)** — matches the historical frozen
  57/200 within network drift. B (+CT+sitemap) = **57/200 (28.5%)**. **True incremental domains = 2.**
- **Rescued-from-empty** (explore found nothing → CT rescued): **2 domains** — `dzen.ru`
  (ms.dzen.ru) and `nginx.org` (lxr.nginx.org). Both are real `llms.txt` on non-conventional
  subdomains explore's org shortlist doesn't probe.
- **Level-2 additions:** 25 discovery items across 18 hosts. Of those hosts, **10 overlapped** what
  explore's org/related discovery already found (no new coverage) and **8 were genuinely new**. By
  source (incremental): same-registrable (CT) 7, publisher-linked (sitemap) 1. The other 6 new hosts
  add *depth* (extra resources) on domains explore already marked positive — not new domains.
- **The 8 genuinely-new hosts, audited by hand — all legitimate:** ms.dzen.ru, awesome-copilot.github.com,
  lxr.nginx.org, cloud.yandex.ru, ipstack-static-website.ipstack.com, blog.fixer.io,
  blog.exchangerate.host, enterprise-ciam.mojoauth.com. Every one is a genuine property of its seed.
- **False / noisy associations: 0.** Zero cross-registrable incremental hosts. No generic
  destinations surfaced.
- **Authority / classification mistakes: 0.** Level is structural; 7 same-registrable labels are all
  actual subdomains, the 1 publisher-linked (cloud.yandex.ru) is Yandex's own property. No host
  appeared in both levels.
- **Latency / request cost:** explore p50/p90 = 11/13 req; discovery p50/p90 = 17/91 req; combined
  wall time p50 ~21 s, p90 ~65 s. (Combined double-counts the exact-host pass, which a unified
  balanced would share once.) Confirms discovery/balanced belongs in the library or async, never the
  synchronous hosted path.
- **Adapter failure rates:** crt.sh aborted **39.0%** (78/200); sitemap absent **53.0%** (106/200).
  So the +2 domains / +8 hosts is a **lower bound** — a reliable CT source would recover some of the
  aborted 39%.

## 6. CT-source investigation (reliability, openness, reproducibility, rate limits, substitutability)

crt.sh's unreliability directly caps this tier: in-run it aborted for a large fraction of domains.
Alternatives evaluated:

| Source | Open / keyless | Reliability | Rate limits (free) | Reproducible / operator-independent |
|---|---|---|---|---|
| **crt.sh** | Yes, keyless | **Poor** — shared Postgres, frequent overload/downtime; undocumented limits | Undocumented | Yes (anyone can query) but often unavailable |
| **CertSpotter (SSLMate)** | Yes, keyless free tier | Good, well-maintained | ~10 full-domain (`include_subdomains`) + 100 single-host / hour keyless; keyed for volume; 75/min, 5/s | Yes; keyed for scale |
| **ctlogs.dev** | Yes | Built for load; crt.sh-compatible | Not formally published | Yes — **drop-in** (`?q=&output=json`, same wildcard style) |
| **Own CT-log mirror** (query CT logs directly) | Yes | Highest (self-hosted) | Self-imposed | **Most** independent; heaviest to operate |

**Architecturally this is already a non-issue.** CT is a self-describing adapter
(`external: "ct-log"`); an operator can point it at crt.sh, CertSpotter, ctlogs.dev, or their own
CT-log mirror **without touching the two-axis model or any other code**. No CT provider is baked into
the protocol — which is exactly the operator-independence / reproducibility property Charter v2
promises.

**Recommendation (honoring "do not switch sources merely to improve benchmark numbers"):** keep the
default source pluggable and documented; do **not** silently swap the default to whatever scores
best. The benchmark discloses crt.sh's abort rate as a measurement floor. If Stage 2 proceeds, the
CT adapter should ship with a documented, substitutable source (CertSpotter or ctlogs.dev as the
reliable default for hosted use; crt.sh acceptable for self-hosters), chosen for reliability +
openness, not for a benchmark delta.

## 7. Verdict

Measured honestly against the **full** existing capability, CT + sitemap add **2 net new domains**
(27.5% → 28.5%) plus extra depth on 6 already-positive domains — not the "+8 domains" the first
report claimed against exact-host-only. The reason is structural and was predictable: `/explore`'s
Organization Discovery already probes the conventional subdomains (docs/api/blog/developers), so
10 of 18 discovery hosts overlapped; CT's genuine contribution is the *non-conventional* subdomain
(lxr., ms., awesome-copilot.) that a shortlist can't guess. That contribution is real, and it is
**understated** by crt.sh's 39% abort rate — a more reliable CT source would raise the floor
somewhat, though explore already covers the common cases, so even perfect CT likely adds a modest
number.

What Stage 1 proves is **safety and correctness, not a coverage breakthrough**: across 200 domains
the two-axis model produced zero false associations, zero classification mistakes, and zero
authority ambiguity, with full provenance. But the coverage delta over what NessGate can *already*
do does not, on this evidence, justify Stage 2's storage + registration machinery on
discovery-power grounds. **The ceiling remains publisher adoption**, exactly as every prior
measurement found — which is the argument for prioritizing the publishing side (declaration files,
registration, the WP plugin) over more discovery.

Recommendation for the Charter-v2 / Stage-2 decision: treat the discovery adapters as a proven,
safe, *optional* library capability; do not stand up persistent storage/registration to chase a
2-domain gain. If Stage 2 proceeds, justify it on the **publishing + index-freshness + latency**
value (fast cached authoritative answers), not on discovery recall — and ship the CT adapter with a
reliable, substitutable source (§6). Charter v2 need not be activated to keep the library alpha
available; activation should wait until there is production behavior that actually requires it.
