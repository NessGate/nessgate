# NessGate real-world compatibility report

**Date:** 2026-09-17, fully re-probed and re-run **2026-09-21** · **Corpus:** 86 real domains ·
**2026-09-21 result (library 1.9.0 vs fresh independent ground truth):** 100% recall (87/87),
0 false positives, 0 silent misattributions, 0/37 negative-control triggers, 41 cross-domain
records from publisher rebrands (neon.tech→neon.com, railway.app→railway.com) all carrying the
honest `verified-external-location`/external labels. Latency p50 2.2 s · requests p50 18.

> **2026-09-21 re-run notes.** (1) Ground truth was independently re-probed corpus-wide —
> ground-truth aging is real: prisma.io began publishing `/openapi.json` after the original
> probe date, so the earlier run flagged a "false positive" that was actually a genuine find;
> the refreshed ground truth confirms it. (2) The attribution check now distinguishes **silent**
> misattribution (an off-domain `sourceUrl` with no honest label — a real defect, count: 0) from
> **labeled external records** (the library ≥1.7.0 follows a publisher's own wholesale redirect,
> records the final URL, and labels the result — correct behavior, counted separately). (3) One
> stress-stratum domain was replaced with `excalidraw.com` (SPA catch-all serving 200+HTML shells
> for every path — validators must reject all of it; they do). (4) Strata shifted slightly with
> the fresh ground truth (multi 25 / single 17 / negative 37 / blocked 7) as sites changed what
> they publish. The original 2026-09-17 report follows below.

This benchmark measures NessGate's discovery accuracy against **independently established
ground truth** on a diverse set of real domains — not against NessGate's own output.

## Method

1. **Independent ground truth** (`probe-groundtruth.mjs`) fetches each candidate path
   directly and validates it with its *own* shape checks. It imports nothing from
   NessGate's resolver, so ground truth is never defined by NessGate. Bounded and safe:
   HTTPS only, 12 s per-fetch timeout, 512 KB cap, a descriptive UA, DoH for DNS. It
   **never bypasses a 403/bot-wall** (those are recorded as `blocked`, not circumvented)
   and collects no credentials. Result: `corpus.json` — per domain, the expected
   resources with discovery path, source URL, protocol version, and verification date.
2. **NessGate under test** (`run-benchmark.mjs`) runs the reference library `resolve()`
   from the **same machine/egress** as the ground-truth prober, so a "miss" reflects
   NessGate's discovery *logic*, not an egress/bot-wall difference. It records correct
   discoveries, misses, false positives, incorrect attribution, latency, and request count.

## Corpus composition (86 domains)

Deliberately diverse and **not** curated to NessGate's wins — AI/dev companies, plain
businesses, news, government, education, retail, international sites, and known stress
cases (large specs, redirects, bot-walls). Strata (by independent ground truth):

| Stratum | Count | Meaning |
|---|---|---|
| multi | 24 | publishes ≥2 standards |
| single | 18 | publishes exactly 1 standard |
| negative | 36 | publishes none |
| blocked | 8 | bot-walled / 403 (unverifiable) |

The ground truth is honest about my priors: `target.com`, which I filed under
"negative-biz", actually publishes an llms.txt — the independent probe caught it and
reclassified it, and NessGate found it.

### Real-world adoption per standard (publisher counts across the 86 domains)

| Standard | Domains publishing |
|---|---|
| llms.txt | 41 |
| api-catalog (RFC 9727) | 15 |
| openapi | 13 |
| ard-catalog (well-known) | 10 |
| a2a-agent-card | 4 |
| ard-agentmap (robots) | 2 |
| ard-link (`<link rel="ard">`) | 1 |
| **ai-info.json, ORD, AWP, host-meta, ANP, UCP, AID, GB/Z 185.4** | **0** |

Eight of the fourteen supported channels have **zero** observed publishers in this corpus
(see Limitations).

## Results

| Metric | Value |
|---|---|
| Ground-truth resources on positive domains | 86 |
| **Correct discoveries (library)** | **86 / 86 (100% recall)** |
| Missed resources | 0 |
| False positives (after investigation) | 0 |
| Incorrect attribution (recorded source off-domain) | 0 |
| Negative controls that produced any output | 0 / 36 |
| Latency (library, same egress) | p50 1.8 s · p90 5.3 s |
| Request count per resolution | p50 18 · range 16–20 |

> **Library vs. hosted worker (important).** These figures are for the reference
> **library**, which follows redirects with `redirect:"follow"`. The **hosted
> `/discover` worker is domain-locked** and deliberately **refuses cross-registrable
> redirects** (SSRF safety). Two corpus domains wholesale-rebranded and redirect
> across a registrable-domain boundary — `neon.tech → neon.com` and
> `railway.app → railway.com` — so the worker finds **nothing** on them while the
> library follows the hop. **Hosted `/discover` recall on this corpus is therefore
> ~91% (78/86), not 100%** — the 8-resource gap is exactly these two rebrands, which
> the worker blocks by design. Two related caveats: (1) *at the time of this run*
> (library 1.6.0) a followed hop recorded the **pre-redirect** URL as `sourceUrl` and
> labeled it `verified-publisher-location`, understating that the bytes came from a
> different registrable domain — **fixed in library 1.7.0**, which records the final
> post-redirect URL and labels cross-registrable landings `verified-external-location`;
> (2) the "incorrect attribution" check inspects the recorded label, not the actual
> post-redirect byte origin, so *this run* could not see a cross-domain hop (a re-run on
> ≥1.7.0 would).

Request count reflects the **complete, ARD v0.91-conformant default** (all channels incl.
the required `rel="ard"` link + robots Agentmap + a DNS lookup); the opt-in `?fast=1`
mode drops ~2.

> **Post-run note (library ≥ 1.7.0):** capability enumeration adds **one** additional
> bounded read (1 MB cap) on domains whose OpenAPI document exceeds the 64 KB detection
> prefix and does not declare a `Content-Length` beyond the cap. The request-count
> figures above were measured on 1.6.0 and predate that read.

## False-positive investigation (the honest part)

The first run reported **11 "false positives."** Investigating each one — as the process
requires — showed that **all 11 were flaws in *my* ground-truth method, and NessGate was
correct in every case:**

| Domain(s) | Apparent FP | Truth |
|---|---|---|
| supabase, vercel, workos, neon, posthog, resend, turso, assemblyai (+clerk, pinecone via redirect) | `openapi` | Real, **large** openapi specs (115 KB – 10.8 MB). NessGate correctly head-detects them; my prober `JSON.parse`d a truncated 64 KB prefix and failed. NessGate even extracted the real titles ("Clerk Backend API", "Pinecone API"). |
| gitlab.com | `llms.txt` | Real 10 KB GitLab llms.txt at `about.gitlab.com/llms.txt` (the canonical host the apex redirects to). NessGate's canonical-host fallback found it; my prober only checked the apex (403). |

I then fixed the prober (head-marker openapi detection without full-parse; canonical-host
awareness) and re-ran: **0 false positives.** Lesson: an independent ground-truth tool
must match the thoroughness of the system under test, or it manufactures false failures.

**No confirmed NessGate bug was found, so no new bug-fixture was required.** The verified
behaviors (large-spec head detection, redirect-stub → real spec, canonical-host llms.txt)
are already covered by existing deterministic fixtures.

## Limitations (stated plainly)

- **Zero-adoption standards.** ai-info.json, ORD, AWP, host-meta, ANP, UCP, AID, and
  GB/Z 185.4 have **no observed publishers** in 86 domains. NessGate's support for them is
  validated only by synthetic and official-example fixtures, **not** real domains — because
  real-world adoption is currently ~0. This is evidence, not a defect: it says which
  standards are speculative today.
- **Snapshot in time.** Ground truth was verified 2026-09-17. Websites change; this corpus
  is **live monitoring**, kept out of deterministic CI. Re-run to refresh.
- **Egress.** Results use the library from an ordinary IP. The hosted worker's egress can be
  bot-walled where an in-agent library call is not (e.g., the library reached
  `about.gitlab.com`; earlier, wordpress.com's llms.txt was reachable from the library but
  not the worker). The embeddable library is the mitigation for egress-sensitive domains.
- **Blocked stratum (8):** homedepot, medium, npmjs, nytimes, openai, perplexity, reddit,
  toyota return 403/bot-walls; ground truth is "unknown", not "none". Not circumvented.
- **Coverage, not exhaustiveness.** 86 domains is a sample, weighted toward AI/dev
  publishers and common negatives; it is not a random draw of the web.

## Prioritized improvements (evidence-based)

1. **Latency tail, not accuracy.** p90 is 5.3 s, driven by *slow-responding* domains where
   all ~14 probes are slow 404s (anthropic 14 s, nike 14 s, stanford 13 s — all negatives),
   **not** by large-spec fetches (those prefix-abort quickly). The opt-in `?fast=1` mode
   already cuts probes; a further win is a shorter per-probe timeout or an early-abort when
   the homepage itself is very slow. No correctness change.
2. **Mark the 8 zero-adoption channels provisional.** They are cheap, correct, and
   spec-grounded — keep them (do not add more just to grow the count), but label them
   low-adoption in the docs and re-measure adoption periodically. Focus latency/DX effort on
   the adopted standards (llms.txt, api-catalog, openapi, ard, a2a).
3. **Document library-first for egress-sensitive callers.** The data shows bot-walls affect
   hosted-egress discovery on ~10% of domains; the in-agent library routes around it.
4. **Benchmark-tooling discipline (applied).** Independent ground truth must match the
   system's thoroughness (large-file head detection, canonical-host follow) — folded back
   into `probe-groundtruth.mjs`.

## Reproducibility & CI separation

```
node benchmarks/realworld/probe-groundtruth.mjs   # rebuild independent ground truth → corpus.json
node benchmarks/realworld/run-benchmark.mjs        # NessGate vs ground truth → results.jsonl + summary
```

This corpus is **live monitoring** and lives in `benchmarks/` — deliberately *not* in the
CI gate, because real domains change or go offline without NessGate being broken.
Deterministic, document-level regression fixtures live separately in `compat/fixtures/` and
run in CI. Any confirmed bug from a future run becomes a permanent fixture there.
