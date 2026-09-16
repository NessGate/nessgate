# Competitive benchmark — first read (NessGate vs DNS-AID)

Harness: `benchmarks/competitive/run-competitive.mjs`; competitor `dns-aid-core` (IETF reference impl) via `--use-http-index` (DNS agent records + ARD-catalog dereferencing). Domains: frozen `holdout-unseen.json`. This is a **first read on the existing holdout**, not the final fair 7-day benchmark.

## The headline finding is a SCOPE distinction, not a coverage win

On supabase.com (verbose trace), DNS-AID **successfully fetched and parsed** the same `ai-catalog.json` NessGate reads, saw all 5 entries, then **deliberately skipped all 5** as `non_agent_artifact` (the MCP server, the management API, llms.txt, docs, skills). DNS-AID is an **agent-endpoint** resolver: it reads ARD catalogs but keeps only formal agent entries. NessGate is a **resource** resolver: it returns every machine-readable resource with provenance.

So they answer different questions. NessGate's larger output is **breadth-of-surface + resource-vs-agent scope**, NOT out-discovering a competitor on the same task. Per the review's own rule ("do not compare systems on functions they do not claim to perform"), NessGate is a correct *superset for resource discovery*; DNS-AID is correct *for agent discovery*. NessGate's breadth advantage on the ARD surface DECAYS as publishers put more into their ARD catalogs.

## Numbers (with honesty caveats)

- **NessGate recall (valid positives):** 97.0% mean; perfect on 32/33.
- **Stale ground truth found + excluded:** 2 positive domain(s) where NessGate found nothing AND every ground-truth path now 404s/redirects (domain changed since freeze): railway.app, neon.tech. These are re-probe/retire candidates, not misses.
- **Real misses (NessGate 0 but paths still live):** 1: wordpress.com {"/llms.txt":200}.
- **DNS-AID agent hits:** nonzero on 3/35 positives (zapier.com:1, huggingface.co:1, ucpchecker.com:1). Parse/tool errors: 0.
- **NessGate resources on surfaces DNS-AID cannot read (correct):** 50 hits across 32 domains.
- **Negative controls:** NessGate false-positive domains 0/12; DNS-AID nonzero 0/12.
- **Latency median:** NessGate 97 ms | DNS-AID 4885 ms. CAVEAT: not comparable — NessGate figures are warm edge-cache on the re-run (cold ~1–2 s); DNS-AID does live DNS + multi-path HTTP probing every call.

## Reliability note: hosted egress vs. the embeddable library

The one "real miss" (wordpress.com — `/llms.txt` returns a live 200 text/plain) is NOT a parser defect. The **hosted** resolver reproducibly returns nothing, but the **embeddable library** run from a normal client IP finds the llms.txt (verified live). wordpress.com bot-protects Cloudflare's worker-egress IP; a local agent is not blocked. This is a genuine limitation of any hosted resolver — and it validates keeping the library usable without nessgate.com, since running discovery in the agent's own context routes around datacenter-egress blocking.

## What this first read implies

The strategic question ("does NessGate discover what others miss?") resolves toward: on the same domains, NessGate and DNS-AID **read the same ARD catalogs**; NessGate additionally returns non-agent resources and reads ~12 non-ARD surfaces DNS-AID ignores. That is a real, correct, provenance-backed **superset for the resource-discovery task** — which supports the *integration-simplicity / one-resolver-covers-all* value thesis over a *distinctive-discovery-power* thesis. Recommend the full 7-day benchmark only add value by (a) sourcing domains with **real A2A/MCP agents** to test the agent-discovery subset head-to-head, and (b) adding the paid Apify ARD resolver as a second independent ARD reader. Absent those, this first read already answers the core question.
