# Resolver v1.5 coverage benchmark — 2026-09-15

Reproducible coverage measurement of the NessGate resolver across two predetermined cohorts.
Raw per-domain rows: `results-a.jsonl`, `results-b.jsonl` (engine run), `results-prod.jsonl`,
`results-prod2.jsonl` (hosted attempts). No resolver code was changed during measurement.

## Cohorts (predetermined; no selection judgment)

- **A — general web (100):** Tranco top-100, in rank order (`cohort-a-tranco100.txt`).
- **B — developer/API (100):** first 100 unique first-column link domains, in file order, from the
  public-apis curated list (`cohort-b-publicapis100.txt`), deduplicated against A.

Per domain, three layers measured separately: exact `GET /discover/{d}`; incremental `?org=1`
(`stats.sameDomainHost`); incremental `?related=1` (`related[]`). "Positive" = at least one
resource/entry; "empty" means **no supported resources were confirmed through NessGate's current
bounded deterministic sources** — it is not a claim that the domain publishes nothing anywhere.

## Engine results (v1.5 worker under `wrangler dev`, residential egress ≈ the embeddable-library path)

| | exact positive | +org=1 | +related=1 | any-layer | empty (unconfirmed) | blocked | latency p50/p90 (triplet) |
|---|---|---|---|---|---|---|---|
| **A** general | 9.0% | +10.0% | +10.0% | **23.0%** | 77.0% | 0% | 13.1s / 29.6s |
| **B** dev/API | 24.0% | +16.0% | +0.0% | **30.0%** | 70.0% | 0% | 13.8s / 27.8s |

Layer behavior matched design: `related=1` fired on majors with declarations/registry entries
(google, microsoft→github.com via the MCP Registry's `com.microsoft` namespace, twitter↔x,
wikipedia, pinterest); `org=1` lifted the developer cohort most (developers./docs. subdomains).

## Hosted verification — could not be completed cleanly from this environment

Two independent failure modes contaminated hosted runs from the operator's network and are
findings in their own right, not resolver-logic results:

1. **Local-vantage connection drops** under sustained test volume (same-machine browser requests
   succeeded while curl failed; zone security logs show no blocks — cause unconfirmed; consistent
   with home-router/NAT exhaustion).
2. **Worker `1102`/503 "exceeded resource limits" on heavy routes** after sustained benchmark
   load, while light routes (`/version`, small discovers) kept serving. An agent-facing API doing
   this much per-request work needs plan-level CPU headroom (operator decision).

The 13 clean rows completed before contamination corroborated the engine numbers exactly
(google `related=3`, cloudflare `discover=3`, microsoft `related=1`).

## Empty-result pattern grouping (147 domains, systematic probes; content-validated)

| recurring pattern | count | note |
|---|---|---|
| no functional homepage | 34 | infrastructure/CDN/parked hostnames in the Tranco top ranks |
| canonical redirect **within** registrable domain, valid files on canonical host | 3 (2 content-confirmed) | apex→www/sub fallback would recover these |
| canonical redirect to a **different** registrable domain, files there | 5 | publisher-redirect **candidates** only — must pass the evidence rules, never silently authoritative |
| valid `security.txt` present *(diagnostic only — not evidence of anything)* | 17 | |
| remainder | — | no supported resources confirmed through current bounded sources |

**www spot-check (27 suspected www-only llms.txt):** 23 were SPA/redirect HTML shells, 4 passed
the text validator — of which one (`office.com`) was a **validator false positive** (an HTML
login page beginning with an HTML comment slips past the doctype check), one was a cross-domain
redirect (`fastly.net→fastly.com`), and two (`capgemini.com`, `covalenthq.com`) are genuine
www-only publishers.

## Proposed general deterministic rules (no domain exceptions; no evidence-model weakening)

1. **Canonical-host fallback (same registrable domain only).** When the apex homepage redirects to
   `www.`/a subdomain of the same registrable domain, probe the canonical host too. Recovers the
   confirmed www-only publishers; measured yield ≈ +1–1.5%.
2. **Content-type guard for text probes.** Reject `text/html` responses for `llms.txt`-class
   probes (closes the comment-prefixed-HTML false positive). Strengthens, not weakens, evidence.
3. **Cross-domain homepage redirect as a publisher-redirect candidate.** Feed
   apex→other-registrable-domain redirects into the existing Related-Discovery evidence classes
   with redirect provenance — never treated as the same authoritative host.

## Verdict

The resolver is technically sound and every layer behaves as designed, but real-world any-layer
coverage is **23% (general web) / 30% (developer-API)**: for most of the web, no supported
resources can be confirmed through current bounded sources, dominated by non-adoption of
publisher-side standards. The three rules above are the only general coverage improvements the
data supports; the larger lever is adoption, not resolution.
