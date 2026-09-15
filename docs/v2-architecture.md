# NessGate v2 — Architecture and Migration Plan

Status: PROPOSAL (nothing implemented; per directive, plan before code)
Date: 2026-09-15
Inputs: v1.6.0 frozen codebase audit · frozen-200 benchmarks (NessGate v1.6 + NessReady P1/P2) · Neutrality Charter (live) · strategic directive of 2026-09-15

---

## 0. What the evidence actually supports (constraints on this plan)

Facts this plan is built on, so we do not design against wishes:

- **v1.6 strict+explore coverage:** 57/200 frozen-cohort seeds positive (28.5%).
- **NessReady P2 with everything on** (crawl, CT, GitHub, npm, unbounded verification): 53/200 seeds gained beyond-T0 verified items; union with strict ≈ 40–45%. **No configuration of discovery reached 60%+.** The remaining gap is publishers that publish nothing machine-readable. Discovery cannot find what does not exist.
- **What produced coverage:** publisher link-graph reading + removing per-invocation verification budget ≈ most of the gain; CT subdomains +6 verified orgs; sitemaps +1; GitHub org evidence +0 verified orgs (18 corroborating evidence rows); npm +0 (evidence rows only).
- **Hosted-worker physics:** synchronous deep discovery hit CPU limits (1102), needed 20 s deadlines, and a full deep report takes ~97 s even queued. A universal resolver cannot answer like that.

Consequences:
1. The coverage target for v2 is honest: **~40–50% organization coverage** with useful verified resources; 60%+ is reachable only through the **publishing side** (§9), not through more discovery.
2. The one discovery mechanism that materially moves coverage — bounded publisher-surface reading — is exactly the one requiring a charter amendment (§10). It is a deliberate decision, not a technical detail.
3. Depth belongs in the **open-source library** (integrator pays compute) and in **asynchronous index refresh**, never in the synchronous hosted path.

---

## 1. Two-level / two-axis result model

Adopt the NessReady two-axis model as the foundational result shape, mapped to the directive's two levels.

Every result item carries two independent facts:

```
verification: verified | unreachable | none        (is the resource real? from which vantage?)
relationship: <evidence class>                     (why is it associated with the query?)
```

Evidence classes (existing /explore classes, renamed only where noted, no numeric scores ever):

| Level | Classes |
|---|---|
| **Level 1 — Authoritative** | `publisher-hosted`, `publisher-declared`, `registered` (new, §9), `namespace-verified` (federated registry, domain-authenticated), `publisher-declared-related` (RWS/Asset Links) |
| **Level 2 — Discovered** | `same-registrable-domain` (rename of `same-domain-host`, aligns with published wording "namespace proximity only"), `publisher-linked` (new: reached via the publisher's own pages/sitemap), `registry-attributed` (registry entry without domain authentication), `publisher-redirect-candidate`, `infrastructure-correlated` (signal only, never promotes), `candidate` (caller-supplied) |

Rules (already proven in NessReady, now normative):
- Verification NEVER upgrades relationship. A verified resource on a linked host is still `publisher-linked`.
- Level 2 is returned in a structurally separate array (`discovered[]` beside `resources[]`), never merged.
- Every item carries `provenance[]` (the reproducible path: which page/file/record led here, every hop).
- The per-report noise rule from NessReady (boilerplate-ubiquity + reciprocal-mention → `presentation: demoted-generic`, evidence preserved) ships with `publisher-linked` from day one, so the open resolver never returns "github.com" as a top result for every domain that has a footer link.

**Useful-empty:** an empty answer must state which mechanisms were checked and link the publishing path ("publish llms.txt / register your declaration") — converting the resolver's biggest weakness into the adoption funnel for §9.

## 2. Index / database schema and TTL strategy

One logical table (`records`), small pointer records only — never page content:

```
record_id        (hash of domain+source+url)
domain           (registrable domain, normalized)
host             (exact host)
url              (resource URL)
type             (open label: llms.txt, ard-catalog, a2a-agent-card, …)
verification     (verified | unreachable | none) + verified_at + vantage
relationship     (evidence class)               + level (1|2)
provenance       (JSON, bounded size ~2 KB)
origin           (declaration | registration | federation:<registry> | resolution)
first_seen / last_verified / expires_at (TTL)
record_version
```

TTL policy:
- **Authoritative records** (origin = declaration/registration/federation): TTL 7 days, background re-verification before expiry; a failed re-verification marks `verification: unreachable` but never deletes the registration — the publisher's declaration is the fact being recorded.
- **Discovery cache** (origin = resolution): TTL 24 h hard. Expired means gone (row deleted), not stale-served. Nothing discovered ever outlives its TTL without being re-derived.
- Estimated size: ≤2 KB/record ⇒ 1 M domains ≈ low GB. D1 is sufficient for years.

## 3. Authoritative index vs discovery cache — the write-path rule

The single most important structural rule, stated once and enforced everywhere:

> **Records enter the authoritative index only by publisher declaration, verified registration, or registry federation. Resolution (including all discovery) can only ever write to the TTL-bounded discovery cache. There is no code path from discovery to authority.**

This is what keeps the index "an index/cache of evidence and resolution state, not an authority because NessGate stores it." A publisher can purge their domain's discovery-cache rows on demand (same spirit as robots opt-out); authoritative rows are removed by the publisher revoking their declaration.

## 4. Storage abstraction and the D1 reference implementation

The library defines a minimal store interface; every feature in this plan is written against it:

```js
// @nessgate/resolver storage interface (all optional — a null store = today's stateless v1)
{ getRecords(domain), putRecords(records[], {origin, ttl}), purge(domain, origin?), touch(record_id) }
```

- Reference implementations shipped in-repo: `memoryStore` (tests), `sqliteStore` (self-hosters), `d1Store` (nessgate.com).
- The hosted nessgate.com is the **reference public resolver**, not the protocol. The neutrality test in the directive becomes a CI test: the conformance suite (§15) must pass identically against a resolver with no store and a fresh store — same conclusions from the same public evidence, storage affecting latency only, never classification.

## 5. Resolver tiers: fast / balanced / deep

Library API (additive; `resolve(domain)` unchanged = fast, no store):

```js
resolve(domain, { tier: "fast" | "balanced" | "deep", store?, budget? })
```

| Tier | Contents | Budget (defaults) | Where it runs |
|---|---|---|---|
| **fast** | index read (if store) + strict exact-host adapters (current v1 resolve) | ≤ 12 requests, ≤ 5 s | hosted `/discover`, everywhere |
| **balanced** | fast + current /explore (declared pointers, org shortlist, RWS/Asset Links, redirect, registry federation) + **CT subdomains** + **sitemap hosts** | ≤ 30 requests, ≤ 20 s | hosted `/explore` (existing limits retained), integrators |
| **deep** | balanced + bounded publisher-surface link reading (charter-gated, §10) + full per-candidate verification | integrator-defined | **library only** (integrator compute) + hosted async refresh (§7) — never the synchronous hosted path |

Every budget truncation is disclosed in the response (`truncations[]`), as today.

## 6. Adapter architecture

Formalize the existing `ADAPTERS` array into self-describing plug-ins (the long-term moat):

```js
{
  id, standard,                     // "llms.txt", "ard-catalog", "ct-subdomains", …
  discovers: "resources" | "hosts" | "relationships",
  evidenceClass,                    // what it can produce
  canEstablishAuthority: boolean,   // Level 1 capable? (only declaration/registration/authenticated-registry adapters)
  tier: "fast" | "balanced" | "deep",
  budget: { requests, bytes },
  external: null | "ct-log" | "registry:<name>" | …,   // network dependency
  run(ctx) → { items[], provenance }
}
```

Existing 14 adapters migrate mechanically (all `tier: fast`, `discovers: resources`). New in v2: `ct-subdomains` (balanced, hosts, `same-registrable-domain`), `sitemap-hosts` (balanced), `publisher-surface` (deep, charter-gated), `mcp-registry` / `agntcy` / `nanda` federation adapters (balanced, `namespace-verified` when domain-authenticated, else `registry-attributed`). Third parties add future standards without touching core. Adapter acceptance criteria for the open core: deterministic, reproducible, no paid dependency, no AI inference.

## 7. Asynchronous deep-resolution / index-update flow

Hosted behavior (Queues + the storage layer):

```
query → serve fast tier from index+live immediately (labelled, with per-record freshness)
      → if the domain has no fresh balanced-tier cache AND passes demand gating:
          enqueue one bounded balanced/deep refresh job (NessReady jobs pattern:
          one candidate verification per queue message, fresh budget each)
      → next query gets the richer cached answer
```

Demand gating (abuse control, §12): refresh jobs run only for (a) domains with authoritative records, or (b) domains queried ≥ N times in a window, and at most once per domain per 24 h. Anonymous single queries never trigger deep work — a free deep-crawl-on-demand endpoint is an abuse magnet we already understand from P1 hardening.

## 8. Registry federation

Read-side federation, already consistent with the charter ("reads them and points back"):
- Adapters for MCP Registry (exists in /explore today), AGNTCY Directory, NANDA index; each declares its authentication semantics.
- Domain-authenticated registry entries → Level 1 `namespace-verified`; unauthenticated attribution → Level 2 `registry-attributed`.
- Federated results are cached in the discovery cache with the registry named in `origin`; NessGate never claims to be the source.
- NessGate does not compete with registries: the strategic position is *many registries → one evidence-labelled normalized answer*.

## 9. Publisher registration / declaration (the coverage lever that actually reaches 60%+)

Constraint carried over from the 2026-09 direction decision: **NessGate ships no publish file of its own.** The front-door-manifest niche is already taken (AWP `/.well-known/awp.json`, A2A `agent.json`, ARD `ai-catalog.json`); a NessGate-specific file would be the reinvention trap and would recreate a publisher-adoption barrier. Declarations therefore ride entirely on the standards NessGate already reads:

- **Declaration = the domain's existing standard files.** An ARD catalog, AWP manifest, llms.txt, etc. IS the publisher's declaration; entries pointing at other hosts are cross-domain declarations. Level 1 `publisher-declared` (already exists in /explore) covers this today. Cross-registrable-domain claims are Level 1 only with bidirectional evidence (both sides declare, or RWS/Asset Links — also already implemented), else Level 2.
- **Registration** (optional attestation, account-less): `POST /register {domain}` → challenge (DNS TXT `_nessgate.<domain>` or `.well-known` proof file, one-time signed tokens) → authoritative index row (`origin: registration`, class `registered`) pinning *what the domain already publishes*, TTL 7 d with re-verification. No accounts, no email, no user data — the domain proves itself, ACME-style. **This machinery existed and passed production e2e before the pivot retired it** (D1 registry, DNS-TXT/file/json-field proofs, SSRF-hardened) — revival, not greenfield, which materially lowers §14 stage-4 risk.
- **Tooling**: WP plugin already writes `ai-info.json`/`llms.txt`/verification files — it becomes the registration client; the useful-empty response (§1) links to the publishing guide.
- Coverage past the ~50% discovery ceiling comes from publishers adopting the *existing* standards (which registration incentivizes and the plugin automates) — not from a new NessGate format.

## 10. Exact Neutrality Charter changes (public, versioned — Charter v2)

Verbatim clauses in conflict, and the proposed amendment for each. Nothing changes silently; charter page shows a change log.

| Current charter text (verbatim) | Conflict | Proposed v2 text (substance) |
|---|---|---|
| "Nothing is crawled, indexed, or persisted. Each answer is computed fresh and dies with its short edge cache." | Persistent index + cache | "NessGate keeps two kinds of state, both inspectable: **records publishers declared or registered** (kept until revoked, re-verified on a schedule) and a **short-lived resolution cache** (each entry expires within 24 hours and is re-derived only from public evidence). It builds no content corpus: no page text, no search index — only pointers with provenance." |
| "it never stores, rehosts, owns…" / "NessGate keeps no user data and no domain data" | Registration rows | "No accounts and no user data, ever. Domain records exist only when the domain itself declared or registered them, and the publisher can revoke or purge at any time." |
| (implied by "reads them on demand" + spec "reads what a domain publishes at the standard machine-discovery locations") | Publisher-surface reading (deep tier) | New clause: "In its broader discovery tiers NessGate may read the publisher's **own** public pages at resolve time — bounded, robots-respecting, provenance on every hop — solely to follow the publisher's own links. It never builds a search-engine-style corpus, never reads third-party sites *about* a publisher, and never presents a discovered relationship as authoritative." |
| "It does not rank, score, rate…" | none — reaffirm | Unchanged. Explicitly reaffirm: no numeric confidence scores; evidence classes only; discovered results ordered by evidence class then alphabetically (no ranking). |

Unchanged commitments (free forever, no ranking sales, neutrality, open spec, resources live on the domain) are restated verbatim in v2. **The charter amendment is the first public artifact of v2 — shipped and announced before any persistent storage goes live.**

## 11. Backward compatibility

- `/discover/{domain}` and `/explore/{domain}` responses: additive changes only (new fields `level`, `discovered[]`, `freshness`, `origin`); existing fields and semantics unchanged. Spec §5 additive rule is honored — no `/v2/` path needed for the planned shape.
- `@nessgate/resolver` v1 `resolve(domain, opts)` behavior is byte-compatible when no `tier`/`store` is passed; v2 features are opt-in options. Semver: 2.0.0 (new options, same default behavior).
- The MCP server gains a `tier` argument, defaulting to today's behavior.
- Freeze discipline: the v1.6 strict path remains the reference behavior; the conformance suite pins it.

## 12. Hosted-service resource and abuse limits

- Synchronous paths keep current budgets (10/60 s edge burst; /discover 120/h; /explore 60/h; 20 s deadline; 24 req; 6 MB) — v2 makes the hosted service FASTER (index hits), never heavier.
- Registration: 5/day/IP + one pending challenge per domain.
- Async refresh: demand-gated (§7), global daily job budget, per-domain 24 h cooldown, queue depth capped; refresh jobs use the NessReady one-candidate-per-message pattern so no invocation exceeds platform budgets.
- All storage rows carry origin + TTL, so cost is bounded by real demand, not by the size of the web.

## 13. NessReady → OSS moves, and what stays commercial

**Moves into OSS NessGate** (deterministic, reproducible, free-source): two-axis model + noise rule; CT-subdomain adapter; sitemap-host adapter; publisher-surface adapter (deep, charter-gated); per-candidate embedded verification pattern; storage interface + reference stores; queued-refresh pattern.

**Stays in NessReady** (explicitly commercial): paid search APIs; AI-assisted candidate generation; multi-vantage fetching; history/monitoring/diffs/alerts; organization reports and PDF artifacts; done-for-you setup; SLAs. **NessReady has no private definition of "NessGate verified"** — it calls the same open resolver; its value is breadth, vantage, history, and workflow, not a different truth.

## 14. Staged implementation order (smallest safe first release)

1. **v2.0-alpha (library only, no charter change needed):** two-axis/two-level result shape in `@nessgate/resolver`; adapter formalization; `tier: balanced` with CT + sitemap adapters; conformance tests. Hosted service untouched.
2. **Charter v2 published** (with change log + announcement). Gate for everything below.
3. **v2.0:** storage interface + D1 discovery cache on nessgate.com (24 h TTL) + `freshness` in responses; hosted /explore adds CT+sitemap (within existing budgets).
4. **v2.1:** registration challenge flow (revived, per §9) + authoritative index; useful-empty responses linking the publishing path; WP-plugin registration client.
5. **v2.2:** async demand-gated refresh (Queues); registry federation adapters (AGNTCY, NANDA; MCP Registry already present).
6. **v2.3:** publisher-surface deep adapter in the library (integrator-run); hosted deep only via async refresh.

Each stage is independently shippable and reversible; the frozen v1.6 behavior remains the fallback throughout.

## 15. Benchmark criteria (did v2 work without compromising trust?)

Re-run the SAME frozen 200-domain cohorts (no new cohorts, no hardcoding, no optimizing around examples) after stages 3, 5, and 6:

- **Useless-empty rate** (primary): fraction of seeds returning zero items at balanced tier. v1.6 baseline: 71.5%. Target after stage 6: ≤ 55% — honest given the measured publishing ceiling; anything better comes from §9 adoption, tracked separately as *declared-domain count* (an adoption metric, not a benchmark metric).
- **Trust invariants (hard gates, any failure blocks release):** zero Level 2 items presented as Level 1; zero classification differences between store-backed and stateless runs on identical evidence (§4 test); zero results derived from non-public or paid sources; spot-audit of 30 random verified items shows ≥ 95% genuinely live and correctly classed (P1 audit method).
- **Latency:** p50 of cached balanced answers < 1 s; p50 cold fast answers ≤ current /discover.
- **Noise:** generic high-degree destinations (measured per report, no host list) appear as primary in < 5% of reports where the noise rule has ≥ 3 crawled pages of signal.
- Every benchmark publishes methodology + raw JSONL, as before.

---

### Out of scope for v2 (explicit)

Web search, AI candidate generation, historical snapshots, monitoring, multi-vantage, paid anything — NessReady. Global federation of NessGate instances (multiple index operators with delegation) — a v3 question; v2's storage abstraction and origin-tagged records are designed so it becomes possible without schema breakage.
