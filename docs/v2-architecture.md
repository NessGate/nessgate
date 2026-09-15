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

Layer assignment (derived from origin + authentication, never from the mere fact of storage):
- **Authoritative layer** — origin = publisher declaration, verified registration, or **domain-authenticated** federation. Re-verified on a schedule (reference default: 7-day window; exact values are spec, not protocol). A registration is an *attestation* that the domain proved control and pointed at resources it publishes at a point in time; that attestation may persist, **but a resource's authoritative status follows its current publication, not the past registration.** A declared resource that is removed, or stays unreachable past its freshness window, drops out of Level 1 presentation even though the registration attestation remains on record — a registration once made never keeps a dead resource "official." (Transient re-verification failure flips a resource to `unreachable`; genuine removal drops it from the authoritative layer entirely.)
- **Discovery layer** — origin = resolution (any discovery adapter) **or unauthenticated registry attribution**. Short TTL (reference default: 24 h), re-derived on expiry, never stale-served, never authoritative.
- Estimated size: ≤2 KB/record ⇒ 1 M domains ≈ low GB; the reference deployment uses Cloudflare D1, but the store is abstract (§4). Exact TTLs, engine, and eviction are spec/operational details, not protocol.

## 3. Authoritative index vs discovery cache — the write-path rule

The single most important structural rule, stated once and enforced everywhere:

> **A record enters the authoritative layer only by publisher declaration, verified registration, or domain-authenticated federation. Resolution — every discovery adapter — and unauthenticated registry attribution can only ever write to the short-TTL discovery layer. There is no code path from discovery to authority.**

This is what keeps the store "an index of evidence and resolution state, not an authority because NessGate stored it."

**Purge rights are scoped by provenance, not by layer (Principle 10):**
- **Records a publisher owns** — its own declarations, its own registrations, and NessGate's reads of *its own* pages/files (the publisher-surface crawl) — are fully under the publisher's control: revoke, purge, or robots-opt-out at any time, and they are gone.
- **Independently sourced evidence about a domain** — certificate-transparency records, inbound declarations *from other publishers* that point at it, third-party registry attributions — is governed by provenance and TTL, **not on-demand erasure.** It is always Level 2, always names its independent source, and always expires on its own schedule. A publisher who disputes it may publish its own authoritative declaration, which then takes precedence in presentation; the independent record stays separately attributed until it expires or is corrected at its source. A publisher cannot rewrite independent evidence as if it never existed.

## 4. Storage abstraction and the D1 reference implementation

The library defines a minimal store interface; every feature in this plan is written against it:

```js
// @nessgate/resolver storage interface (all optional — a null store = today's stateless v1)
{ getRecords(domain), putRecords(records[], {origin, ttl}), purge(domain, origin?), touch(record_id) }
```

- Reference implementations shipped in-repo: `memoryStore` (tests), `sqliteStore` (self-hosters), `d1Store` (nessgate.com).
- The hosted nessgate.com is the **reference public resolver**, not the protocol. The neutrality test becomes a CI test: the conformance suite (§15) must pass identically against a resolver with no store and a fresh store — **the same captured evidence, evaluated under the same open rules, yields the same classification** — storage affecting latency only, never classification.

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

Read-side federation, consistent with the charter ("reads them and points back"):
- Adapters for MCP Registry (exists in /explore today), AGNTCY Directory, NANDA index; each **declares its own authentication method and keeps its own identity** — a federated result always names the source registry and how that registry verified it, never a generic "trusted" status.
- **Domain-authenticated** registry entries (the registry proved the domain controls the namespace) → Level 1 `namespace-verified`, and MAY enter the authoritative layer, tagged `origin: federation:<registry>` with the authentication method recorded in provenance.
- **Unauthenticated** attribution (a registry lists the domain without proving control) → Level 2 `registry-attributed`, discovery layer only, short TTL.
- NessGate never presents itself as the source and never flattens registries into one badge: the strategic position is *many registries, each keeping its identity → one evidence-labelled normalized answer*.

## 9. Publisher registration / declaration (the coverage lever that actually reaches 60%+)

Constraint carried over from the 2026-09 direction decision: **NessGate ships no publish file of its own.** The front-door-manifest niche is already taken (AWP `/.well-known/awp.json`, A2A `agent.json`, ARD `ai-catalog.json`); a NessGate-specific file would be the reinvention trap and would recreate a publisher-adoption barrier. Declarations therefore ride entirely on the standards NessGate already reads:

- **Declaration = the domain's existing standard files.** An ARD catalog, AWP manifest, llms.txt, etc. IS the publisher's declaration; entries pointing at other hosts are cross-domain declarations. Level 1 `publisher-declared` (already exists in /explore) covers this today. Cross-registrable-domain claims are Level 1 only with bidirectional evidence (both sides declare, or RWS/Asset Links — also already implemented), else Level 2.
- **Registration** (optional attestation, account-less): `POST /register {domain}` → challenge (DNS TXT `_nessgate.<domain>` or `.well-known` proof file, one-time signed tokens) → an authoritative-layer attestation (`origin: registration`, class `registered`) that the domain proved control and pointed at resources it already publishes. **Registration is never required for Level 1 and never a NessGate-only source of truth:** a publisher whose own standard files (ARD, AWP, llms.txt, RWS/Asset Links) already establish authority gets Level 1 from those files with no registration at all. Registration only *attests* to what is independently re-derivable from the domain's own evidence — its provenance records the same proof anyone could re-check — so it adds convenience and an explicit ownership signal, never a fact that exists only because NessGate stored it. The attestation is subject to the §2 freshness rule (a removed resource is not kept "official" by a past registration). No accounts, no email, no user data — the domain proves itself, ACME-style. **This machinery existed and passed production e2e before the pivot retired it** (DNS-TXT/file/json-field proofs, SSRF-hardened) — revival, not greenfield, which lowers §14 stage-4 risk.
- **Tooling**: WP plugin already writes `ai-info.json`/`llms.txt`/verification files — it becomes the registration client; the useful-empty response (§1) links to the publishing guide.
- Coverage past the ~50% discovery ceiling comes from publishers adopting the *existing* standards (which registration incentivizes and the plugin automates) — not from a new NessGate format.

## 10. Neutrality Charter changes (Charter v2 — principle-level, public, versioned)

Charter v2 is stated as **principles**, not mechanisms. Exact TTL values, storage engines (D1/SQLite/Postgres), queue design, challenge formats, and budgets live in the **specification** and may change without a charter amendment; the promises below cannot. Nothing changes silently — the charter page carries a change log, and Charter v2 ships (and is announced) before any persistent storage goes live.

### A. Clauses that must change (with the principle that replaces each)

| Current charter text (verbatim) | Why it must change | Charter v2 principle |
|---|---|---|
| "Nothing is crawled, indexed, or persisted. Each answer is computed fresh and dies with its short edge cache." | Persistent store (authoritative records + short-lived discovery cache) | "NessGate keeps two clearly separated kinds of state, both inspectable: **records a publisher declared or registered**, kept until the publisher revokes them and re-verified on a schedule; and a **short-lived discovery cache** re-derived from public evidence and never served stale. NessGate builds no content corpus — no stored page text, no search index — only pointers, each carrying its source, evidence class, verification state, timestamps, and expiry." |
| "it never stores…" / "NessGate keeps no user data and no domain data" | Registration + declaration + independent-evidence records | "No accounts and no user data, ever. A domain record exists only because the domain itself declared or registered it, or because an independent public source (a certificate log, another publisher, a named registry) attested it with recorded provenance. Publishers control what they own and may revoke it at any time; independent evidence is separately attributed and expires on its own schedule rather than being erased on demand." |
| (implied by "reads them on demand") | Publisher-surface reading (deep tier) + defined public adapters | "In its broader tiers NessGate may read a publisher's **own** public pages at resolve time — bounded, robots-respecting, provenance on every hop — solely to follow that publisher's own links. It does not crawl arbitrary third-party sites or commentary *about* a publisher. Separately, a small set of **explicitly defined public adapters** (certificate-transparency logs, named registries) may read third-party sources, always with full provenance and always Level 2 until independently confirmed." |
| "It does not rank, score, rate…" | Reaffirm under the new tiers | "No scores, ever — no numeric confidence, no ranking. Results are **grouped by evidence class and deterministically ordered within each group**; grouping is not ranking and buys no one placement." |

### B. Affirmative neutrality promises (new, principle-level)

Carried into Charter v2 as explicit public commitments:

1. **Discovery never becomes authority.** A resource NessGate merely found is marked *discovered* and stays there; it becomes *authoritative* only when a publisher declaration, a verified registration, or a domain-authenticated registry independently establishes it. Storing a discovered record never upgrades it.
2. **Two questions, never merged.** NessGate reports *whether a resource is real* and *how strongly it relates to a domain* as two separate facts. Finding or verifying a resource never makes it "official."
3. **Storage independence.** Any persistent store is an implementation choice, never part of the protocol. The same captured evidence, evaluated under the same open rules, yields the same classification with any store or none.
4. **Operator independence.** nessgate.com is one reference deployment. The open implementation runs for anyone on their own database or with no database, and reaches the same classifications from the same captured evidence and the same open rules.
5. **No privileged submitter — including our own commercial layer.** Anyone may submit candidate resources; every submission, from any party including NessReady, is evaluated under the identical public rules and remains *discovered* until it independently earns authority. There is no private path to promotion, and none for sale.
6. **Source-preserving federation.** When a result comes from another registry, NessGate names that registry and its verification method. Registries are never flattened into a generic "trusted" stamp.
7. **No proprietary publishing format.** NessGate introduces no publishing file for domains to adopt. It reads the standards that already exist; a domain's own standard files are its declaration.

Unchanged v1 commitments — free forever, no ranking/placement sales, neutral to every domain, open and independently implementable spec, resources always live on the domain — are restated verbatim in v2.

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
