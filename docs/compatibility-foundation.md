# NessGate Compatibility Foundation — moat-centered strategy & plan

Status: PROPOSAL (planning only; **no production changes**). Date: 2026-09-15.
Supersedes the *strategic emphasis* of `v2-architecture.md` (storage/index/registration are
reclassified as supporting infrastructure, not the moat — see §9). Preserves all prior experimental
work: the v2 storage/index design and the Stage-1 `discovery`-tier alpha remain valid; only their
role in the strategy changes.

> **NessGate's moat is not knowing every domain in advance; it is knowing how to resolve domains it
> has never seen before.**

## 0. Identity (unchanged, sharpened)

```
Known domain
  → bounded authoritative inspection
  → deep multi-protocol compatibility
  → one normalized representation
  → explicit provenance / evidence.
```

The durable advantage is **not** the compatibility corpus by itself (open source; fixtures are
public and copyable). It is the *system* that maintains compatibility: continuous protocol tracking,
a permanent real-world regression corpus, official example vectors (canonical documents, not full
conformance suites), fast fixes, a contributor
ecosystem, trusted normalization semantics, and a measured reputation for resolving **unseen**
domains correctly. Speed of compatibility maintenance and breadth of regression knowledge are the
moat — not secrecy.

## 1. Compatibility corpus

A permanent, document-level regression corpus (not domain-level — we test *how a document is read*,
so there is nothing to "memorize" about specific sites).

```
compat/
  README.md              # the rules below, and how to add a fixture
  matrix.json            # machine-readable support matrix (§2)
  fixtures/
    <protocol>/<version>/<case>.json
  vendor/                # official schemas / test vectors, license-permitting (§3)
    <protocol>/<version>/...
  adapters/
    <adapter-id>.json    # adapter contract manifests (§4)
```

Fixture shape (deterministic, no network):

```json
{
  "id": "ard-catalog/0.91/basic-entries",
  "protocol": "ard-catalog",
  "version": "0.91",
  "surface": "/.well-known/ard.json",
  "kind": "json",
  "origin": "official-example | reference-impl | real-world | synthetic",
  "license": "CC-BY-4.0 | ... | n/a",
  "provenance": "where this fixture came from (URL / spec section / incident id)",
  "input":  { "url": "https://ex.com/.well-known/ard.json", "status": 200, "contentType": "application/json", "body": "…" },
  "expect": { "verification": "verified", "relationship": "publisher-hosted", "level": 1,
              "resources": [ { "source": "ard-catalog", "type": "…", "url": "…" } ] },
  "notes": "quirk / why this case exists"
}
```

Corpus categories to seed and grow: every supported protocol; each protocol version; official
examples & schemas (where licensing permits); reference-implementation outputs; malformed-but-common
real-world implementations; redirect & hosting variations; conflicting signals; legacy
implementations; vendor quirks; national ecosystems (e.g. GB/Z 185.4); and **every real NessGate
compatibility failure we ever discover**.

**Fundamental rule (enforced in CONTRIBUTING + CI):**
> Never fix a compatibility problem only in code. Every real compatibility fix MUST add a permanent
> regression fixture/test. A code fix without a fixture fails review.

## 2. Protocol / version support matrix

`compat/matrix.json` — the single machine-readable source of truth. One entry per protocol×version:

```json
{
  "ard-catalog": {
    "0.91": {
      "surfaces": ["/.well-known/ard.json", "/.well-known/ai-catalog.json", "link rel=ard", "robots Agentmap:"],
      "parser": "normalizeResources('ard-catalog')",
      "officialSuite": "vendor/ard-catalog/0.91/",
      "authority": "publisher-hosted (Level 1) when on the domain's own surface",
      "deviations": ["accepts entries[] with inline data", "…"],
      "fixtures": ["ard-catalog/0.91/basic-entries", "…"]
    }
  }
}
```

Rule: **no "supports X" claim anywhere** (site, README, spec, marketing) unless the matrix + passing
tests justify it. A matrix consistency check (§CI) fails the build if the matrix names a
fixture/suite that doesn't exist, or an adapter/protocol lacks matrix coverage.

## 3. Official conformance ingestion

Where an ecosystem publishes official schemas / test vectors / conformance suites / reference
implementations, **vendor them into `compat/vendor/` and run them in CI** rather than re-authoring
correctness by hand. Tests therefore have two layers:

- **Layer 1 — official correctness:** validate our parse/normalize against the ecosystem's own
  schema/vectors (e.g. an ARD entry schema; OpenAPI's schema; A2A agent-card schema). Runtime stays
  dependency-free; the validator (e.g. `ajv`) is a **dev/CI-only** devDependency, never shipped in
  `@nessgate/resolver`.
- **Layer 2 — real-world compatibility:** run every `compat/fixtures/**` case through the actual
  parser/normalizer + `classify`, asserting exact expected output.

Each vendored suite records its source, version, license, and retrieval date in
`compat/vendor/<protocol>/<version>/SOURCE.md`.

## 4. Adapter contract

Formalize the v2 adapter descriptor (`V2_ADAPTERS`) so every protocol adapter is self-describing and
backed by the corpus. Each adapter declares (in code + a `compat/adapters/<id>.json` manifest kept
in sync by a test):

- protocol and version(s);
- surfaces it reads;
- authority semantics (can it establish Level 1? which evidence class);
- normalization output (what records it emits);
- provenance requirements;
- supported deviations / quirks;
- official tests it passes (`vendor/…` refs);
- compatibility fixtures covering it (`fixtures/…` refs).

Goal: **adding a new protocol = adding an adapter + fixtures + a matrix entry, with no change to
resolver core logic.** A contract test asserts every adapter has a manifest, matrix entry, and ≥1
fixture, and that its declared authority matches the two-axis `LEVEL` map (a `canEstablishAuthority:
false` adapter can never name a Level-1 class — already true in the alpha).

## 5. Compatibility Lab (AI-assisted, OFFLINE)

An offline pipeline *around* the deterministic resolver. It proposes; it never decides.

```
lab/
  README.md          # the hard rule below
  watchers/          # spec/version change monitors (WebFetch/WebSearch over spec URLs)
  analyzers/         # cluster failed resolutions & anomalies; compare vs reference impls
  proposers/         # draft fixtures + adapter/parser diffs
```

Workflow (every step human/CI-gated):

```
spec change OR anomaly / failed resolution
  → investigation (analyzer clusters, inspects public impls, diffs vs reference)
  → PROPOSED regression fixture/test
  → PROPOSED code (adapter/parser) change
  → official + regression + security tests run
  → human / CI approval
  → release
```

**Hard invariant:** AI MUST NEVER silently alter production classification or authority rules. The
lab's only outputs are proposed fixtures and proposed diffs that enter the *same* review+CI gate as
any human change. AI lives in the lab, never in the authority decision path (§8). (The lab can reuse
the multi-agent workflow tooling already used elsewhere; runs are offline and produce PRs.)

## 6. Unseen-domain benchmark (the moat metric) — FROZEN FIRST (M0.5)

**Sequencing rule (reviewer directive):** the holdout cohort, its ground truth, and the first
untouched baseline are **frozen BEFORE the corpus is expanded (M1)** — otherwise, even
unintentionally, corpus additions could bias the ruler. Establish the ruler, then build.

`benchmarks/holdout-unseen.txt` — a **frozen, stratified** cohort drawn from sources *not* used by
the Tranco / public-apis cohorts, **never** referenced in any fixture, matrix entry, or tuning.

**Stratification (do NOT use a random sample dominated by domains that publish nothing):** the cohort
tags each domain with a stratum, recorded in `benchmarks/holdout-unseen.json`:
- `positive` — real supported machine-readable surface(s);
- `multi-protocol` — more than one supported surface;
- `ecosystem` — spread across different protocols/ecosystems (ARD, A2A, MCP, OpenAPI, ORD, AWP,
  llms.txt, host-meta, ANP, UCP, AID, GB/Z);
- `legacy` — difficult/legacy implementations where naturally present;
- `negative-control` — genuinely no supported surface;
- `blocked` — blocked/unreachable; classified **separately**, never counted as a negative.

**Ground truth** is established by an **independent** direct probe (raw HTTPS GET of the exact
well-known/surface URLs + human review of the bodies), NOT by running the resolver under test — so
the benchmark is a fair ruler, not a tautology. Frozen artifacts: domain list; selection
methodology; per-domain ground-truth snapshot + date; and content hashes where useful.

**Separate metrics (never a single "accuracy" number)** — a resolver that returns nothing for
everything must NOT score well just because many sites expose nothing. `benchmarks/bench-unseen.mjs`
reports each independently:
- **authoritative-resource recall** — of the ground-truth authoritative surfaces, how many the
  resolver found (the metric that punishes "returns nothing");
- **false-positive / false-association rate**;
- **classification correctness** (right evidence class / level);
- **provenance correctness** (every result re-derivable from its provenance);
- **protocol / parser failures**;
- **unresolved / blocked / unreachable rate** (reported separately, not as negatives);
- **latency / request cost.**

**Never optimize or hardcode around holdout domains.** If a holdout domain later teaches a
compatibility fix: retire it from the holdout, turn the lesson into a normal `compat/` fixture, and
replace it with a fresh unseen holdout domain.

## 7. Compatibility metrics (engineering, not marketing)

Generated into `compat/metrics.json` by `scripts/compat-matrix.mjs`:

- protocols supported; protocol versions covered;
- official conformance vectors passing / total;
- permanent real-world regression cases;
- distinct implementation quirks handled;
- unseen-domain metrics (from §6 — the separated set, never a single accuracy number);
- silent-regression count (regressions caught only after release — target 0);
- time from protocol/spec change → compatible release.

**No generic 0–100 confidence score for resources** — evidence classes only.

## 8. Production stays bounded & deterministic

Production NessGate inspects only deterministic, bounded discovery surfaces and known protocol
mechanisms (today's `/discover` + `/explore` limits). It does not become an LLM web crawler. AI
belongs in the Compatibility Lab, never in the live authority/classification path.

## 9. Storage / index — reclassified as supporting infrastructure

The v2 storage/index/registration design (`v2-architecture.md`) is **preserved but demoted**: it is
supporting infrastructure for **latency, freshness, temporary resolution state, and optional
publisher registration/attestation** — not the moat. Hard constraints:

- No giant permanent database mapping the Internet.
- The domain's own public authoritative evidence remains the source NessGate **revalidates against**;
  stored records are cache/attestation with provenance + TTL, never authority-by-storage.
- **NessGate must remain fully useful for a completely unseen domain with an empty database.** This
  is a testable invariant (the §4 store-independence conformance test): identical classification with
  a store or none.
- All storage/registration work stays gated on Charter v2 becoming active (unchanged).

## 10. Open-source moat (assume the code is copied)

Competitors can copy the code and public fixtures. The durable advantage must therefore be: faster
compatibility maintenance; broader regression knowledge; trusted semantics; conformance quality; a
contributor ecosystem; integrations/distribution; a reputation for correctness; and rapid adaptation
to new protocols and real-world quirks. Do not depend on secrecy.

## 11. Strategic non-goals (documented on purpose)

NessGate is **not** trying to become: a general AI search engine; an agent marketplace; a ranking
engine; the largest agent directory; a general-purpose web crawler; or a proprietary protocol
publishers must adopt. It **interoperates** with MCP registries, AGNTCY, NANDA, and future
registries rather than competing with all of them. Its unique question:

> *"I know this organization/domain. How does it expose itself to AI and agents?"*

## 12. Proposed implementation order (build decision is yours)

Docs first (this). Then, smallest safe increments, each independently shippable, **no production
resolver behavior change and no Charter-v2 activation required for M0.5–M5**:

- **M0.5 — Freeze the unseen-domain benchmark FIRST (the ruler).** Select + stratify the holdout
  (§6) from sources not used by our cohorts; establish independent ground truth; freeze the domain
  list, methodology, ground-truth snapshot/date, and hashes; build `bench-unseen.mjs` with the
  separated metrics; record the first **untouched** baseline. Done *before* any corpus expansion so
  the ruler cannot be contaminated.
- **M1 — Corpus + CI spine.** Create `compat/` (matrix, adapter manifests for the 14 existing
  adapters, fixtures backfilled from the current hand-written tests). Add `scripts/test-compat.mjs`
  (layer 2) + `scripts/compat-matrix.mjs` (consistency + metrics); wire both into `npm run check` and
  the deploy gate. Add the "fix ⇒ fixture" rule to CONTRIBUTING. **M1 must not intentionally change
  resolver behavior**; after M1, rerun the exact frozen unseen benchmark only to confirm no
  regression.
- **M2 — Official conformance (layer 1).** Vendor available official schemas/vectors (ARD, A2A,
  OpenAPI, api-catalog, …); add the dev-only validator; record sources/licenses.
- **M3 — (folded into M0.5)** the unseen benchmark now lives at M0.5; M3 is retired.
- **M4 — Adapter contract in code.** Extend the `V2_ADAPTERS` descriptor with the §4 fields; add the
  contract test (every adapter ↔ manifest ↔ matrix ↔ fixtures).
- **M5 — Compatibility Lab (offline).** Watchers + analyzer + proposer, human/CI-gated; produces
  candidate fixtures/diffs only.
- **Later — Supporting infra (former "Stage 2").** Storage/index + registration, justified on
  latency/publishing/freshness (not discovery recall), sequenced after the moat work and gated on
  Charter v2 activation. The Stage-1 `discovery` tier (CT/sitemap) remains an optional,
  source-substitutable library capability (reconciled benchmark: safe, correct, small recall gain
  over strict+explore — supporting feature, not the moat).

**Build now (approved): M0.5 then M1, then stop and report.** Do not begin M2/M4/M5, storage,
registration, or Charter-v2 activation until that review. Keep all production behavior unchanged.
