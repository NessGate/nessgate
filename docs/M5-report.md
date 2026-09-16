# M5 — Compatibility Lab — report

Date: 2026-09-16. Offline, proposal-only. Sequenced after M4 so the Lab proposes against a **stable**
adapter/fixture contract. No storage, registration, or Charter-v2 activation. Production resolver
untouched (additive).

## What M5 is

The Lab keeps the moat current: it turns spec/version changes and resolution anomalies into
**human-reviewable proposals** (candidate fixtures + change notes). It sits around the deterministic
resolver, never inside it.

## Hard invariant — machine-checked (`scripts/test-lab-isolation.mjs`, in the gate)

> The Lab may only PROPOSE. It never silently alters production classification or authority rules.

Enforced and **negative-tested** (a lab file writing into `compat/` is caught; a resolver importing
`lab/` would be caught):
- Resolver core, compat corpus code, and every gate script import **nothing** from `lab/` — no
  production/gate dependency on the Lab (18 files checked).
- Lab tools write **only** within `lab/` — never into `compat/`, `packages/`, `src/`, `public/`, or
  `benchmarks/`. A proposal enters the corpus only when a human completes it and moves it through the
  full gate.

## Tools (offline, on-demand — not in CI)

- **`lab/watch-specs.mjs`** — fetches watched spec/schema/vendor sources (`lab/sources.json`), hashes
  each, compares to the frozen `lab/spec-snapshots.json`; new/changed sources emit a drift proposal.
  `--freeze` (human, after review) re-freezes the snapshot; it never updates automatically.
  Bootstrapped 5 sources (OpenAPI petstore, RFC 9727, RFC 6415, ARD spec, A2A spec).
- **`lab/analyze-failures.mjs <results.jsonl>`** — clusters recall misses (by protocol), false
  associations, and parser errors from a benchmark/failure file into proposals with a **fixture
  skeleton** + investigation checklist. Deterministic; reads only; writes only to `lab/proposals/`.

**Loop demonstrated:** run against the *historical* unseen baseline (before the OpenAPI fix), the
analyzer produced exactly `anomaly-recall-openapi (vercel.com, posthog.com)` with a ready fixture
skeleton — i.e. the Lab would have surfaced the precise gap the unseen benchmark found, and routed it
into the fix⇒fixture discipline. (Demo proposals were removed; that gap is already fixed.)

## Only-proposes, by construction

No web-scale crawling, no resolver/corpus mutation, no production request-path involvement, no AI in
CI. AI is an optional, human-triggered drafting step whose output is a proposal that must pass the
same official + regression + compat + contract + lab-isolation gate as any human change.

## Status

Compatibility Foundation milestones complete: **M0.5** (frozen unseen ruler), **M1** (corpus + CI),
**OpenAPI fix + hardening** (deployed), **M2** (official conformance), **M4** (adapter contract),
**M5** (Compatibility Lab). CI gate: 8 offline suites + smoke.

**Not started (deliberately):** persistent storage/index, publisher registration, Charter-v2
activation. These remain gated on Charter v2 becoming the active charter and on a separate decision —
the moat work (compatibility knowledge + unseen-domain correctness) is now self-sustaining without
them.
