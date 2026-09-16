# NessGate Compatibility Lab (M5)

The Lab keeps the moat **current**: it turns spec/version changes and real resolution anomalies into
**human-reviewable proposals** — candidate regression fixtures and change notes — so compatibility
knowledge accumulates instead of decaying. It sits *around* the deterministic resolver, never inside
it.

## The hard invariant (enforced by `scripts/test-lab-isolation.mjs`)

> **The Lab may only PROPOSE. It never silently alters production classification or authority rules.**

Concretely, and machine-checked in CI:
- The resolver core (`packages/resolver/`, `public/resolver.mjs`, `src/worker.js`) imports **nothing**
  from `lab/`. There is no production code path through the Lab.
- Every Lab tool writes **only** under `lab/proposals/` — never into `compat/`, `packages/`, `src/`,
  or `public/`. A proposal becomes real only when a **human** reviews it, completes the fixture, and
  moves it into `compat/` through normal review + the full gate.
- AI is optional and human-triggered (draft an investigation/fixture from a proposal stub). No AI
  runs in CI, and no AI output is trusted until it passes the same official + regression + contract +
  security gate as any human change.

## Workflow

```
spec change  OR  resolution anomaly / benchmark miss
  → investigation (cluster, inspect public impls, compare vs reference)   ← lab tools, offline
  → PROPOSED regression fixture/test + PROPOSED code change note          ← lab/proposals/*.md
  → human review: complete the fixture, write the fix                     ← moves into compat/ + code
  → official + regression + compat + contract + security tests           ← npm run check / gate
  → human / CI approval → release
```

## Tools (offline, on-demand — not in CI)

- **`node lab/watch-specs.mjs`** — fetches the watched spec/schema/vendor sources in `sources.json`,
  hashes each, and compares to the frozen `spec-snapshots.json`. New/changed/removed sources emit a
  drift proposal (review the vendored copy, add/adjust a conformance vector, re-freeze the snapshot).
  Never updates the snapshot automatically. Requires network; non-deterministic → excluded from CI.
- **`node lab/analyze-failures.mjs <results.jsonl>`** — reads an unseen-benchmark (or discover-
  failure) result file, clusters anomalies (recall misses by protocol, false associations, parser
  failures, unreachable clusters), and emits one proposal per cluster with a **fixture skeleton** and
  an investigation checklist. Deterministic; reads only, writes only to `lab/proposals/`.

## What the Lab does NOT do

It does not crawl the web at large, does not modify the resolver or corpus, does not run in the
production request path, and does not decide — it drafts. The deterministic resolver and the frozen
unseen benchmark remain the sources of truth.
