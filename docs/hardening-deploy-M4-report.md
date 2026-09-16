# OpenAPI hardening + deploy + M4 (adapter contract) — report

Date: 2026-09-16. The OpenAPI fix is now **deployed to production**; M4 is complete. No M5, storage,
registration, or Charter-v2 activation.

## Hardening (before deploy)

**Fix 1 — truncated-by-cap vs complete-but-malformed.** `detectOpenApi(text, truncated)` now takes
whether *we* truncated the body at the prefix cap. A body that **completed within the cap** must be
valid JSON + openapi/swagger shape — a complete-but-malformed document is **rejected even if it
contains a marker**. Only a **cap-truncated** body may use head-marker detection. `fetchBounded`
(library) and `safeFetch` (worker) return `{ text, truncated }`; `truncated` is true only when bytes
existed **beyond** the cap (a body ending exactly at the cap is complete — verified by a one-read
peek). Regression fixtures: `openapi/reject/detect-complete-malformed` + `truncated` flags on the
detect fixtures.

**Fix 2 — literal byte cap.** The final chunk is trimmed to the remaining allowance before
buffering, then the stream is cancelled: **at most `maxBytes` of body data are ever retained**
(proven: a single 10 MB chunk yields exactly 65 536 bytes retained). Documented accurately —
NessGate retains/processes no more than `maxBytes`; the network/runtime may have delivered a chunk
underneath `fetch` before cancel (the earlier "131 KB" figure was bytes the mock *produced*, not
bytes retained).

Applied byte-identically in `packages/resolver/index.mjs` + `public/resolver.mjs` and mirrored in
`src/worker.js` (parity verified). Tests: `scripts/test-openapi.mjs` (Fix 1, Fix 2 literal-cap unit,
+ six end-to-end cases). Refreshed unseen benchmark **unchanged**: recall 67/67 (100 %), openapi
8/8, 0 FP, class/prov 100 %.

## Deploy + live smoke

Pre-deploy gate (regression · v2 · compat corpus · openapi · conformance · contract · matrix) passed;
deployed build `a9bc860`. Live `/discover`:
- small OpenAPI — render.com → openapi "Render AI Discovery API" (13 resources);
- **large OpenAPI — vercel.com (10.8 MB) → openapi "Vercel API"** (the fix, live);
- negative — example.com → 0 resources.
Full smoke passed incl. **deployed build matches HEAD**.

## M4 — adapter contract formalized in code

`compat/contract.mjs` defines the contract; `scripts/test-contract.mjs` machine-checks the chain and
fails CI on any drift (negative-tested: it catches surface drift, authority/level inconsistency, and
missing reject fixtures). Enforced across 14 adapters / 14 manifests / 29 fixtures / 6 vendored
vectors:

- every runtime adapter has a manifest with all required fields;
- manifest **surfaces + channel match the runtime adapter** (a manifest cannot claim what the code
  doesn't probe);
- **authority ↔ two-axis level ↔ `canEstablishAuthority`** are consistent (authority is linked to the
  resolver's own `levelFor`, so contract and classification can't diverge);
- provenance is required on every adapter;
- `normalizeAs` protocol and every declared fixture exist in the matrix/corpus;
- a named `officialSuite` points at real vendored files;
- **conformance coverage**: every shape-checked protocol has both a positive and a reject fixture
  (added awp/host-meta/anp reject fixtures to satisfy this).

Now in `npm run check` and the pre-deploy gate.

## Status

Deployed + verified: OpenAPI large-spec handling. Complete: M0.5, M1, OpenAPI fix + hardening, M2,
M4. **Not started (awaiting review): M5 (Compatibility Lab), storage, registration, Charter-v2
activation.** Per the sequencing, M5 begins only after M4 is stable — the AI Lab proposes changes
against this now-stable adapter/fixture contract.
