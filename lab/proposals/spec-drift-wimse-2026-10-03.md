# PROPOSAL: spec drift — wimse

Source: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
Kind: spec-draft · Detected: 2026-10-03
Hash: e075527df6fed493 → dc06e4a5b7eaebc8 (128198 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/wimse/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/wimse/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.

## Resolution (reviewed 2026-10-03)

Page-content drift on a tracked source, reviewed the same day: the resolver implements the current MCP revisions (initialize era through 2025-11-25; stateless 2026-07-28 via server/discover) and WIMSE remains tracked-only. No behavior change required; snapshot re-frozen.
