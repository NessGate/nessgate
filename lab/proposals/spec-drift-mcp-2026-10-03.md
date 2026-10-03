# PROPOSAL: new watched source — mcp

Source: https://modelcontextprotocol.io/specification/latest
Kind: spec · Detected: 2026-10-03
Hash: 3d257ea31b1555bd (319496 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/mcp/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/mcp/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.
