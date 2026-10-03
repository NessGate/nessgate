# PROPOSAL: spec drift — mcp

Source: https://modelcontextprotocol.io/specification/latest
Kind: spec · Detected: 2026-10-03
Hash: 3d257ea31b1555bd → f2b28206a69d1d2e (322407 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/mcp/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/mcp/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.

## Resolution (reviewed 2026-10-03)

Page-content drift on a tracked source, reviewed the same day: the resolver implements the current MCP revisions (initialize era through 2025-11-25; stateless 2026-07-28 via server/discover) and WIMSE remains tracked-only. No behavior change required; snapshot re-frozen.
