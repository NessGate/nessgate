# PROPOSAL: spec drift — a2a-agent-card

Source: https://a2a-protocol.org/latest/specification/
Kind: spec · Detected: 2026-10-03
Hash: 4805254c10d8cbde → 0e6a4625fb6a4958 (617292 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/a2a-agent-card/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/a2a-agent-card/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.

## Resolution (reviewed 2026-10-03)

Reviewed against the fields the resolver and the readiness assessor read. The
current "latest" specification page carries `supportedInterfaces`,
`protocolVersion`, `securitySchemes`, and `signatures` — every field consumed —
and no longer shows `preferredTransport` / `additionalInterfaces`, which appear
in the 0.3.x card shape. The assessor (`assessA2aReadiness`) and the normalizer
already accept both shapes (interfaces via `additionalInterfaces` OR
`supportedInterfaces`, transport via `preferredTransport` OR the first
interface, version via `protocolVersion` OR `version`), and the corpus covers
both (`compat/fixtures/readiness/a2a/*`, `compat/fixtures/a2a-agent-card/*`).
No behavior change required; snapshot re-frozen the same day. Re-review if a
future drift removes `supportedInterfaces` or renames the security fields.
