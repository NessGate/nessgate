# PROPOSAL: new watched source — web-bot-auth

Source: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
Kind: spec-draft · Detected: 2026-10-03
Hash: e5b22f8df0f9b0f4 (42708 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/web-bot-auth/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/web-bot-auth/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.
