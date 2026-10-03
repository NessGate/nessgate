# PROPOSAL: new watched source — openai-bot-ranges

Source: https://openai.com/chatgpt-user.json
Kind: operator-ranges · Detected: 2026-10-03
Hash: 457798dfbea98bc0 (8322 bytes)

## Suggested review (human)
- [ ] Read the upstream change; does the protocol/version or its shape change?
- [ ] If our vendored vector is stale, refresh it under `compat/vendor/openai-bot-ranges/` (+ SOURCE.md).
- [ ] If behavior changes, add/adjust a `compat/fixtures/openai-bot-ranges/` case (per the fix⇒fixture rule).
- [ ] Update `compat/matrix.json` versions/deviations if needed.
- [ ] Run `npm run check`; then `node lab/watch-specs.mjs --freeze` to re-freeze the snapshot.

> Lab output only. No resolver, corpus, or snapshot change was made automatically.
