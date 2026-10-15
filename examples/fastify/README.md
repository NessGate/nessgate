# NessGate Inspect + Fastify

Attach neutral evidence about each incoming caller to `request.nessgate`, using
the published [`@nessgate/inspect`](https://www.npmjs.com/package/@nessgate/inspect)
package. Evidence only — no allow/deny, no score; your handlers decide.

## Run

```bash
npm i fastify @nessgate/inspect
node inspect.mjs
curl -s localhost:8799/ -H 'user-agent: Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)'
```

The GPTBot User-Agent returns `directory-attributed` for OpenAI; a plain request
returns `claimed`. The stronger tiers (`network-verified`, `cryptographically-verified`)
appear only for genuine operator traffic or a signed request.

## Source IP

`request.ip` is the real connection peer by default. Behind a reverse proxy or
CDN, set `TRUST_PROXY=1` **and** make sure only a trusted platform can set the
forwarding header — Fastify then reads `request.ip` from it. Network
verification depends on the source IP being the real origin, so do not trust a
forwarding header from an untrusted hop.

## Runtime

This runs on Node. `network-verified` needs outbound DNS/HTTPS from the request
path (reverse-DNS or the operator's published IP ranges); a host with no outbound
network still returns `claimed`/`directory-attributed` honestly, degrading to
`unknown` rather than a false result.
