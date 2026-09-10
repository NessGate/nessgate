# NessGate

**The open, neutral compatibility resolver for the agentic web.** Give NessGate a domain and it
reads whatever that domain already publishes — across ARD, A2A, `llms.txt`, RFC 9727
api-catalog, Open Resource Discovery, RFC 6415 host-meta, OpenAPI and more — and returns
**one normalized answer**, with a link back to each source so an agent can always verify
against the domain itself.

```
company.com  →  { resources: [
                   { source: "ard-catalog", type: "application/json",
                     url:       "https://company.com/ai-info.json",
                     sourceUrl: "https://company.com/.well-known/ard.json" },
                   ... ] }
```

One call instead of ten. NessGate **reads** these standards; it does not define or replace
them — a new standard is just a new adapter, never a competitor. It reuses each source's own
type labels and invents no taxonomy of its own. The **domain is always the authority**;
NessGate only normalizes what the domain already publishes, reads it on demand, and stores nothing.

Live at **https://nessgate.com** · [Specification](https://nessgate.com/spec) ·
[Charter](https://nessgate.com/charter) · [API](https://nessgate.com/api)

## Use it

**Embeddable library** — dependency-free, fetches the target domain directly (no runtime
dependency on nessgate.com), runs in browsers, Node, Deno, Workers, and agent runtimes.
Published as [`@nessgate/resolver`](https://www.npmjs.com/package/@nessgate/resolver):

```js
import { resolve } from "@nessgate/resolver";      // or "https://nessgate.com/resolver.mjs"
const { resources } = await resolve("example.com");
```

**Hosted endpoint** — open CORS, no auth:

```
curl https://nessgate.com/discover/example.com
```

**MCP** — the same lookup as a tool (`discover_domain`) at `https://nessgate.com/mcp`.

## Principles

NessGate is free, neutral infrastructure — see the [Charter](https://nessgate.com/charter). It
never charges to use or to be read, never sells ranking or placement (there is none), keeps no
accounts, and stores no domain data. It reads a domain on demand (answers are cached at the edge
for up to 10 minutes), never crawls or indexes, and makes no ownership or safety claim — it reports
what a domain serves and links back to each source. The specification is open and the reference
implementation is Apache-2.0 licensed:
anyone may run their own resolver, and if nessgate.com disappeared, every domain's files would
still stand on the domain itself.

## Architecture

- **One stateless Cloudflare Worker** (`src/worker.js`) serves the static site
  (`public/`, via the assets binding with `run_worker_first`), the resolver API, the MCP
  server, the per-domain pages, and the sitemap. There is no database.
- **The resolver** (`GET /discover/{domain}`, and the embeddable `public/resolver.mjs`) reads
  what a domain publishes at the standard well-known locations, normalizes it into one answer,
  fetches the domain directly, and stores nothing. Answers are computed fresh and cached at the
  edge for 10 minutes. A parity test keeps the worker's and the library's normalization
  byte-identical, and keeps `packages/resolver/index.mjs` (the npm package) byte-identical to
  `public/resolver.mjs`.
- **Cloudflare KV** (`NESSGATE_KV`) holds only approximate, IP-keyed hourly rate-limit counters
  that expire within the hour. Nothing else is stored.
- **Rate limiting**: a Cloudflare-native edge limiter (burst, per-colo and eventually
  consistent — approximate by design) in front of an approximate KV hourly cap. Abuse
  protection, not exact global accounting.
- **SSRF protections**: DoH pre-check against private/reserved IPs, on-domain redirects only
  (≤ 3), 1 MB caps, 8 s timeouts, HTTPS-only. Probes are read-only GETs of public well-known
  paths; the DNS-rebinding TOCTOU window is documented in `src/worker.js` and is immaterial
  here (Worker egress has no private network behind it, and probes assert nothing).
- No accounts, no emails, no stored domain data.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /discover/{domain}` | **The resolver.** Reads what the domain publishes across the supported standards (llms.txt, ARD/ai-catalog, A2A agent card, RFC 9727 api-catalog, ai-info.json, OpenAPI, ORD, AWP, host-meta) and returns one normalized answer — `{domain, provenance, note, discovered[], resources[], checked[]}`, each resource carrying its `source` and native `sourceUrl`. CORS open, no auth; nothing stored or crawled; 10-min cache, 120/hr/IP. |
| `POST /mcp` | Model Context Protocol server (Streamable HTTP, stateless, no auth) exposing one tool, `discover_domain`, that returns the same answer as `/discover`. |
| `GET /{domain}` | Human-readable domain page — the resolver rendered for humans (live discovery). |
| `GET /resolver.mjs` | The embeddable resolver library (also on npm as `@nessgate/resolver`). |
| `GET /openapi.json`, `/llms.txt`, `/spec`, `/sitemap.xml`, `/robots.txt`, `/.well-known/security.txt`, `/.well-known/api-catalog` | Machine discovery & docs |

## Operations runbook

- **Deploy flow:** commit → `npm run deploy` (runs the full regression suite as a hard
  pre-deploy gate, then stamps the build with the git SHA via `BUILD_ID`) → `npm run check`
  (regression tests + live smoke checks, including proof that `/version` on production equals
  local HEAD) → push. CI (GitHub Actions) runs the regression suite on every push. The
  deploy-script gate is the effective production gate, since deploys run from the workstation.
- **Build verification:** `GET /version` and the `X-NessGate-Build` header on every response
  identify the exact deployed commit.
- **Tests:** `npm test` — no-network regression suite for the security-critical logic
  (normalization, SSRF/private-IP detection, probe-content validation, thin normalization, and
  worker↔library↔npm parity).
- **Rollback:** `npm run rollback` (or `npx wrangler rollback [version-id]`; versions listed by
  `npx wrangler deployments list`).
- **Logs:** `npx wrangler tail nessgate`.
- **CSS changes:** bump the `?v=N` on the stylesheet link in all pages (assets are cached;
  unversioned CSS changes will not reach browsers).

## Configuration

`wrangler.toml` binds: assets (`run_worker_first`), KV, and a `[[ratelimits]]` binding. There
are no D1 databases, no cron triggers, and no secrets — the resolver is stateless.

## npm package

`packages/resolver/` is published as [`@nessgate/resolver`](https://www.npmjs.com/package/@nessgate/resolver)
via GitHub Actions Trusted Publishing (OIDC, tokenless, with provenance) — see
`.github/workflows/publish-resolver.yml`. `index.mjs` is kept byte-identical to
`public/resolver.mjs` by the parity test.

## License & contributing

The reference implementation is licensed under **Apache-2.0** (`LICENSE`); the WordPress
plugin is GPL, as required by WordPress.org. The protocol is open and independently
implementable — see `CONTRIBUTING.md`, the naming/trademark policy in `TRADEMARK.md`, and the
[Charter](https://nessgate.com/charter). Anyone may build a compatible resolver without asking
permission; independent implementations are a goal, not a threat. The canonical
resolver/normalization logic lives in `public/resolver.mjs` and `src/worker.js` (kept
byte-identical by a parity test).

## Security contacts

`security@nessgate.com` (see `/.well-known/security.txt`),
`abuse@nessgate.com`, `privacy@nessgate.com`, `contact@nessgate.com`.
