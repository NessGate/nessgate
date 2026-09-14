# NessGate

**The open, neutral compatibility resolver for the agentic web.** Give NessGate a domain and it
reads whatever that domain already publishes — across ARD (all three surfaces), A2A, `llms.txt`,
RFC 9727 api-catalog, Open Resource Discovery, RFC 6415 host-meta, OpenAPI, Agent Network Protocol
(ANP), Universal Commerce Protocol (UCP), AID, GB/Z 185.4 and more — and returns **one normalized answer**,
with a link back to each source so an agent can always verify against the domain itself.

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
dependency on nessgate.com), runs anywhere with `fetch` — Node, Deno, Workers, and agent runtimes.
(It runs in a browser too, but a browser can only read *other* domains that send CORS headers, and
most `.well-known` files don't — so from a browser, resolve arbitrary domains via the hosted
endpoint below, which sends open CORS.) Published as
[`@nessgate/resolver`](https://www.npmjs.com/package/@nessgate/resolver):

```js
import { resolve } from "@nessgate/resolver";      // or "https://nessgate.com/resolver.mjs"
const { resources } = await resolve("example.com");
```

**Hosted endpoint** — open CORS, no auth:

```
curl https://nessgate.com/discover/example.com
```

**MCP** — the same lookup as a tool (`discover_domain`) at `https://nessgate.com/mcp`. Listed in the
[official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=com.nessgate/nessgate)
as `com.nessgate/nessgate` (domain-verified remote server), so MCP-aware clients can install it directly.

### Integrate it (≈5 lines)

Give an agent a domain, get back what to use — no per-standard code. Drop this into a tool,
a retrieval step, or an onboarding flow:

```js
import { resolve } from "@nessgate/resolver";           // dependency-free, no key, no account
const { resources } = await resolve(domain);            // reads the domain directly
for (const r of resources)
  console.log(r.type, r.url, "←", r.sourceUrl);         // normalized record + where it came from
// each r: { source, type, url, sourceUrl } — pick the one your agent needs (OpenAPI, A2A, MCP, …)
```

No SDK? The hosted endpoint is one HTTP GET (`GET https://nessgate.com/discover/{domain}`, open
CORS, no auth), and the MCP tool `discover_domain` returns the same shape. Adding a new standard
is a new adapter upstream — integrations don't change.

Full integration guide — library, HTTP, and MCP client config (including the `mcp-remote` bridge
for stdio-only clients): [`docs/integrations.md`](docs/integrations.md).

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
  what a domain publishes, normalizes it into one answer, fetches the domain directly, and stores
  nothing. Answers are computed fresh and cached at the edge for 10 minutes. A parity test keeps
  the worker's and the library's normalization byte-identical, and keeps
  `packages/resolver/index.mjs` (the npm package) byte-identical to `public/resolver.mjs`.
- **Adapter architecture — four discovery channels.** Each supported standard is a small,
  independent adapter, and every adapter uses one of four channels to locate its document:
  - **well-known** — GET a fixed path (or paths) on the domain: `llms.txt`, `ard-catalog`
    (ARD / `ai-catalog`), `a2a-agent-card` (A2A), `api-catalog` (RFC 9727), `ai-info.json`,
    `openapi`, `ord` (Open Resource Discovery), `awp` (draft), `host-meta` (RFC 6415),
    `anp` (Agent Network Protocol `/.well-known/agent-descriptions`), and `ucp` (Universal
    Commerce Protocol `/.well-known/ucp`).
  - **link-rel** — parse `<link rel="ard">` in the homepage, then GET the target (`ard-link`).
  - **robots** — parse an `Agentmap:` directive in `/robots.txt`, then GET the target
    (`ard-agentmap`).
  - **dns** — a DoH TXT lookup at `_agent.<domain>` (`aid`: `v=aid1;u=<uri>;p=<proto>;a=<auth>`).

  **ARD:** NessGate implements ARD's **normative domain resolution** — it fetches
  `/.well-known/ard.json` and honours the `<link rel="ard">` relation (both **MUST** in ARD v0.91
  §5.1) — plus the robots `Agentmap:` surface. ARD's optional in-page JSON-LD is found only by
  general web crawling, which NessGate does not do; ARD's DNS mechanism is *described* in §5.1 but
  not yet normatively specified (no record type or parameters). Neither is implemented — publishing
  a guessed record would be fake conformance. ANP and UCP are emerging; the AID TXT record (`v=aid1`
  at `_agent`) and AWP are drafts, read as-is with no adoption claim. **Note:** the `aid` adapter is
  the AID TXT mechanism, *not* the IETF DNS-AID draft (SVCB at `_agents.<domain>` — a separate,
  unimplemented mechanism).
- **GB/Z 185 (China, 智能体互联) — 185.4 yes, 185.5 gated.** NessGate **normalizes GB/Z 185.4
  agent descriptions ("ACS")**: an ACS is an A2A-family card with GB/Z extensions (an agent
  identity code `aic`, an mTLS scheme, a `certificate` block), recognized **by content** and
  labelled `gbz-185-4`, preserving those fields and provenance. Recognition is domain-first: an
  ACS served at the agent-description location NessGate already reads is normalized — **no
  GB/Z-specific `.well-known` path is guessed.** **GB/Z 185.5 discovery is a federated gateway
  service with no domain-native location**, so it is *not* part of the hosted resolver and is
  never auto-discovered. The embeddable library exposes it as an **opt-in, Node-only** call
  (`resolve(domain, { gbz: { gatewayUrl, fetch, query } })`) that POSTs to the reference
  implementation's real `…/acps-adp-v2/discover` endpoint with a **caller-supplied authenticated
  fetch** (bring-your-own mTLS/OIDC — NessGate embeds no credentials) and normalizes the ACS
  records it returns. No guessed endpoints, no fake conformance.
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
| `GET /discover/{domain}` | **The resolver.** Reads what the domain publishes across the supported adapters (llms.txt, ARD/ai-catalog via well-known paths, `rel="ard"` link, and robots `Agentmap:`; A2A agent card, RFC 9727 api-catalog, ai-info.json, OpenAPI, ORD, AWP, host-meta, ANP, UCP, AID, GB/Z 185.4) and returns one normalized answer — `{domain, provenance, note, discovered[], resources[], checked[]}`, each resource carrying its `source` and native `sourceUrl`. CORS open, no auth; nothing stored or crawled; 10-min cache, 120/hr/IP. |
| `GET /explore/{domain}` | **Evidence-based resolver (v2, additive).** Everything `/discover` returns, plus bounded *delegated* discovery: it follows the explicit machine-readable pointers a domain declares (an `llms.txt` index's links, ARD/api-catalog entries) up to depth 2 — cross-host **only** where the publisher named the target — and federates the official MCP Registry for the domain's verified namespace. Every record carries an `evidence` class (`publisher-hosted` / `publisher-declared` / `namespace-verified`) and a `provenance` chain. Strictly bounded (depth ≤2, ≤8 hosts, ≤24 requests, global byte cap, SSRF checks on every hop); stateless, no crawling, no AI, no ownership claim. With `?org=1` (**Organization Discovery**), it additionally probes a bounded set of plausible same-registrable-domain hosts (homepage-linked subdomains + a small conventional shortlist, max 4 hosts × 2 paths) and reports only *verified* resources as `same-domain-host` — solving the "resources live on developers.example.com, not example.com" case. `/discover` stays unchanged. |
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
