# @nessgate/resolver

The open, neutral resolver for the agentic web. Give it a domain and it reads whatever that
domain already publishes at the standard machine-discovery locations — ARD / `ai-catalog.json`
(well-known path, `rel="ard"` link, and robots `Agentmap:` directive), A2A agent card,
`llms.txt`, RFC 9727 api-catalog, `ai-info.json`, OpenAPI, Open Resource Discovery, AWP,
RFC 6415 host-meta, Agent Network Protocol, Universal Commerce Protocol, the AID TXT record,
and GB/Z 185.4 agent descriptions — and returns **one normalized list**, each record carrying
its `source` and the native `sourceUrl` so you can verify against the domain directly.

- **Dependency-free.** Runs anywhere with `fetch`: Node ≥18, Deno, Bun, Workers, and agent
  runtimes.
- **Decentralized.** Fetches the target domain directly — no runtime dependency on nessgate.com.
- **Neutral.** Reads the existing standards; reuses each source's own type labels; invents no
  taxonomy of its own. A new standard is just a new adapter, never a competitor.

## Install

```
npm install @nessgate/resolver
```

## Use

```js
import { resolve } from "@nessgate/resolver";

const { resources } = await resolve("example.com");
for (const r of resources) {
  console.log(r.source, r.type, r.url); // e.g. "ard-catalog" "application/json" "https://example.com/ai-info.json"
}
```

`resolve(domain, opts)` returns `{ domain, provenance, discovered, resources, checked }`.

- `resources` — the normalized union of what the domain publishes. Each record has
  `source`, `sourceUrl`, `type` (the source's own label), `url`, a `class`
  (how far NessGate verified it), and, where useful, `name` / `rel` / `id` / `raw`.
- `discovered` — the routing map: which standards were found, and where.
- `checked` — the standards probed.

### Declared capabilities (verbatim, never inferred)

Where a source document itself declares operations or skills, the record carries a
`capabilities` array copied 1:1 from the publisher's own words:

- **OpenAPI** — one entry per declared operation (`method`, `path`, `operationId`,
  `summary`), plus a `security` array from the spec's own
  `components.securitySchemes` / Swagger-2 `securityDefinitions`. Operations are
  enumerated only from a **complete** document (one extra bounded read up to
  `maxBytes` when the spec exceeds the 64 KB detection prefix); a spec larger than
  the cap stays detected but not enumerated — never partially extracted.
- **A2A / GB-Z agent cards** — the card's own `skills` (`id`, `name`, `description`,
  `tags`); the card-level capabilities object rides along in `raw`.
- **ARD** entries already carry their declared media types and metadata.

NessGate never infers, renames, or classifies a capability. `capabilities` is absent
when the source declares none; lists are capped at 40 and flagged
`capabilitiesTruncated` when the publisher declares more.

### Redirects and the `class` label

The library follows redirects and records the **final** URL as `sourceUrl`. A fetched
document whose final URL crossed to a *different* registrable domain (e.g. a wholesale
rebrand like `neon.tech → neon.com`) is labeled `class: "verified-external-location"` —
never `verified-publisher-location`. The other classes are
`publisher-declared` (declared in a fetched catalog, same registrable domain, target not
fetched), `declared-external-pointer` (declared, different registrable domain,
unverified), and `unsupported` (no usable URL). The hosted resolver at nessgate.com is
domain-locked and never follows cross-domain redirects, so `verified-external-location`
appears only in library results.

Options: `{ fetch, timeoutMs = 8000, maxBytes = 1_000_000 }`. Bring your own `fetch` if the
runtime has none.

Optional GB/Z 185.5 discovery (Node only): pass
`opts.gbz = { gatewayUrl, fetch, query, headers }` to query a gateway **you configure** with
your **own authenticated fetch** (mTLS/OIDC stays on your side — the library embeds no
credentials). Returned agent descriptions carry `provenance: "gbz-185-5-gateway"`. Nothing is
auto-discovered; without `opts.gbz` no gateway is ever contacted.

Also exported: `normalizeResources`, `classifyResource`, `extractOpenApiCapabilities`,
`normalizeDomain`, `validateProbeContent`, `probeShapeOk`, `parseLinkRel`,
`parseAgentmap`, `parseAidRecord`, `isAcs`, `normalizeAcsGatewayResponse`, and the
`ADAPTERS` table.

## In a browser

The code runs in browsers, but a browser can only fetch *other* domains that send CORS
headers — and most `.well-known` files don't — so browser code resolving **arbitrary**
domains should use the hosted endpoint instead
(`GET https://nessgate.com/discover/{domain}`, open CORS, no auth). Resolving your **own**
domain from your own pages works directly.

## Security

**This library fetches the domain you pass it and follows redirects.** In Node or other
server-side environments, a caller that passes an **untrusted** domain must validate it
first: reject private, loopback, link-local, and other reserved addresses, and keep
redirects on the original host. Without these checks, an untrusted input could be used to
reach internal network resources (SSRF). The hosted resolver at
[nessgate.com](https://nessgate.com) performs these checks (DoH pre-check against
private/reserved IPs, on-domain redirects only, size and timeout caps, HTTPS-only); when you
run this library yourself, that responsibility is yours.

## Specification

This is the reference client for the NessGate Resolver Specification — see the
[specification](https://nessgate.com/spec) and the [Charter](https://nessgate.com/charter).
The specification is open and independently implementable.

## License

Apache-2.0.
