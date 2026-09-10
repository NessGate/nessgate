# @nessgate/resolver

The open, neutral resolver for the agentic web. Give it a domain and it reads whatever that
domain already publishes at the standard machine-discovery locations — ARD / `ai-catalog.json`,
A2A agent card, `llms.txt`, RFC 9727 api-catalog, Open Resource Discovery, RFC 6415
host-meta, OpenAPI — and returns **one normalized list**, each record carrying its `source`
and the native `sourceUrl` so you can verify against the domain directly.

- **Dependency-free.** Runs in browsers, Node, Deno, Workers, and agent runtimes.
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
  `source`, `sourceUrl`, `type` (the source's own label), `url`, and, where useful,
  `name` / `rel` / `id` / `raw`.
- `discovered` — the routing map: which standards were found, and where.
- `checked` — the standards probed.

Options: `{ fetch, timeoutMs = 8000, maxBytes = 1_000_000 }`. Bring your own `fetch` if the
runtime has none.

Also exported: `normalizeResources`, `normalizeDomain`, `PROBES`.

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
