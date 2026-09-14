# Integrating NessGate

Three ways to depend on NessGate. All are zero-registration — no key, no account, no sign-up.
Pick whichever fits where your agent runs. Each returns the same normalized records.

Every record is `{ source, type, url, sourceUrl }`: `source` is which discovery mechanism found
it, `url` is the resource, and `sourceUrl` is the exact document on the domain so you can always
verify against the domain itself.

## 1. Library — embed it in your runtime

Dependency-free ESM. Fetches the target domain **directly**, so there is no runtime dependency on
nessgate.com (the hosted endpoint below offers the same lookup as a convenience, plus SSRF
guarding — see the note).

```bash
npm i @nessgate/resolver
```

```js
import { resolve } from "@nessgate/resolver";
const { resources } = await resolve("example.com");
for (const r of resources) console.log(r.type, r.url, "←", r.sourceUrl);
```

Runs anywhere with `fetch`: Node ≥18, Deno, Bun, Cloudflare Workers, and agent runtimes.

> **In a browser:** the code runs, but a browser can only fetch *other* domains that return CORS
> headers — most `.well-known` files don't — so browser code resolving **arbitrary** domains should
> use the hosted endpoint (path 2 below, open CORS). Resolving your **own** domain works directly.

> **Untrusted domains, server-side:** the embeddable library does no SSRF guarding (it has to run
> in browsers too). Validate the domain yourself, or use the hosted endpoint below, which applies
> HTTPS-only, private-IP, redirect and size protections.

**GB/Z 185.4 (China)** agent descriptions ("ACS") are normalized automatically when encountered
(source `gbz-185-4`) — no configuration needed. **GB/Z 185.5** gateway discovery is opt-in and
Node-only (there is no domain-native way to locate a gateway, so nothing is auto-discovered):

```js
const { resources } = await resolve("example.com", {
  gbz: {
    gatewayUrl: "https://your-acps-gateway.example",   // you configure this — never guessed
    fetch: myAuthenticatedFetch,                        // bring your own mTLS/OIDC-authenticated fetch
    query: { description: "what you're looking for" },  // the semantic discovery query
  },
});
// ACS records from the gateway carry provenance: "gbz-185-5-gateway"
```

This POSTs to the reference implementation's real `{gatewayUrl}/acps-adp-v2/discover` endpoint.
NessGate embeds no credential handling — your `fetch` supplies the certs/tokens. Never runs on the
hosted endpoint or in a browser.

## 2. HTTP endpoint — any language

Open CORS, no auth.

```bash
curl https://nessgate.com/discover/example.com
```

Returns `{ domain, provenance, note, discovered[], resources[], checked[] }`. The hosted endpoint
adds SSRF protections and caches at the edge for up to ~10 minutes.

For evidence-based resolution beyond the exact host, `GET https://nessgate.com/explore/{domain}`
additionally follows the pointers the domain's own files declare and federates the official MCP
Registry; every record carries an `evidence` class and a `provenance` chain. See the
[API docs](https://nessgate.com/api) for the contract.

## 3. MCP tool — for MCP-aware agents and clients

NessGate runs a remote MCP server (Streamable HTTP) exposing one tool, **`discover_domain`**. It is
listed in the official MCP Registry as **`com.nessgate/nessgate`**.

- **If your client installs from the MCP Registry**, search `com.nessgate/nessgate`.
- **Clients with native remote (Streamable HTTP) support** — point them at the URL:

  ```json
  {
    "mcpServers": {
      "nessgate": { "type": "streamable-http", "url": "https://nessgate.com/mcp" }
    }
  }
  ```

- **Clients that only speak stdio** (e.g. current Claude Desktop) — bridge with `mcp-remote`:

  ```json
  {
    "mcpServers": {
      "nessgate": { "command": "npx", "args": ["-y", "mcp-remote", "https://nessgate.com/mcp"] }
    }
  }
  ```

Exact config key names vary by client; the registry entry is the canonical source. Then call
`discover_domain` with `{ "domain": "example.com" }`.

---

Missing a discovery standard, or found a reason you wouldn't depend on this? Open an issue:
<https://github.com/NessGate/nessgate/issues>. A standard with a concrete, domain-native discovery
path is usually a small adapter.
