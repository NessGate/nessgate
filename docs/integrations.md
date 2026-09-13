# Integrating NessGate

Three ways to depend on NessGate. All are zero-registration — no key, no account, no sign-up.
Pick whichever fits where your agent runs. Each returns the same normalized records.

Every record is `{ source, type, url, sourceUrl }`: `source` is which discovery mechanism found
it, `url` is the resource, and `sourceUrl` is the exact document on the domain so you can always
verify against the domain itself.

## 1. Library — embed it in your runtime

Dependency-free ESM. Fetches the target domain **directly**, so there is no runtime dependency on
nessgate.com (nessgate.com just runs the same code as a hosted convenience).

```bash
npm i @nessgate/resolver
```

```js
import { resolve } from "@nessgate/resolver";
const { resources } = await resolve("example.com");
for (const r of resources) console.log(r.type, r.url, "←", r.sourceUrl);
```

Runs in Node ≥18, Deno, Bun, browsers, Cloudflare Workers, and agent runtimes.

> Server-side callers passing **untrusted** domains: the embeddable library does no SSRF guarding
> (it has to run in browsers too). Validate the domain yourself, or use the hosted endpoint below,
> which applies HTTPS-only, private-IP, redirect and size protections.

## 2. HTTP endpoint — any language

Open CORS, no auth.

```bash
curl https://nessgate.com/discover/example.com
```

Returns `{ domain, provenance, note, discovered[], resources[], checked[] }`. The hosted endpoint
adds SSRF protections and caches at the edge for up to ~10 minutes.

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
