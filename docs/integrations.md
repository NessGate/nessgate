# Integrating NessGate

Three ways to depend on NessGate. All are zero-registration — no key, no account, no sign-up.
Pick whichever fits where your agent runs. Each returns the same normalized records.
Field-by-field reference for all response shapes: [`docs/data-model.md`](./data-model.md).

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

Beyond `resolve()`, the library also provides `plan(domain, clientCaps)` (a client-matched
connection plan with one outcome: `ready` / `credentials-required` / `incomplete` / `broken` /
`no-compatible-method`), `assessReadiness(resource)`, and two opt-in discovery extensions —
`registry: true` (MCP-Registry federation, failures disclosed as `federatedUnavailable`) and
`delegate: true` (bounded declared-pointer following with provenance and depth).

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

Two further endpoints build on it:

```bash
curl "https://nessgate.com/explore/example.com?readiness=1"      # per-endpoint readiness blocks
curl -X POST https://nessgate.com/connect/example.com \
  -H 'content-type: application/json' \
  -d '{"client":{"supports":[{"protocol":"mcp","auth":["oauth2","none"]}]}}'   # a connection plan
```

`?readiness=1` attaches a `readiness` block to each connectable resource
(`ready` / `credentials-required` / `incomplete` / `broken`, with `missing[]` naming anything
not published). `POST /connect/{domain}` matches the caller's declared client capabilities
against what the domain publishes and returns one outcome with a concrete plan (protocol,
endpoint, transport, version, auth metadata). Credentials stay with the caller.

## 3. MCP tool — for MCP-aware agents and clients

NessGate runs a remote MCP server (Streamable HTTP) exposing three read-only tools —
**`discover_domain`**, **`connect_domain`**, and **`check_readiness`** — the same answers as
`/discover`, `POST /connect`, and `/explore?readiness=1`. It is listed in the official MCP
Registry as **`com.nessgate/nessgate`**.

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

Exact config key names vary by client; the registry entry is the canonical source. Call
`discover_domain` with `{ "domain": "example.com" }`, or `connect_domain` with
`{ "domain": "example.com", "client": { "supports": [{ "protocol": "mcp" }] } }`.

## 4. Agent-framework examples

Ready-made tool wrappers over the HTTP endpoints, each runnable standalone:

- [`examples/langchain/`](../examples/langchain/) — `connect_domain` / `discover_domain` as
  LangChain `@tool`s, plus the MCP route via `langchain-mcp-adapters`.
- [`examples/llamaindex/`](../examples/llamaindex/) — the same two functions as LlamaIndex
  `FunctionTool`s (standard-library HTTP; `llama-index-core` only for the wrappers), plus the
  MCP route via `llama-index-tools-mcp`.

For any other framework, the MCP server (path 3) is the zero-maintenance route; the HTTP
endpoints (path 2) are a few lines in any language.

## 5. Inbound requests — inspecting callers (experimental)

The reverse direction — describing what an *incoming* automated caller declares and can
prove — is an experimental module in [`lab/nessgate-inspect/`](../lab/nessgate-inspect/). It
observes only (no allow/deny, no scores) and returns tiered, provenanced facts.

**Express / Connect (two lines):**

```js
import { nessgateInspect } from "./lab/nessgate-inspect/integrations/middleware.mjs";
app.use(nessgateInspect({ log: true }));     // every handler then has req.nessgate
```

**Cloudflare Worker (edge):**

```js
import { inspect } from "./lab/nessgate-inspect/inspect.mjs";
export default {
  async fetch(req) {
    const headers = Object.fromEntries(req.headers);
    const sourceIp = req.headers.get("cf-connecting-ip");   // the platform-provided peer
    return Response.json(await inspect({ method: req.method, url: req.url, headers }, { sourceIp }));
  },
};
```

**Behind nginx or another reverse proxy:** the source IP for network attribution must be the
real connection peer. Terminate at the proxy, ensure only the proxy can set
`X-Forwarded-For`, and pass `{ trustProxy: true }` to the middleware (off by default — a
caller-settable header is never trusted implicitly). With nginx, `proxy_set_header
X-Forwarded-For $remote_addr;` (overwrite, not append) gives the middleware the true peer.

Verification that needs the network (key directories, published IP ranges, reverse DNS) adds
round-trips; for latency-sensitive paths run the inspection out-of-band (from logs or a queue)
rather than inline.

---

Missing a discovery standard, or found a reason you wouldn't depend on this? Open an issue:
<https://github.com/NessGate/nessgate/issues>. A standard with a concrete, domain-native discovery
path is usually a small adapter.
