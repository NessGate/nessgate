# Installing NessGate in Cline (and other MCP clients)

NessGate is a **remote MCP server** (Streamable HTTP). There is nothing to build, install, or run
locally, and it needs **no API key, account, or environment variables**. Setup is a single config
entry that points at the hosted endpoint.

## Cline

Add this to Cline's MCP settings file (`cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "nessgate": {
      "url": "https://nessgate.com/mcp",
      "type": "streamableHttp"
    }
  }
}
```

That is the entire installation. Cline connects to `https://nessgate.com/mcp` and exposes one tool.

## The tool

- **`discover_domain`** — argument: `{ "domain": "example.com" }`. Given a domain, it reads the
  machine-readable resources that domain publishes across the standard discovery mechanisms (ARD,
  A2A, `llms.txt`, RFC 9727 api-catalog, OpenAPI, Open Resource Discovery, host-meta, ANP, UCP,
  DNS-AID) and returns one normalized answer. Every record includes a `sourceUrl` pointing back to
  the document on the domain, so results can be verified against the domain itself.

## Verify it works

Ask the agent to call `discover_domain` with `{ "domain": "stripe.com" }`. You should get a JSON
answer listing the resources that domain publishes, each linking back to its source.

## Notes

- No authentication, no secrets, no local process.
- Read-only: NessGate reads a domain on demand, stores nothing, and makes no ownership or safety
  claim.
- If `nessgate.com` is ever unreachable, the tool simply returns no results — it never blocks.
- Listed in the official MCP Registry as `com.nessgate/nessgate`.
