// Deterministic tests for bounded delegation extractors. Fixtures mirror REAL
// structures captured live (elevenlabs api-catalog; stripe-style llms.txt).
// Run: node test-delegate.mjs

import { endpointsFromApiCatalog, endpointsFromLlmsTxt, expandByDelegation } from "./delegate.mjs";

let pass = 0, fail = 0;
const eq = (name, got, want) => { const ok = JSON.stringify(got) === JSON.stringify(want); if (ok) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name}\n         got:  ${JSON.stringify(got)}\n         want: ${JSON.stringify(want)}`); } };
const truthy = (name, got) => { if (got) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name} (got ${JSON.stringify(got)})`); } };

// --- api-catalog (RFC 9727) → service-desc OpenAPI, skipping human links -----
{
  const catalog = { linkset: [{ anchor: "https://api.ex.io/v1", "service-desc": [{ href: "https://api.ex.io/openapi.json", type: "application/json" }], "service-doc": [{ href: "https://ex.io/docs", type: "text/html" }], status: [{ href: "https://status.ex.io/", type: "text/html" }] }] };
  const out = endpointsFromApiCatalog(catalog, "https://ex.io/.well-known/api-catalog");
  eq("api-catalog → 1 openapi endpoint (only service-desc)", out.length, 1);
  eq("api-catalog → correct href", out[0].url, "https://api.ex.io/openapi.json");
  eq("api-catalog → protocol openapi", out[0].source, "openapi");
  eq("api-catalog → skips service-doc/status (human)", out.map((o) => o.url), ["https://api.ex.io/openapi.json"]);
}

// --- llms.txt: extract ONLY machine specs, ignore doc/marketing links --------
{
  const llms = `# Stripe\n\n- [Payments](https://stripe.com/payments): docs.\n- [Docs](https://stripe.com/docs/api): human.\n`;
  eq("llms.txt (all human links) → nothing extracted", endpointsFromLlmsTxt(llms, "https://stripe.com/llms.txt"), []);
}
{
  const llms = `# Ex\n\n- [API spec](https://api.ex.io/openapi.json): machine.\n- [Agent](https://ex.io/.well-known/agent-card.json): a2a.\n- [MCP](https://ex.io/mcp): server.\n- [Blog](https://ex.io/blog): human.\n`;
  const out = endpointsFromLlmsTxt(llms, "https://ex.io/llms.txt");
  eq("llms.txt → 3 machine specs extracted", out.length, 3);
  eq("llms.txt → openapi detected", out.find((o) => o.url.includes("openapi")).source, "openapi");
  eq("llms.txt → a2a detected", out.find((o) => o.url.includes("agent-card")).source, "a2a-agent-card");
  eq("llms.txt → mcp detected", out.find((o) => o.url.endsWith("/mcp")).source, "mcp");
  truthy("llms.txt → blog (human) NOT extracted", !out.some((o) => o.url.includes("blog")));
}

// --- llms.txt: a docs page whose path contains "mcp" is NOT an endpoint ------
{
  const llms = `# Ex\n- [MCP guide](https://linear.app/docs/mcp.md): docs.\n- [Connector](https://platform.claude.com/docs/mcp-connector.md): docs.\n- [Real MCP](https://ex.io/mcp): endpoint.\n`;
  const out = endpointsFromLlmsTxt(llms, "https://ex.io/llms.txt");
  eq("llms.txt → excludes .md docs, keeps the real /mcp endpoint", out.map((o) => o.url), ["https://ex.io/mcp"]);
}

// --- expandByDelegation: appends declared endpoints, tags provenance ---------
{
  const catalogJson = { linkset: [{ "service-desc": [{ href: "https://api.ex.io/openapi.json" }] }] };
  const discovery = {
    domain: "ex.io",
    discovered: [{ type: "api-catalog", url: "https://ex.io/.well-known/api-catalog" }],
    resources: [{ source: "api-catalog", type: "api-catalog", url: "https://ex.io/.well-known/api-catalog", sourceUrl: "https://ex.io/.well-known/api-catalog" }],
  };
  const fakeFetch = async () => ({ status: 200, headers: new Map(), text: async () => JSON.stringify(catalogJson), arrayBuffer: async () => new TextEncoder().encode(JSON.stringify(catalogJson)).buffer, url: "https://ex.io/.well-known/api-catalog" });
  const { delegated, discovery: expanded } = await expandByDelegation(discovery, { fetch: fakeFetch });
  eq("expand → 1 endpoint delegated", delegated, 1);
  const added = expanded.resources.find((r) => r.url === "https://api.ex.io/openapi.json");
  truthy("expand → openapi endpoint appended to resources", !!added);
  eq("expand → tagged publisher-declared (Level 1)", added.class, "publisher-declared");
  eq("expand → provenance records the api-catalog hop", added.provenance[0].via, "api-catalog");
}

// --- expand is a no-op (returns same object) when nothing to follow ----------
{
  const discovery = { domain: "x.io", discovered: [{ type: "openapi", url: "https://x.io/openapi.json" }], resources: [] };
  const { delegated } = await expandByDelegation(discovery, { fetch: async () => { throw new Error("should not fetch"); } });
  eq("expand → 0 when no pointer surfaces", delegated, 0);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
