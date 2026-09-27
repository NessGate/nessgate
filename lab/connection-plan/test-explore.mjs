// Deterministic tests for the /explore adapter. Fixtures mirror REAL /explore
// output captured live (supabase, elevenlabs, stripe). Run: node test-explore.mjs

import { deriveProtocol, normalizeExplore } from "./explore.mjs";

let pass = 0, fail = 0;
const eq = (name, got, want) => { const ok = JSON.stringify(got) === JSON.stringify(want); if (ok) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name}\n         got:  ${JSON.stringify(got)}\n         want: ${JSON.stringify(want)}`); } };
const truthy = (name, got) => { if (got) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name} (got ${JSON.stringify(got)})`); } };

// --- deriveProtocol: media-type + URL shape → connectable protocol -----------
eq("openapi via media-type", deriveProtocol("ard-catalog", "application/openapi+json", "https://api.ex.com/v1-json"), "openapi");
eq("openapi via url path", deriveProtocol("api-catalog", "application/json", "https://api.ex.com/openapi.json"), "openapi");
eq("mcp via mcp-server type", deriveProtocol("mcp-registry", "mcp-server", "https://mcp.ex.com"), "mcp");
eq("mcp via /mcp path", deriveProtocol("ard-catalog", "application/json", "https://api.ex.com/v1/mcp"), "mcp");
eq("mcp via mcp. host", deriveProtocol("api-catalog", "item", "https://mcp.ex.com/mcp"), "mcp");
eq("a2a via agent.json", deriveProtocol("x", "application/json", "https://ex.com/.well-known/agent.json"), "a2a-agent-card");
eq("pointer stays null (llms.txt)", deriveProtocol("llms.txt", "llms.txt", "https://ex.com/llms.txt"), null);
eq("human doc stays null", deriveProtocol("api-catalog", "text/html", "https://ex.com/docs"), null);

// --- normalizeExplore on a supabase-shaped answer ----------------------------
const supabase = {
  domain: "supabase.com", outcome: "found",
  resources: [
    { source: "llms.txt", type: "llms.txt", url: "https://supabase.com/llms.txt", sourceUrl: "https://supabase.com/llms.txt", evidence: "publisher-hosted" },
    { source: "ard-catalog", type: "application/json", url: "https://mcp.supabase.com/mcp", sourceUrl: "https://supabase.com/.well-known/ard.json", evidence: "publisher-declared" },
    { source: "ard-catalog", type: "application/json", url: "https://api.supabase.com/.well-known/oauth-protected-resource/mcp", sourceUrl: "x", evidence: "publisher-declared" },
    { source: "ard-catalog", type: "application/openapi+json", url: "https://api.supabase.com/api/v1-json", sourceUrl: "x", evidence: "publisher-declared" },
    { source: "openapi", type: "openapi", url: "https://supabase.com/openapi.json", sourceUrl: "https://supabase.com/openapi.json", evidence: "publisher-hosted" },
  ],
  related: [
    { host: "github.com", class: "registry-verified-related", resources: [
      { source: "mcp-registry", type: "mcp-server", url: "https://github.com/supabase-community/supabase-mcp", sourceUrl: "reg", evidence: "namespace-verified" },
    ] },
  ],
};
{
  const d = normalizeExplore(supabase);
  truthy("supabase → drops oauth-protected-resource metadata (not an endpoint)", !d.resources.some((r) => r.url.includes("oauth-protected-resource")));
  truthy("supabase → mcp.supabase.com/mcp typed as mcp", d.resources.some((r) => r.url === "https://mcp.supabase.com/mcp" && r.type === "mcp"));
  truthy("supabase → api/v1-json typed as openapi", d.resources.some((r) => r.url === "https://api.supabase.com/api/v1-json" && r.source === "openapi"));
  truthy("supabase → federated github mcp-server flattened & typed mcp", d.resources.some((r) => r.url.includes("github.com/supabase-community") && r.type === "mcp"));
  truthy("supabase → llms.txt kept as pointer (source llms.txt)", d.resources.some((r) => r.source === "llms.txt"));
  truthy("supabase → evidence carried into class", d.resources.find((r) => r.url === "https://mcp.supabase.com/mcp").class === "publisher-declared");
}

// --- elevenlabs: mcp-registry endpoint surfaces as a connectable mcp ----------
{
  const eleven = { domain: "elevenlabs.io", outcome: "found", resources: [
    { source: "mcp-registry", type: "mcp-server", url: "https://api.us.elevenlabs.io/v1/mcp", sourceUrl: "reg", evidence: "namespace-verified" },
    { source: "api-catalog", type: "application/json", url: "https://api.elevenlabs.io/openapi.json", sourceUrl: "cat", evidence: "publisher-declared" },
  ] };
  const d = normalizeExplore(eleven);
  truthy("elevenlabs → registry MCP endpoint is connectable", d.resources.some((r) => r.type === "mcp" && r.url.endsWith("/v1/mcp")));
  truthy("elevenlabs → api-catalog openapi endpoint is connectable", d.resources.some((r) => r.source === "openapi" && r.url.endsWith("openapi.json")));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
