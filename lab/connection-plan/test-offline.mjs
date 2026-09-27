// Deterministic, no-network tests for the connection-plan matcher.
//
// Each fixture is a captured `resolve()` answer (the exact shape the library
// returns), paired with a client profile and the expected verdict. No network,
// no timing — pure logic, so it proves the MATCHING is correct independently of
// whether any real domain happens to publish today. Run: node test-offline.mjs

import { buildConnectionPlan } from "./plan.mjs";
import { PROFILES } from "./profiles.mjs";

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.error(`FAIL   ${name}\n         got:  ${JSON.stringify(got)}\n         want: ${JSON.stringify(want)}`); }
};
const truthy = (name, got) => { if (got) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name} (expected truthy, got ${JSON.stringify(got)})`); } };

// --- captured discovery answers (verbatim resolve() shapes) ---------------
const D = {
  openapiApiKey: {
    domain: "api.example.com", provenance: "self-published", checked: ["openapi"],
    discovered: [{ type: "openapi", url: "https://api.example.com/openapi.json" }],
    resources: [{ source: "openapi", type: "openapi", url: "https://api.example.com/openapi.json", sourceUrl: "https://api.example.com/openapi.json", name: "Example API", security: [{ name: "k", type: "apiKey", in: "header" }], class: "verified-publisher-location" }],
  },
  openapiBearerOnly: {
    domain: "b.example.com", provenance: "self-published", checked: ["openapi"],
    discovered: [{ type: "openapi", url: "https://b.example.com/openapi.json" }],
    resources: [{ source: "openapi", type: "openapi", url: "https://b.example.com/openapi.json", sourceUrl: "https://b.example.com/openapi.json", name: "B API", security: [{ name: "bearer", type: "http", scheme: "bearer" }], class: "verified-publisher-location" }],
  },
  a2aOauth: {
    domain: "a.example.com", provenance: "self-published", checked: ["a2a-agent-card"],
    discovered: [{ type: "a2a-agent-card", url: "https://a.example.com/.well-known/agent-card.json" }],
    resources: [{ source: "a2a-agent-card", type: "a2a-agent-card", url: "https://a.example.com/a2a", sourceUrl: "https://a.example.com/.well-known/agent-card.json", name: "Ex Agent", raw: { name: "Ex Agent", version: "1.0", supportedInterfaces: [{ transport: "JSONRPC", url: "https://a.example.com/a2a" }] }, class: "publisher-hosted" }],
  },
  aidMcp: {
    domain: "aid.example.com", provenance: "self-published", checked: ["aid"],
    discovered: [{ type: "aid", url: "https://mcp.example.com/" }],
    resources: [{ source: "aid", type: "mcp", url: "https://mcp.example.com/", sourceUrl: "dns:_agent.aid.example.com", name: "AID MCP", raw: { version: "aid1", uri: "https://mcp.example.com/", proto: "mcp", auth: "oauth2" }, class: "publisher-declared" }],
  },
  mcpIntrospectedOk: {
    domain: "mcp.example.com", provenance: "self-published", checked: ["awp"],
    discovered: [{ type: "mcp", url: "https://mcp.example.com/mcp" }],
    resources: [{ source: "awp", type: "mcp", url: "https://mcp.example.com/mcp", sourceUrl: "https://mcp.example.com/.well-known/awp.json", introspection: { ok: true, protocolVersion: "2025-06-18" }, class: "verified-publisher-location" }],
  },
  mcpAuthRequired: {
    domain: "mcp2.example.com", provenance: "self-published", checked: ["awp"],
    discovered: [{ type: "mcp", url: "https://mcp2.example.com/mcp" }],
    resources: [{ source: "awp", type: "mcp", url: "https://mcp2.example.com/mcp", sourceUrl: "https://mcp2.example.com/.well-known/awp.json", introspection: { ok: false, status: "auth-required" }, class: "publisher-hosted" }],
  },
  empty: { domain: "nothing.example.com", provenance: "self-published", checked: ["llms.txt", "openapi"], discovered: [], resources: [] },
};

// --- 1. OpenAPI + apiKey vs a REST client that supports apiKey -------------
{
  const p = buildConnectionPlan(D.openapiApiKey, PROFILES["rest-tool"]);
  eq("openapi/apiKey → outcome protocol-only (version unconfirmable)", p.match.outcome, "protocol-only");
  eq("openapi/apiKey → 1 plan", p.connectionPlans.length, 1);
  eq("openapi/apiKey → auth label reused verbatim", p.connectionPlans[0].auth.methods.map((m) => m.label), ["apiKey"]);
  eq("openapi/apiKey → matchedOn.auth true", p.connectionPlans[0].matchedOn.auth, true);
  eq("openapi/apiKey → completeness version-unconfirmed", p.connectionPlans[0].completeness, "version-unconfirmed");
}

// --- 2. OpenAPI needs bearer, client only has apiKey → hard auth conflict --
{
  const p = buildConnectionPlan(D.openapiBearerOnly, { client: { supports: [{ protocol: "openapi", auth: ["apiKey"] }] } });
  eq("openapi/bearer vs apiKey-only → no-match", p.match.outcome, "no-match");
  eq("openapi/bearer → 0 plans", p.connectionPlans.length, 0);
  truthy("openapi/bearer → rejection reason names auth conflict", p.unmatched.serviceOffered.some((x) => /auth/.test(x.reason)));
}

// --- 3. A2A with a declared transport but undeclared auth -----------------
{
  const p = buildConnectionPlan(D.a2aOauth, PROFILES["a2a-agent"]);
  eq("a2a → outcome protocol-only", p.match.outcome, "protocol-only");
  eq("a2a → transport lowercased from card", p.connectionPlans[0].transport, "jsonrpc");
  eq("a2a → version carried from card", p.connectionPlans[0].version, "1.0");
  eq("a2a → completeness connection-undeclared (auth not surfaced)", p.connectionPlans[0].completeness, "connection-undeclared");
  truthy("a2a → note flags undeclared connection detail", p.notes.some((n) => /consult/.test(n)));
}

// --- 4. AID record whose p=mcp declares oauth2 ----------------------------
{
  const p = buildConnectionPlan(D.aidMcp, PROFILES["mcp-agent"]);
  eq("aid→mcp → protocol resolved to mcp", p.connectionPlans[0].protocol, "mcp");
  eq("aid→mcp → auth declared oauth2", p.connectionPlans[0].auth.methods.map((m) => m.label), ["oauth2"]);
  eq("aid→mcp → matchedOn.auth true", p.connectionPlans[0].matchedOn.auth, true);
  eq("aid→mcp → completeness connection-undeclared (no transport in AID)", p.connectionPlans[0].completeness, "connection-undeclared");
}

// --- 5. MCP introspected OK → a fully usable, COMPLETE plan ---------------
{
  const p = buildConnectionPlan(D.mcpIntrospectedOk, PROFILES["mcp-agent"]);
  eq("mcp/introspected → direct-match", p.match.outcome, "direct-match");
  eq("mcp/introspected → completeness complete", p.connectionPlans[0].completeness, "complete");
  eq("mcp/introspected → transport streamable-http", p.connectionPlans[0].transport, "streamable-http");
  eq("mcp/introspected → version confirmed", p.connectionPlans[0].version, "2025-06-18");
  truthy("mcp/introspected → selectedPlan set (client gave prefer)", p.selectedPlan && p.selectedPlan.protocol === "mcp");
}

// --- 6. MCP behind auth wall → observed (inferred), not declared ----------
{
  const p = buildConnectionPlan(D.mcpAuthRequired, PROFILES["mcp-agent"]);
  eq("mcp/auth-wall → protocol-only", p.match.outcome, "protocol-only");
  eq("mcp/auth-wall → auth detail inferred", p.connectionPlans[0].auth.detail, "inferred");
  truthy("mcp/auth-wall → note says auth was OBSERVED", p.notes.some((n) => /OBSERVED/.test(n)));
}

// --- 7. Empty discovery → none-found --------------------------------------
{
  const p = buildConnectionPlan(D.empty, PROFILES.polyglot);
  eq("empty → none-found", p.match.outcome, "none-found");
  eq("empty → clientOnly lists every unmet client protocol", p.unmatched.clientOnly.length, PROFILES.polyglot.client.supports.length);
}

// --- 8. Protocol mismatch (service REST, client MCP-only) → no-match ------
{
  const p = buildConnectionPlan(D.openapiApiKey, PROFILES["mcp-agent"]);
  eq("mismatch → no-match", p.match.outcome, "no-match");
  truthy("mismatch → serviceOffered explains client lacks protocol", p.unmatched.serviceOffered.some((x) => /does not support/.test(x.reason)));
  truthy("mismatch → selectedPlan null (no usable plan)", p.selectedPlan === null);
}

// --- 9. Neutrality invariant: no numeric score anywhere in the output -----
{
  const p = buildConnectionPlan(D.mcpIntrospectedOk, PROFILES["mcp-agent"]);
  const s = JSON.stringify(p);
  truthy("neutrality → no 'score'/'confidence'/'rank' field", !/"(score|confidence|rank|rating)"\s*:/i.test(s));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
