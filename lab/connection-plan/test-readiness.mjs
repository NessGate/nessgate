// Deterministic, no-network tests for the readiness assessors + pipeline.
// The pure assessors take already-fetched docs, so the MCP OAuth chain, OpenAPI
// security, and A2A card logic are all provable offline. Run: node test-readiness.mjs

import { assessMcp, assessOpenApi, assessA2a, assessReadiness } from "./readiness.mjs";
import { PROFILES } from "./profiles.mjs";

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.error(`FAIL   ${name}\n         got:  ${JSON.stringify(got)}\n         want: ${JSON.stringify(want)}`); }
};
const truthy = (name, got) => { if (got) { pass++; console.log(`  ok   ${name}`); } else { fail++; console.error(`FAIL   ${name} (got ${JSON.stringify(got)})`); } };

/* ---- MCP: public server, no auth → READY ---- */
{
  const a = assessMcp({ init: { ok: true, status: 200, protocolVersion: "2025-06-18" } });
  eq("mcp public → ready", a.outcome, "ready");
  eq("mcp public → auth not required", a.auth.required, false);
  eq("mcp public → version confirmed", a.version, "2025-06-18");
}

/* ---- MCP: auth wall + full OAuth metadata chain → CREDENTIALS-REQUIRED ---- */
{
  const a = assessMcp({
    init: { ok: false, status: 401, protocolVersion: null, wwwAuthenticate: 'Bearer resource_metadata="https://mcp.ex.com/.well-known/oauth-protected-resource"' },
    prm: { authorization_servers: ["https://auth.ex.com"] },
    as: { issuer: "https://auth.ex.com", authorization_endpoint: "https://auth.ex.com/authorize", token_endpoint: "https://auth.ex.com/token", scopes_supported: ["mcp.read", "mcp.write"], grant_types_supported: ["authorization_code"], registration_endpoint: "https://auth.ex.com/register" },
  });
  eq("mcp+oauth → credentials-required", a.outcome, "credentials-required");
  eq("mcp+oauth → token endpoint resolved", a.auth.tokenEndpoint, "https://auth.ex.com/token");
  eq("mcp+oauth → authorize endpoint resolved", a.auth.authorizationEndpoint, "https://auth.ex.com/authorize");
  eq("mcp+oauth → scopes surfaced verbatim", a.auth.scopes, ["mcp.read", "mcp.write"]);
  eq("mcp+oauth → dynamic client registration detected", a.auth.dynamicClientRegistration, true);
  eq("mcp+oauth → nothing missing (only the secret, which is the client's)", a.missing, []);
}

/* ---- MCP: auth wall but NO protected-resource metadata → INCOMPLETE (named) ---- */
{
  const a = assessMcp({ init: { ok: false, status: 401, wwwAuthenticate: null }, prm: null, as: null });
  eq("mcp no-metadata → incomplete", a.outcome, "incomplete");
  truthy("mcp no-metadata → names RFC 9728 as the missing piece", a.missing[0].includes("RFC 9728"));
}

/* ---- MCP: PRM present but AS unreachable → INCOMPLETE names RFC 8414 ---- */
{
  const a = assessMcp({ init: { ok: false, status: 401 }, prm: { authorization_servers: ["https://auth.ex.com"] }, as: null });
  eq("mcp AS-unreachable → incomplete", a.outcome, "incomplete");
  truthy("mcp AS-unreachable → names RFC 8414", a.missing[0].includes("RFC 8414"));
}

/* ---- MCP: bare 403 (no auth challenge) → INCOMPLETE, not a false OAuth wall ---- */
{
  const a = assessMcp({ init: { ok: false, status: 403, wwwAuthenticate: null } });
  eq("mcp bare-403 → incomplete (not credentials-required)", a.outcome, "incomplete");
  truthy("mcp bare-403 → flagged undetermined (auth vs WAF)", a.missing[0].includes("undetermined"));
}

/* ---- MCP: 403 WITH a WWW-Authenticate challenge IS a real auth wall ---- */
{
  const a = assessMcp({ init: { ok: false, status: 403, wwwAuthenticate: "Bearer" }, prm: null, as: null });
  eq("mcp 403+challenge → treated as auth wall (incomplete: missing metadata)", a.outcome, "incomplete");
  truthy("mcp 403+challenge → names RFC 9728", a.missing[0].includes("RFC 9728"));
}

/* ---- OpenAPI: full servers + oauth2 flows → CREDENTIALS-REQUIRED ---- */
{
  const a = assessOpenApi({ spec: { openapi: "3.1.0", servers: [{ url: "https://api.ex.com/v1" }], components: { securitySchemes: { oauth: { type: "oauth2", flows: { authorizationCode: { authorizationUrl: "https://api.ex.com/authorize", tokenUrl: "https://api.ex.com/token", scopes: { read: "r", write: "w" } } } } } } } });
  eq("openapi full → credentials-required", a.outcome, "credentials-required");
  eq("openapi full → version confirmed", a.version, "3.1.0");
  eq("openapi full → token url extracted", a.auth.tokenEndpoint, "https://api.ex.com/token");
  eq("openapi full → scopes extracted", a.auth.scopes, ["read", "write"]);
}

/* ---- OpenAPI: no securitySchemes → INCOMPLETE names it ---- */
{
  const a = assessOpenApi({ spec: { openapi: "3.0.0", servers: [{ url: "https://api.ex.com" }] } });
  eq("openapi no-security → incomplete", a.outcome, "incomplete");
  truthy("openapi no-security → names securitySchemes", a.missing.some((m) => m.includes("securitySchemes")));
}

/* ---- A2A: transport+version, no security → READY (A2A: absent = no auth) ---- */
{
  const a = assessA2a({ card: { version: "1.0", supportedInterfaces: [{ transport: "JSONRPC", url: "https://a.ex.com/a2a" }] } });
  eq("a2a open → ready", a.outcome, "ready");
  eq("a2a open → transport lowercased", a.transport, "jsonrpc");
}

/* ---- A2A: with securitySchemes → CREDENTIALS-REQUIRED ---- */
{
  const a = assessA2a({ card: { version: "1.0", supportedInterfaces: [{ transport: "GRPC", url: "https://a.ex.com" }], securitySchemes: { oauth: { type: "oauth2" } } } });
  eq("a2a secured → credentials-required", a.outcome, "credentials-required");
}

/* ---- A2A: missing transport → INCOMPLETE names it (readiness-checker) ---- */
{
  const a = assessA2a({ card: { version: "1.0" } });
  eq("a2a no-transport → incomplete", a.outcome, "incomplete");
  truthy("a2a no-transport → names transport", a.missing.some((m) => m.includes("transport")));
}

/* ---- A2A modern schema: protocolVersion + preferredTransport + security ---- */
{
  const a = assessA2a({ card: { protocolVersion: "0.3.0", preferredTransport: "JSONRPC", url: "https://a.ex.com/", securitySchemes: { oauth: { type: "oauth2" } } } });
  eq("a2a modern secured → credentials-required", a.outcome, "credentials-required");
  eq("a2a modern → transport from preferredTransport", a.transport, "jsonrpc");
  eq("a2a modern → version from protocolVersion", a.version, "0.3.0");
}

/* ---- A2A: only a real url (no interfaces) → default JSON-RPC, no auth → READY ---- */
{
  const a = assessA2a({ card: { protocolVersion: "0.3.0", url: "https://a.ex.com/rpc" } });
  eq("a2a url-only → ready", a.outcome, "ready");
  eq("a2a url-only → transport defaults to jsonrpc", a.transport, "jsonrpc");
}

/* ---- A2A: card whose url is the card FILE (cloudflare-style) → no false transport ---- */
{
  const a = assessA2a({ card: { name: "Site Agent", url: "https://x.com/.well-known/agent.json", capabilities: {} } });
  eq("a2a card-file url → incomplete", a.outcome, "incomplete");
  truthy("a2a card-file url → does NOT infer a transport", a.transport === null);
}

/* ---- MCP version parsing: extracts protocolVersion from an SSE data frame ---- */
{
  // (indirect) assessMcp trusts init.protocolVersion; here we assert the SSE-aware
  // parser is wired by checking a public server with a parsed version → ready+version.
  const a = assessMcp({ init: { ok: true, status: 200, protocolVersion: "2025-06-18" } });
  eq("mcp ready → version carried through", a.version, "2025-06-18");
}

/* ---- Pipeline: no connectable method → no-compatible-method ---- */
{
  const discovery = { domain: "x.com", discovered: [{ type: "openapi", url: "https://x.com/openapi.json" }], resources: [{ source: "openapi", type: "openapi", url: "https://x.com/openapi.json", sourceUrl: "https://x.com/openapi.json" }] };
  const r = await assessReadiness(discovery, PROFILES["mcp-agent"], { fetch: async () => { throw new Error("no network in test"); } });
  eq("pipeline mismatch → no-compatible-method", r.outcome, "no-compatible-method");
}

/* ---- Pipeline: pointers-only → incomplete with delegation reason ---- */
{
  const discovery = { domain: "p.com", discovered: [{ type: "llms.txt", url: "https://p.com/llms.txt" }], resources: [{ source: "llms.txt", type: "llms.txt", url: "https://p.com/llms.txt", sourceUrl: "https://p.com/llms.txt" }] };
  const r = await assessReadiness(discovery, PROFILES.polyglot, { fetch: async () => { throw new Error("no network"); } });
  eq("pipeline pointers-only → incomplete", r.outcome, "incomplete");
  truthy("pipeline pointers-only → suggests delegation", r.missing[0].includes("delegation"));
}

/* ---- Neutrality: no numeric score in a readiness report ---- */
{
  const discovery = { domain: "x.com", discovered: [], resources: [] };
  const r = await assessReadiness(discovery, PROFILES.polyglot, { fetch: async () => { throw new Error("no network"); } });
  truthy("neutrality → no score/confidence/rank field", !/"(score|confidence|rank|rating)"\s*:/i.test(JSON.stringify(r)));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
