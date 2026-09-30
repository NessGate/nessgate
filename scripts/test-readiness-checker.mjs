// Gate test for the opt-in connection-readiness checker.
//
//  (1) PARITY: the five pure assessors are byte-behaviorally identical in the
//      worker (src/worker.js) and the library (public/resolver.mjs).
//  (2) OUTCOMES: each assessor returns the honest outcome + named gaps.
//  (3) IO: assessReadiness() drives the MCP OAuth chain (RFC 9728 → RFC 8414),
//      OpenAPI, and pointer paths end-to-end against a mock fetch (no network).
//  (4) NEUTRALITY: no numeric score anywhere in a readiness record.
//
// No network. Part of `npm run check`. Run: node scripts/test-readiness-checker.mjs

import * as worker from "../src/worker.js";
const lib = await import("../public/resolver.mjs");

let pass = 0, fail = 0;
const eq = (name, got, want) => { const ok = JSON.stringify(got) === JSON.stringify(want); if (ok) { pass++; } else { fail++; console.error(`FAIL  ${name}\n        got:  ${JSON.stringify(got)}\n        want: ${JSON.stringify(want)}`); } };
const ok_ = (name, cond) => { if (cond) pass++; else { fail++; console.error(`FAIL  ${name}`); } };

/* (1) worker/library parity on the pure assessors + matcher -------------- */
const PURE = ["extractProtocolVersion", "readinessProtocol", "assessOpenApiReadiness", "assessA2aReadiness", "assessMcpReadiness", "assessFetchFailure", "matchClient", "canonClientProtocol"];
for (const fn of PURE) ok_(`worker & library both export ${fn}`, typeof worker[fn] === "function" && typeof lib[fn] === "function");

const parityCases = [
  ["extractProtocolVersion", ['{"result":{"protocolVersion":"2025-06-18"}}']],
  ["extractProtocolVersion", ["event: message\ndata: {\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n\n"]],
  ["extractProtocolVersion", ["not json"]],
  ["readinessProtocol", [{ source: "mcp-registry", type: "mcp-server", url: "https://mcp.x.com/" }]],
  ["readinessProtocol", [{ source: "openapi", type: "openapi", url: "https://x.com/openapi.json" }]],
  ["readinessProtocol", [{ source: "aid", type: "mcp", url: "https://x/mcp", raw: { proto: "mcp" } }]],
  ["readinessProtocol", [{ source: "llms.txt", type: "llms.txt", url: "https://x/llms.txt" }]],
  ["readinessProtocol", [{ source: "ard-catalog", type: "application/json", url: "https://api.x/.well-known/oauth-protected-resource/mcp" }]],
  ["readinessProtocol", [{ source: "llms.txt", type: "llms.txt", url: "https://x.com/docs/mcp.md" }]],
  ["readinessProtocol", [{ source: "x", type: "text/html", url: "https://x.com/blog/openapi-tips" }]],
  ["readinessProtocol", [{ source: "x", type: "text/html", url: "https://x.com/mcp-guide" }]],
  ["readinessProtocol", [{ source: "x", type: "x", url: "https://x.com/v1/mcp" }]],
  ["readinessProtocol", [{ source: "x", type: "x", url: "https://x.com/openapi.yaml" }]],
  ["assessOpenApiReadiness", [{ openapi: "3.1.0", servers: [{ url: "https://a" }], components: { securitySchemes: { k: { type: "http", scheme: "bearer" } } } }]],
  ["assessOpenApiReadiness", [{ openapi: "3.0.0", servers: [{ url: "https://a" }] }]],
  ["assessOpenApiReadiness", [null]],
  ["assessA2aReadiness", [{ protocolVersion: "0.3.0", preferredTransport: "JSONRPC", url: "https://a/", securitySchemes: { o: { type: "oauth2" } } }]],
  ["assessA2aReadiness", [{ url: "https://x/.well-known/agent.json", capabilities: {} }]],
  ["assessMcpReadiness", [{ init: { ok: true, status: 200, protocolVersion: "2025-06-18" } }]],
  ["assessMcpReadiness", [{ init: { ok: false, status: 401 }, prm: { authorization_servers: ["https://a"] }, as: { authorization_endpoint: "https://a/az", token_endpoint: "https://a/tok" } }]],
  ["assessMcpReadiness", [{ init: { ok: false, status: 403, wwwAuthenticate: null } }]],
  ["matchClient", [{ protocol: "mcp", transport: "streamable-http", version: null, auth: { required: true, type: "oauth2" } }, { protocol: "mcp", auth: ["oauth2", "none"] }]],
  ["matchClient", [{ protocol: "openapi", transport: "https", auth: { required: true, type: "http:bearer" } }, { protocol: "openapi", auth: ["apiKey"] }]],
  ["matchClient", [{ protocol: "a2a-agent-card", transport: "jsonrpc", version: "0.3.0", auth: { required: false } }, { protocol: "a2a", auth: ["oauth2"] }]],
  ["canonClientProtocol", ["a2a"]],
  ["canonClientProtocol", ["rest"]],
  ["assessFetchFailure", ["openapi", 404, "OpenAPI document"]],
  ["assessFetchFailure", ["openapi", 200, "OpenAPI document"]],
  ["assessFetchFailure", ["a2a-agent-card", 403, "A2A agent card"]],
  ["assessFetchFailure", ["openapi", 0, "OpenAPI document"]],
  ["assessMcpReadiness", [{ init: { ok: false, status: 404 } }]],
  ["assessOpenApiReadiness", [{ openapi: "3.0.3", servers: [{ url: "https://a" }], security: [] }]],
  ["assessOpenApiReadiness", [{ openapi: "3.0.3", servers: [{ url: "https://a" }], security: [{ k: [] }] }]],
  ["assessMcpReadiness", [{ init: { ok: true, status: 200, protocolVersion: null } }]],
  ["readinessProtocol", [{ source: "llms.txt", type: "llms.txt", url: "https://replicate.com/docs/reference/mcp" }]],
  ["readinessProtocol", [{ source: "x", type: "x", url: "https://x.com/blog/mcp" }]],
  ["readinessProtocol", [{ source: "x", type: "x", url: "https://x.com/reference/openapi" }]],
];
for (const [fn, args] of parityCases) {
  eq(`parity ${fn}(${JSON.stringify(args[0]).slice(0, 40)}…)`, worker[fn](...args), lib[fn](...args));
}

/* metadata docs are not endpoints (the MCP resolver fetches them itself) */
eq("oauth-protected-resource is not a connectable endpoint", lib.readinessProtocol({ source: "ard-catalog", type: "application/json", url: "https://api.x/.well-known/oauth-protected-resource/mcp" }), null);

/* detection tightening (audit #2): reject look-alikes, keep real endpoints */
const rp = (u, extra = {}) => lib.readinessProtocol({ source: "x", type: "x", url: u, ...extra });
eq("noise: /docs/mcp.md (doc) → null", rp("https://x.com/docs/mcp.md"), null);
eq("noise: /blog/openapi-tips (substring, not segment) → null", rp("https://x.com/blog/openapi-tips"), null);
eq("noise: /mcp-guide (not a bounded segment) → null", rp("https://x.com/mcp-guide"), null);
eq("noise: /openapi-guide.html → null", rp("https://x.com/openapi-guide.html"), null);
eq("noise: mcp. host but .html doc → null", rp("https://mcp.x.com/blog.html"), null);
eq("keep: /mcp → mcp", rp("https://x.com/mcp"), "mcp");
eq("keep: /v1/mcp → mcp", rp("https://x.com/v1/mcp"), "mcp");
eq("keep: mcp. host root → mcp", rp("https://mcp.x.com/"), "mcp");
eq("keep: /openapi.json → openapi", rp("https://x.com/openapi.json"), "openapi");
eq("keep: /openapi.yaml → openapi", rp("https://x.com/openapi.yaml"), "openapi");
eq("keep: /.well-known/agent.json → a2a", rp("https://x.com/.well-known/agent.json"), "a2a-agent-card");
eq("keep: explicit type=openapi even on odd url → openapi", lib.readinessProtocol({ source: "openapi", type: "openapi", url: "https://x.com/spec" }), "openapi");

/* (2) outcome correctness (via the library) ------------------------------ */
eq("openapi complete → credentials-required", lib.assessOpenApiReadiness({ openapi: "3.1.0", servers: [{ url: "https://a" }], components: { securitySchemes: { o: { type: "oauth2", flows: { authorizationCode: { authorizationUrl: "https://a/az", tokenUrl: "https://a/tok", scopes: { r: "x" } } } } } } }).outcome, "credentials-required");
eq("openapi no-security → incomplete", lib.assessOpenApiReadiness({ openapi: "3.0.0", servers: [{ url: "https://a" }] }).outcome, "incomplete");
ok_("openapi no-security → names securitySchemes", lib.assessOpenApiReadiness({ openapi: "3.0.0", servers: [{ url: "https://a" }] }).missing.some((m) => m.includes("securitySchemes")));
eq("a2a modern secured → credentials-required", lib.assessA2aReadiness({ protocolVersion: "0.3.0", preferredTransport: "JSONRPC", url: "https://a/", securitySchemes: { o: { type: "oauth2" } } }).outcome, "credentials-required");
eq("a2a open url → ready", lib.assessA2aReadiness({ protocolVersion: "0.3.0", url: "https://a/rpc" }).outcome, "ready");
eq("a2a card-file url → incomplete (no false transport)", lib.assessA2aReadiness({ url: "https://x/.well-known/agent.json" }).transport, null);
eq("mcp public → ready", lib.assessMcpReadiness({ init: { ok: true, status: 200, protocolVersion: "2025-06-18" } }).outcome, "ready");
eq("mcp+oauth chain → credentials-required", lib.assessMcpReadiness({ init: { ok: false, status: 401 }, prm: { authorization_servers: ["https://a"] }, as: { authorization_endpoint: "https://a/az", token_endpoint: "https://a/tok", registration_endpoint: "https://a/reg" } }).outcome, "credentials-required");
ok_("mcp+oauth → DCR detected", lib.assessMcpReadiness({ init: { ok: false, status: 401 }, prm: {}, as: { authorization_endpoint: "https://a/az", token_endpoint: "https://a/tok", registration_endpoint: "https://a/reg" } }).auth.dynamicClientRegistration === true);
ok_("mcp no-metadata → names RFC 9728", lib.assessMcpReadiness({ init: { ok: false, status: 401 } }).missing[0].includes("RFC 9728"));
ok_("mcp bare-403 → undetermined (not a false OAuth wall)", lib.assessMcpReadiness({ init: { ok: false, status: 403, wwwAuthenticate: null } }).missing[0].includes("undetermined"));

/* broken vs incomplete (grounded in the stability experiment): broken ONLY on
   positive evidence — an ANSWER that contradicts the declaration. Denials and
   network failures are vantage-ambiguous and never read as broken. */
eq("fetch 404 → broken", lib.assessFetchFailure("openapi", 404, "OpenAPI document").outcome, "broken");
eq("fetch 5xx → broken", lib.assessFetchFailure("openapi", 503, "OpenAPI document").outcome, "broken");
eq("fetch 200-unparseable → broken", lib.assessFetchFailure("openapi", 200, "OpenAPI document").outcome, "broken");
eq("fetch 403 (denial) → incomplete, NOT broken", lib.assessFetchFailure("openapi", 403, "OpenAPI document").outcome, "incomplete");
eq("fetch network-fail → incomplete, NOT broken", lib.assessFetchFailure("openapi", 0, "OpenAPI document").outcome, "incomplete");
eq("mcp handshake 404 → broken", lib.assessMcpReadiness({ init: { ok: false, status: 404 } }).outcome, "broken");
eq("mcp handshake 500 → broken", lib.assessMcpReadiness({ init: { ok: false, status: 502 } }).outcome, "broken");
eq("mcp handshake network-fail → incomplete", lib.assessMcpReadiness({ init: { ok: false, status: 0 } }).outcome, "incomplete");
eq("mcp handshake 405 (ambiguous legacy transport) → incomplete, NOT broken", lib.assessMcpReadiness({ init: { ok: false, status: 405 } }).outcome, "incomplete");

/* ready requires PROTOCOL evidence — an HTML docs page answering 200 is not an
   MCP endpoint (real false positive found in external testing: replicate.com) */
eq("mcp 200 WITHOUT initialize result → incomplete, never ready", lib.assessMcpReadiness({ init: { ok: true, status: 200, protocolVersion: null } }).outcome, "incomplete");
ok_("mcp 200-not-mcp → names protocol-level evidence", lib.assessMcpReadiness({ init: { ok: true, status: 200, protocolVersion: null } }).missing[0].includes("protocol-level evidence"));
eq("mcp 200 WITH initialize result → ready (unchanged)", lib.assessMcpReadiness({ init: { ok: true, status: 200, protocolVersion: "2025-06-18" } }).outcome, "ready");
/* doc-section paths never fuzzy-match as endpoints */
eq("noise: /docs/reference/mcp (the replicate FP) → null", lib.readinessProtocol({ source: "llms.txt", type: "llms.txt", url: "https://replicate.com/docs/reference/mcp" }), null);
eq("noise: /blog/mcp → null", rp("https://x.com/blog/mcp"), null);
eq("noise: /reference/openapi → null", rp("https://x.com/reference/openapi"), null);
eq("keep: pinecone-style /mcp/ → mcp", rp("https://www.pinecone.io/mcp/"), "mcp");
eq("keep: explicit type=mcp even under /docs/ → mcp (labels trusted)", lib.readinessProtocol({ source: "awp", type: "mcp", url: "https://x.com/docs/endpoint" }), "mcp");

/* OpenAPI explicit-open: security:[] is the spec's OWN "no auth" declaration */
eq("openapi security:[] → ready (explicitly open)", lib.assessOpenApiReadiness({ openapi: "3.0.3", servers: [{ url: "https://a" }], security: [] }).outcome, "ready");
eq("openapi security:[] → auth not required", lib.assessOpenApiReadiness({ openapi: "3.0.3", servers: [{ url: "https://a" }], security: [] }).auth.required, false);
eq("openapi NO security + NO schemes → still incomplete (didn't say ≠ none)", lib.assessOpenApiReadiness({ openapi: "3.0.3", servers: [{ url: "https://a" }] }).outcome, "incomplete");
eq("openapi non-empty security w/o schemes → incomplete (declares auth it never defines)", lib.assessOpenApiReadiness({ openapi: "3.0.3", servers: [{ url: "https://a" }], security: [{ k: [] }] }).outcome, "incomplete");

/* ready-check CLI core: majority verdict + end-to-end with a mock fetch */
const rc = await import("../packages/resolver/ready-check.mjs");
eq("majority: unanimous ready → ready", rc.majorityVerdict(["ready", "ready", "ready"]), "ready");
eq("majority: any disagreement → unstable (zapier class)", rc.majorityVerdict(["ready", "broken", "ready"]), "unstable");
eq("majority: unanimous creds → credentials-required", rc.majorityVerdict(["credentials-required", "credentials-required"]), "credentials-required");
eq("majority: empty → unobserved", rc.majorityVerdict([]), "unobserved");
{
  // Mock domain publishing ONLY an explicitly-open OpenAPI: readyCheck must PASS.
  const spec = { openapi: "3.1.0", servers: [{ url: "https://api.ex.com" }], security: [], paths: {} };
  const fetch = async (url) => {
    const ok = String(url).endsWith("/openapi.json");
    const body = ok ? JSON.stringify(spec) : "not found";
    const bytes = new TextEncoder().encode(body);
    return { ok, status: ok ? 200 : 404, url: String(url), headers: { get: () => null }, text: async () => body, arrayBuffer: async () => bytes.buffer };
  };
  const r = await rc.readyCheck("ex.com", { fetch, observations: 2, timeoutMs: 500, deadlineMs: 5000 });
  eq("readyCheck e2e → verdict ready", r.verdict, "ready");
  eq("readyCheck e2e → pass true", r.pass, true);
  eq("readyCheck e2e → endpoint observed twice, unanimously", r.endpoints[0].observations, ["ready", "ready"]);
}
{
  // Mock domain publishing nothing → FAIL with publish guidance.
  const fetch = async (url) => ({ ok: false, status: 404, url: String(url), headers: { get: () => null }, text: async () => "nope", arrayBuffer: async () => new TextEncoder().encode("nope").buffer });
  const r = await rc.readyCheck("empty.ex.com", { fetch, observations: 1, timeoutMs: 300, deadlineMs: 3000 });
  eq("readyCheck empty → nothing-connectable", r.verdict, "nothing-connectable");
  ok_("readyCheck empty → fail with publish guidance", r.pass === false && /Publish a machine-readable/.test(r.note));
}

/* matchClient (client × service) — deterministic intersection, tri-state */
ok_("match: oauth2 service ∩ oauth2 client → compatible", lib.matchClient({ protocol: "mcp", auth: { required: true, type: "oauth2" } }, { protocol: "mcp", auth: ["oauth2", "none"] }).compatible === true);
eq("match: oauth2 ∩ {oauth2,none} → auth true", lib.matchClient({ protocol: "mcp", auth: { required: true, type: "oauth2" } }, { protocol: "mcp", auth: ["oauth2"] }).matchedOn.auth, true);
ok_("match: bearer service vs apiKey-only client → INCOMPATIBLE", lib.matchClient({ protocol: "openapi", auth: { required: true, type: "http:bearer" } }, { protocol: "openapi", auth: ["apiKey"] }).compatible === false);
eq("match: client unconstrained → auth any", lib.matchClient({ protocol: "mcp", auth: { required: true, type: "oauth2" } }, { protocol: "mcp" }).matchedOn.auth, "any");
eq("match: service auth undeclared → unknown (not a hard fail)", lib.matchClient({ protocol: "mcp", auth: undefined }, { protocol: "mcp", auth: ["oauth2"] }).matchedOn.auth, "unknown");
ok_("match: no-auth service → usable by any client", lib.matchClient({ protocol: "a2a-agent-card", auth: { required: false } }, { protocol: "a2a", auth: ["oauth2"] }).compatible === true);
eq("match: version conflict → incompatible", lib.matchClient({ protocol: "mcp", version: "2025-06-18" }, { protocol: "mcp", versions: ["2024-01-01"] }).compatible, false);
eq("canonClientProtocol alias a2a", lib.canonClientProtocol("a2a"), "a2a-agent-card");

/* (3) IO orchestration against a mock fetch (no network) ----------------- */
function resp(status, bodyObj, headers = {}) {
  const body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj);
  const bytes = new TextEncoder().encode(body);
  const h = {}; for (const k in headers) h[k.toLowerCase()] = headers[k];
  return { ok: status >= 200 && status < 300, status, url: "", headers: { get: (k) => (k.toLowerCase() in h ? h[k.toLowerCase()] : null) }, text: async () => body, arrayBuffer: async () => bytes.buffer };
}
function mockFetch(routes) {
  return async (url) => {
    const u = String(url);
    if (routes[u]) return routes[u];
    const pre = Object.keys(routes).find((k) => u.startsWith(k));
    return pre ? routes[pre] : resp(404, "");
  };
}

// MCP OAuth chain: 401 + resource_metadata → PRM → AS metadata → credentials-required.
{
  const fetch = mockFetch({
    "https://mcp.ex.com/mcp": resp(401, "", { "www-authenticate": 'Bearer resource_metadata="https://mcp.ex.com/.well-known/oauth-protected-resource"' }),
    "https://mcp.ex.com/.well-known/oauth-protected-resource": resp(200, { authorization_servers: ["https://auth.ex.com"] }),
    "https://auth.ex.com/.well-known/oauth-authorization-server": resp(200, { authorization_endpoint: "https://auth.ex.com/az", token_endpoint: "https://auth.ex.com/tok", scopes_supported: ["s1"], registration_endpoint: "https://auth.ex.com/reg" }),
  });
  const r = await lib.assessReadiness({ source: "mcp", type: "mcp", url: "https://mcp.ex.com/mcp" }, { fetch });
  eq("IO mcp chain → credentials-required", r.outcome, "credentials-required");
  eq("IO mcp chain → token endpoint resolved", r.auth.tokenEndpoint, "https://auth.ex.com/tok");
  eq("IO mcp chain → scopes surfaced", r.auth.scopes, ["s1"]);
}
// OpenAPI: fetch the spec → credentials-required.
{
  const fetch = mockFetch({ "https://api.ex.com/openapi.json": resp(200, { openapi: "3.1.0", servers: [{ url: "https://api.ex.com" }], components: { securitySchemes: { k: { type: "apiKey", in: "header", name: "x" } } } }) });
  const r = await lib.assessReadiness({ source: "openapi", type: "openapi", url: "https://api.ex.com/openapi.json" }, { fetch });
  eq("IO openapi → credentials-required", r.outcome, "credentials-required");
  eq("IO openapi → auth apiKey", r.auth.type, "apiKey");
  eq("IO openapi → version", r.version, "3.1.0");
}
// Pointer surface → incomplete, no fetch needed.
{
  let fetched = false;
  const fetch = async () => { fetched = true; return resp(404, ""); };
  const r = await lib.assessReadiness({ source: "llms.txt", type: "llms.txt", url: "https://x.com/llms.txt" }, { fetch });
  eq("IO pointer → incomplete", r.outcome, "incomplete");
  ok_("IO pointer → suggests following it", r.missing[0].includes("follow"));
  ok_("IO pointer → no fetch performed", fetched === false);
}
// SSRF guard: a private/reserved host is refused (no throw, honest incomplete).
{
  const fetch = async () => resp(200, { openapi: "3.1.0", servers: [{ url: "x" }], components: { securitySchemes: { k: { type: "apiKey" } } } });
  const r = await lib.assessReadiness({ source: "openapi", type: "openapi", url: "https://127.0.0.1/openapi.json" }, { fetch });
  eq("IO ssrf-guard → incomplete (blocked host never fetched)", r.outcome, "incomplete");
}

/* (4) neutrality: no numeric score/confidence/rank in a readiness record -- */
{
  const s = JSON.stringify(lib.assessMcpReadiness({ init: { ok: false, status: 401 }, prm: {}, as: { authorization_endpoint: "https://a/az", token_endpoint: "https://a/tok" } }));
  ok_("neutrality → no score/confidence/rank field", !/"(score|confidence|rank|rating)"\s*:/i.test(s));
}

console.log(fail ? `\nreadiness-checker: ${pass} passed, ${fail} FAILED` : `\nreadiness-checker: all ${pass} checks passed (parity + outcomes + IO + neutrality)`);
process.exit(fail ? 1 : 0);
