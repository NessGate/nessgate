// NessGate — Connection-READINESS layer (EXPERIMENTAL, lab-only).
//
// Builds on plan.mjs. Where the planner answers "is this compatible?", this layer
// answers the stronger question:
//
//   "Make the connection ready as far as possible — I only supply credentials."
//
// Pipeline:  compatibility plan  →  fill connection details (safe read-only
//            metadata following)  →  safe handshake  →  one clear outcome.
//
// FOUR OUTCOMES (enums, never scores — charter-neutral):
//   ready                 — enough is known AND a safe handshake confirmed it;
//                           no credentials needed.
//   credentials-required  — endpoint + transport + version + auth METHOD and its
//                           metadata (token/authorize URLs, scopes) are all known
//                           and reachable; only the secret is missing — and by
//                           design the secret STAYS WITH THE CLIENT.
//   incomplete            — a compatible protocol exists, but a connection element
//                           the protocol ITSELF defines is not machine-published.
//                           NessGate names exactly what is missing (the readiness-
//                           checker loop).
//   no-compatible-method  — no published protocol the client speaks.
//
// HARD LINES (design constraints):
//   - Advisory & local: we prepare the plan; the CLIENT connects directly.
//   - No credential storage — NessGate never sees or holds a secret.
//   - No proxying, no protocol translation, no AI, no new NessGate format.
//   - "ready" for an AUTHENTICATED service is impossible without creds, so authed
//     services top out at credentials-required. Readiness is vantage-relative:
//     a successful handshake is "from this vantage".

import { buildConnectionPlan } from "./plan.mjs";

/* --------------------------- safe read-only IO ---------------------------- */
// Every network touch here is a read-only GET/POST of public metadata, https-only,
// timed, byte-capped, and NEVER carries a credential. Auth-server URLs come from
// attacker-influenceable metadata, so each hop is host-guarded.

export const isBadHost = (h) => {
  h = String(h || "").toLowerCase().replace(/\.+$/, "");
  if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;         // IPv4 literal
  if (h.includes(":")) return true;                            // IPv6 literal
  if (/^(10|127)\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
};

async function readCapped(res, maxBytes) {
  const buf = await res.arrayBuffer();
  return new TextDecoder().decode(buf.byteLength > maxBytes ? buf.slice(0, maxBytes) : buf);
}

export async function safeGet(fetchImpl, url, { timeoutMs = 8000, maxBytes = 262144 } = {}) {
  let u;
  try { u = new URL(url); } catch { throw new Error("bad url"); }
  if (u.protocol !== "https:") throw new Error("non-https");
  if (isBadHost(u.hostname)) throw new Error("blocked host");
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { redirect: "follow", signal: ac.signal, headers: { accept: "application/json" } });
    return { status: res.status, headers: res.headers, text: await readCapped(res, maxBytes), finalUrl: res.url };
  } finally { clearTimeout(t); }
}

const getJson = async (fetchImpl, url, o) => { const r = await safeGet(fetchImpl, url, o); try { return { ...r, json: JSON.parse(r.text) }; } catch { return { ...r, json: null }; } };

// Extract the negotiated MCP protocolVersion from an initialize response, whether
// it came back as plain JSON or one/more SSE `data:` frames (Streamable HTTP).
function extractProtocolVersion(text) {
  const tryParse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  const pv = (j) => (j && j.result && typeof j.result.protocolVersion === "string" ? j.result.protocolVersion : null);
  let v = pv(tryParse(text));
  if (v) return v;
  for (const m of String(text).matchAll(/^data:\s*(.+)$/gm)) { v = pv(tryParse(m[1])); if (v) return v; }
  return null;
}

// A read-only MCP `initialize` (no tools/call, no secrets). Captures status, the
// WWW-Authenticate header (RFC 9728 points to resource metadata here), and the
// negotiated protocolVersion. Mirrors the resolver's own hardened introspection.
async function mcpInitialize(fetchImpl, url, { timeoutMs = 8000 } = {}) {
  let u; try { u = new URL(url); } catch { return { ok: false, status: 0, error: "bad url" }; }
  if (u.protocol !== "https:" || isBadHost(u.hostname)) return { ok: false, status: 0, error: "blocked" };
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "NessGate-Readiness", version: "0.1" } } });
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: "POST", redirect: "follow", signal: ac.signal, headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body });
    const text = await readCapped(res, 65536);
    return { ok: res.status === 200, status: res.status, wwwAuthenticate: res.headers.get("www-authenticate") || null, protocolVersion: extractProtocolVersion(text) };
  } catch (e) {
    return { ok: false, status: 0, error: String(e && e.message || e) };
  } finally { clearTimeout(t); }
}

/* ----------------------- pure readiness assessors ------------------------- */
// Each takes ALREADY-FETCHED documents and returns a verdict. Pure → unit-tested
// offline with captured fixtures, independent of any live service.

// MCP: init handshake + optional OAuth metadata chain (RFC 9728 → RFC 8414).
export function assessMcp({ init, prm, as }) {
  const transport = init && init.status === 405 ? "sse-legacy" : "streamable-http";
  const version = (init && init.protocolVersion) || null;
  const base = { protocol: "mcp", transport, version };
  if (init && init.ok) {
    // Reached the server and it did NOT demand auth → genuinely ready (public MCP).
    return { ...base, outcome: "ready", auth: { required: false }, verified: { handshake: "ok", protocolVersion: version }, missing: [] };
  }
  // A bare 403 is NOT proof of OAuth — it is just as often bot/WAF protection.
  // Only a 401, or a 403 that carries WWW-Authenticate, is a real auth wall.
  // (Mirrors the resolver's own denial honesty: bare 403 = undetermined.)
  const authWall = init && (init.status === 401 || (init.status === 403 && init.wwwAuthenticate));
  if (authWall) {
    if (as && as.authorization_endpoint && as.token_endpoint) {
      return {
        ...base,
        outcome: "credentials-required",
        auth: {
          required: true, type: "oauth2",
          authorizationServer: as.issuer || as._source,
          authorizationEndpoint: as.authorization_endpoint,
          tokenEndpoint: as.token_endpoint,
          scopes: Array.isArray(as.scopes_supported) ? as.scopes_supported : undefined,
          grantTypes: Array.isArray(as.grant_types_supported) ? as.grant_types_supported : undefined,
          dynamicClientRegistration: !!as.registration_endpoint,
          registrationEndpoint: as.registration_endpoint || undefined,
        },
        verified: { handshake: "auth-required", protocolVersion: version },
        missing: [],
      };
    }
    // Auth is required but the metadata needed to set it up is not published.
    const missing = !prm
      ? ["OAuth 2.0 Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource"]
      : ["Authorization Server Metadata (RFC 8414) — the protected-resource doc names no reachable authorization server"];
    return { ...base, outcome: "incomplete", auth: { required: true, type: "oauth2" }, verified: { handshake: "auth-required" }, missing };
  }
  // A bare 403 with no auth challenge: authorization OR bot/WAF — undetermined.
  if (init && init.status === 403) {
    return { ...base, outcome: "incomplete", verified: { handshake: "denied:403" }, missing: ["undetermined: endpoint returned 403 with no auth challenge (authorization OR bot/WAF protection — a safe probe cannot distinguish them)"] };
  }
  // Unreachable / unexpected — cannot confirm a connection.
  return { ...base, outcome: "incomplete", verified: { handshake: init && init.status ? "error:" + init.status : "unreachable" }, missing: ["a reachable MCP endpoint (initialize handshake did not succeed)"] };
}

// OpenAPI: the spec declares its own servers + security schemes (with flows).
export function assessOpenApi({ spec }) {
  const out = { protocol: "openapi", transport: "https", version: null, missing: [] };
  if (!spec || typeof spec !== "object") return { ...out, outcome: "incomplete", missing: ["a parseable OpenAPI document"] };
  out.version = typeof spec.openapi === "string" ? spec.openapi : typeof spec.swagger === "string" ? spec.swagger : null;
  const servers = Array.isArray(spec.servers) ? spec.servers.map((s) => s && s.url).filter(Boolean) : [];
  const schemes = (spec.components && spec.components.securitySchemes) || spec.securityDefinitions || null;
  const missing = [];
  if (!servers.length) missing.push("servers[] (no base URL is declared)");
  if (!schemes || !Object.keys(schemes).length) missing.push("securitySchemes (no auth method is declared)");
  if (!out.version) missing.push("openapi/swagger version string");
  out.endpoint = servers[0] || undefined;
  if (missing.length) return { ...out, outcome: "incomplete", missing };
  // Fully declared → the client supplies its own credential per the scheme.
  const first = Object.entries(schemes)[0][1] || {};
  const type = first.type; const flows = first.flows;
  const auth = { required: true, type };
  if (type === "http" && first.scheme) auth.type = "http:" + String(first.scheme).toLowerCase();
  if (type === "oauth2" && flows) {
    const f = flows.authorizationCode || flows.clientCredentials || flows.password || flows.implicit || {};
    auth.authorizationEndpoint = f.authorizationUrl;
    auth.tokenEndpoint = f.tokenUrl;
    auth.scopes = f.scopes ? Object.keys(f.scopes) : undefined;
  }
  return { ...out, outcome: "credentials-required", auth, verified: { handshake: "not-attempted" } };
}

// A2A: the agent card declares transport(s), version, and (optionally) security.
// Supports BOTH the current schema (protocolVersion, preferredTransport, url,
// additionalInterfaces[]) and the older one (version, supportedInterfaces[]).
export function assessA2a({ card }) {
  const out = { protocol: "a2a-agent-card", missing: [] };
  if (!card || typeof card !== "object") return { ...out, outcome: "incomplete", missing: ["a parseable A2A agent card"] };
  const ifaces = [
    ...(Array.isArray(card.additionalInterfaces) ? card.additionalInterfaces : []),
    ...(Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : []),
  ].filter((i) => i && typeof i === "object");
  let transport = null, endpoint = typeof card.url === "string" ? card.url : undefined;
  if (typeof card.preferredTransport === "string") transport = card.preferredTransport.toLowerCase();
  else if (ifaces.length && ifaces[0].transport) { transport = String(ifaces[0].transport).toLowerCase(); endpoint = ifaces[0].url || endpoint; }
  // A2A spec default: when only `url` is given (and it is a real endpoint, not the
  // card file itself), the transport is JSON-RPC.
  else if (typeof card.url === "string" && !/\.json(\?|$)/i.test(card.url)) transport = "jsonrpc";
  out.transport = transport; out.endpoint = endpoint;
  out.version = typeof card.protocolVersion === "string" ? card.protocolVersion : typeof card.version === "string" ? card.version : null;

  const schemes = card.securitySchemes && typeof card.securitySchemes === "object" ? card.securitySchemes : null;
  const requiredList = Array.isArray(card.security) && card.security.length ? card.security : null;
  const missing = [];
  if (!out.transport) missing.push("a transport (no preferredTransport, interfaces, or usable url)");
  if (!out.version) missing.push("protocolVersion (no version is declared)");
  if (missing.length) return { ...out, outcome: "incomplete", missing };
  if (!schemes && !requiredList) {
    // A2A treats absent security as "no auth" → connectable as-is.
    return { ...out, outcome: "ready", auth: { required: false }, verified: { handshake: "not-attempted" } };
  }
  const first = schemes ? Object.values(schemes)[0] || {} : {};
  return { ...out, outcome: "credentials-required", auth: { required: true, type: first.type || "declared" }, verified: { handshake: "not-attempted" } };
}

/* --------------------- fill connection details (IO) ----------------------- */
// Given one compatibility plan, do the SAFE read-only fetches its protocol needs,
// then call the matching pure assessor.

async function fillMcp(plan, fetchImpl, opts) {
  // The declared URL is often the MCP server CARD (a JSON doc), not the endpoint
  // you POST to. If so, READ the endpoint the card itself names (not a guess —
  // the publisher's own declared field) and handshake THAT.
  let endpoint = plan.endpoint;
  let cardDeref = false;
  if (/\.json(\?|$)/i.test(endpoint) || /server-card|agent-card|\/\.well-known\//i.test(endpoint)) {
    try {
      const card = await getJson(fetchImpl, endpoint, opts);
      const inner = card && card.json && (card.json.url || card.json.endpoint || card.json.serverUrl || card.json.mcpUrl || (card.json.server && card.json.server.url));
      if (typeof inner === "string" && /^https:\/\//i.test(inner) && inner !== endpoint) { endpoint = inner; cardDeref = true; }
    } catch {}
  }
  const init = await mcpInitialize(fetchImpl, endpoint, opts);
  let prm = null, as = null;
  if (init.status === 401 || init.status === 403) {
    // 1) resource_metadata pointer from WWW-Authenticate, else the well-known path.
    let prmUrl = null;
    const m = init.wwwAuthenticate && init.wwwAuthenticate.match(/resource_metadata="?([^",\s]+)"?/i);
    if (m) prmUrl = m[1];
    else { try { prmUrl = new URL("/.well-known/oauth-protected-resource", endpoint).toString(); } catch {} }
    if (prmUrl) { const r = await getJson(fetchImpl, prmUrl, opts).catch(() => null); if (r && r.json) prm = r.json; }
    // 2) authorization server metadata (RFC 8414 / OIDC).
    const asBase = prm && Array.isArray(prm.authorization_servers) && prm.authorization_servers[0];
    if (asBase) {
      for (const path of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
        try {
          const r = await getJson(fetchImpl, new URL(path, asBase).toString(), opts);
          if (r && r.json && r.json.token_endpoint) { as = { ...r.json, _source: asBase }; break; }
        } catch {}
      }
    }
  }
  return { ...assessMcp({ init, prm, as }), endpoint, cardDereferenced: cardDeref };
}

async function fillOpenApi(plan, fetchImpl, opts) {
  try { const r = await getJson(fetchImpl, plan.endpoint, { ...opts, maxBytes: 1_000_000 }); return assessOpenApi({ spec: r.json }); }
  catch (e) { return assessOpenApi({ spec: null }); }
}

async function fillA2a(plan, fetchImpl, opts) {
  // Re-fetch the card at its source to read securitySchemes (the resolver does not
  // currently surface them). Read-only.
  try { const r = await getJson(fetchImpl, plan.sourceUrl, opts); return assessA2a({ card: r.json }); }
  catch { return assessA2a({ card: null }); }
}

async function fillAndAssess(plan, fetchImpl, opts) {
  let a;
  if (plan.protocol === "mcp") a = await fillMcp(plan, fetchImpl, opts);
  else if (plan.protocol === "openapi") a = await fillOpenApi(plan, fetchImpl, opts);
  else if (plan.protocol === "a2a-agent-card") a = await fillA2a(plan, fetchImpl, opts);
  else a = { protocol: plan.protocol, outcome: "incomplete", missing: [`no readiness resolver implemented for "${plan.protocol}" yet`], transport: plan.transport, version: plan.version };
  // Carry the compatibility plan's provenance/evidence onto the readiness record.
  return { ...a, endpoint: a.endpoint || plan.endpoint, evidence: plan.evidence, sourceUrl: plan.sourceUrl, provenance: plan.provenance };
}

/* ----------------------------- the pipeline ------------------------------- */

const OUTCOME_RANK = { ready: 0, "credentials-required": 1, incomplete: 2, "no-compatible-method": 3 };

// discovery: a resolve()/explore() answer.  clientCaps: the client profile.
// opts.fetch: the fetch to use for the fill/verify hops (defaults to global).
export async function assessReadiness(discovery, clientCaps, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const plan = buildConnectionPlan(discovery, clientCaps);

  // No compatible connectable protocol at all → the terminal outcome.
  if (plan.connectionPlans.length === 0) {
    const outcome = plan.match.outcome === "none-found" ? "incomplete"
      : plan.match.outcome === "pointers-only" ? "incomplete"
      : "no-compatible-method";
    const missing = plan.match.outcome === "pointers-only"
      ? ["a connectable endpoint — the domain publishes only pointer/catalog surfaces; follow them (delegation) to reach one"]
      : plan.match.outcome === "none-found" ? ["any machine-readable service surface"] : [];
    return { domain: discovery.domain, outcome, connection: null, alternatives: [], missing, compatibility: plan.match, leads: plan.leads, notes: plan.notes };
  }

  // Fill + verify every compatible plan (bounded — MAX_ASSESS).
  const MAX_ASSESS = opts.maxAssess || 4;
  const assessed = [];
  for (const p of plan.connectionPlans.slice(0, MAX_ASSESS)) assessed.push(await fillAndAssess(p, fetchImpl, opts));
  // Best outcome first (ready > credentials-required > incomplete), stable within.
  assessed.sort((a, b) => OUTCOME_RANK[a.outcome] - OUTCOME_RANK[b.outcome]);

  const best = assessed[0];
  return {
    domain: discovery.domain,
    outcome: best.outcome,
    connection: best,               // the recommended connection (or best incomplete)
    alternatives: assessed.slice(1),
    missing: best.missing || [],
    compatibility: plan.match,
    selectedByClientPreference: plan.selectedPlan ? plan.selectedPlan.protocol : null,
    leads: plan.leads,
    notes: plan.notes,
  };
}

export { buildConnectionPlan };
