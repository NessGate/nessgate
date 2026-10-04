// BASELINE ("without NessGate"): the discovery/compatibility glue a competent
// developer writes by reading each specification once. This is deliberately a
// FAIR first implementation, not a strawman — it handles the mainstream paths
// correctly (well-known probing, OpenAPI servers+securitySchemes, the A2A card
// fields as documented in the 0.3.x era, the MCP initialize handshake INCLUDING
// the RFC 9728 → RFC 8414 OAuth metadata chain, registry lookup). Where it
// diverges from NessGate on edge cases, each divergence is the NATURAL first
// reading of the spec — and each corresponds to a real bug class this project
// itself hit and later fixture-pinned (see run-validation.mjs TRAPS).
//
// Rules a first implementation naturally adopts (annotated for the comparison):
//  [N1] an MCP endpoint that answers HTTP 200 to initialize is working
//  [N2] a 200 body that fails JSON.parse at a declared location is broken
//  [N3] a 403 on an MCP endpoint means authentication is required (OAuth wall)
//  [N4] the first active registry entry for a server name is the server
//  [N5] A2A cards use url/preferredTransport/protocolVersion (the 0.3.x shape)
//  [N6] MCP speaks initialize (the handshake every tutorial shows)
//  [N7] a Signature-Agent value is a URL you fetch for keys (kid or thumbprint)
//  [N8] a URL whose path contains /mcp is an MCP endpoint candidate

import { createPublicKey, verify as edVerify, createHash } from "node:crypto";

const J = (t) => { try { return JSON.parse(t); } catch { return null; } };
const get = async (fetchImpl, url, cap = 262144) => {
  try {
    const r = await fetchImpl(url, { headers: { accept: "application/json" } });
    const text = (await r.text()).slice(0, cap); // [N2 precondition: silent cap]
    return { status: r.status, text };
  } catch { return { status: 0, text: "" }; }
};

/* ---------------- discovery ---------------- */
export async function discover(fetchImpl, domain) {
  const found = [];
  const ard = await get(fetchImpl, `https://${domain}/.well-known/ard.json`);
  if (ard.status === 200) {
    const doc = J(ard.text);
    for (const e of (doc && doc.entries) || []) if (e && e.url) found.push({ kind: kindOf(e.url, e.type), url: e.url });
  }
  for (const [path, kind] of [["/.well-known/agent-card.json", "a2a"], ["/.well-known/agent.json", "a2a"], ["/openapi.json", "openapi"]]) {
    const r = await get(fetchImpl, `https://${domain}${path}`);
    if (r.status === 200 && J(r.text)) found.push({ kind, url: `https://${domain}${path}` });
  }
  const llms = await get(fetchImpl, `https://${domain}/llms.txt`);
  if (llms.status === 200) {
    for (const m of llms.text.matchAll(/https?:\/\/[^\s)"']+/g)) {
      const u = m[0].replace(/[.,;]+$/, "");
      const k = kindOf(u);                                   // [N8]
      if (k) found.push({ kind: k, url: u });
    }
  }
  const seen = new Set();
  return found.filter((f) => !seen.has(f.url) && seen.add(f.url));
}
function kindOf(url, typeHint = "") {
  const t = String(typeHint).toLowerCase();
  if (t.includes("mcp")) return "mcp";
  if (t.includes("openapi")) return "openapi";
  let p = ""; try { p = new URL(url).pathname.toLowerCase(); } catch { return null; }
  if (/\/mcp(\/|$)?/.test(p) || /^mcp\./.test(new URL(url).hostname)) return "mcp"; // [N8]
  if (/openapi.*\.json|\/openapi(\/|$)/.test(p)) return "openapi";
  if (/agent(-card)?\.json/.test(p)) return "a2a";
  return null;
}

/* ---------------- registry lookup ---------------- */
export async function registryLookup(fetchImpl, domain) {
  const ns = domain.toLowerCase().split(".").reverse().join(".");
  const r = await get(fetchImpl, `https://registry.modelcontextprotocol.io/v0.1/servers?search=${encodeURIComponent(ns)}&limit=50`);
  const doc = J(r.text);
  for (const e of (doc && doc.servers) || []) {                // [N4] first match wins
    const s = e.server || e;
    const meta = e._meta && e._meta["io.modelcontextprotocol.registry/official"];
    if (!s || !String(s.name || "").startsWith(ns + "/")) continue;
    if (meta && meta.status && meta.status !== "active") continue;
    const remote = (s.remotes || []).find((x) => x && x.url);
    if (remote) return { name: s.name, url: remote.url, version: s.version };
  }
  return null;
}

/* ---------------- readiness / auth resolution ---------------- */
export async function checkOpenApi(fetchImpl, url) {
  const r = await get(fetchImpl, url);
  if (r.status !== 200) return { protocol: "openapi", usable: false, state: r.status === 404 ? "broken" : "unreachable" };
  const spec = J(r.text);
  if (!spec) return { protocol: "openapi", usable: false, state: "broken" };   // [N2]
  const server = Array.isArray(spec.servers) && spec.servers[0] && spec.servers[0].url;
  const schemes = (spec.components && spec.components.securitySchemes) || spec.securityDefinitions || null;
  if (!server) return { protocol: "openapi", usable: false, state: "incomplete" };
  if (!schemes) return { protocol: "openapi", usable: true, state: "open", endpoint: server }; // assume open when none declared
  const first = Object.values(schemes)[0] || {};
  return { protocol: "openapi", usable: true, state: "needs-credentials", endpoint: server, auth: first.type === "http" ? "http:" + first.scheme : first.type };
}

export async function checkA2a(fetchImpl, url) {
  const r = await get(fetchImpl, url);
  const card = r.status === 200 ? J(r.text) : null;
  if (!card) return { protocol: "a2a", usable: false, state: r.status === 200 ? "broken" : "unreachable" };
  const transport = typeof card.preferredTransport === "string" ? card.preferredTransport.toLowerCase() : null; // [N5]
  const endpoint = typeof card.url === "string" ? card.url : null;
  const version = typeof card.protocolVersion === "string" ? card.protocolVersion : null;
  if (!transport || !version || !endpoint) return { protocol: "a2a", usable: false, state: "incomplete" };
  const auth = card.securitySchemes ? Object.values(card.securitySchemes)[0] : null;
  return auth ? { protocol: "a2a", usable: true, state: "needs-credentials", endpoint, transport, version, auth: auth.type }
              : { protocol: "a2a", usable: true, state: "open", endpoint, transport, version };
}

export async function checkMcp(fetchImpl, url) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "glue", version: "1" } } }); // [N6]
  let res;
  try { res = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body }); }
  catch { return { protocol: "mcp", usable: false, state: "unreachable" }; }
  if (res.status === 200) return { protocol: "mcp", usable: true, state: "open", endpoint: url }; // [N1]
  if (res.status === 401 || res.status === 403) {                                                  // [N3]
    const www = res.headers && res.headers.get ? res.headers.get("www-authenticate") : null;
    const m = www && www.match(/resource_metadata="?([^",\s]+)"?/i);
    const prmUrl = m ? m[1] : new URL("/.well-known/oauth-protected-resource", url).toString();
    const prm = J((await get(fetchImpl, prmUrl)).text);
    const asBase = prm && Array.isArray(prm.authorization_servers) && prm.authorization_servers[0];
    if (asBase) for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
      const as = J((await get(fetchImpl, new URL(p, asBase).toString())).text);
      if (as && as.token_endpoint) return { protocol: "mcp", usable: true, state: "needs-credentials", endpoint: url, auth: "oauth2", tokenEndpoint: as.token_endpoint, authorizationEndpoint: as.authorization_endpoint };
    }
    return { protocol: "mcp", usable: true, state: "needs-credentials", endpoint: url, auth: "oauth2" }; // [N3]
  }
  if (res.status === 404 || res.status === 410 || res.status >= 500) return { protocol: "mcp", usable: false, state: "broken" };
  return { protocol: "mcp", usable: false, state: "error:" + res.status };
}

export async function check(fetchImpl, item) {
  if (item.kind === "openapi") return checkOpenApi(fetchImpl, item.url);
  if (item.kind === "a2a") return checkA2a(fetchImpl, item.url);
  if (item.kind === "mcp") return checkMcp(fetchImpl, item.url);
  return { protocol: item.kind, usable: false, state: "unsupported" };
}

/* ---------------- inbound agent identity (Web Bot Auth) ---------------- */
export async function verifyInbound(fetchImpl, request) {                      // [N7]
  const h = request.headers || {};
  const hget = (n) => { for (const k in h) if (k.toLowerCase() === n) return h[k]; };
  const si = hget("signature-input"), sg = hget("signature"), sa = hget("signature-agent");
  if (!si || !sg) return { present: false };
  const eq = si.indexOf("=");
  const label = si.slice(0, eq);
  const rawInner = si.slice(eq + 1);
  const comps = (rawInner.match(/^\(([^)]*)\)/) || [, ""])[1].match(/"([^"]*)"/g)?.map((s) => s.slice(1, -1)) || [];
  const keyid = (rawInner.match(/keyid="([^"]*)"/) || [])[1];
  const sigB64 = (sg.match(new RegExp(label + "=:(.*?):")) || [])[1];
  if (!keyid || !sigB64) return { present: true, verified: false };
  let dir = String(sa || "").trim().replace(/^"|"$/g, "");
  if (/^[a-z]\w*=/i.test(dir)) dir = (dir.match(/"([^"]*)"/) || [])[1] || "";   // dict? take first member
  if (!/^https:\/\//.test(dir)) dir = "https://" + dir;
  if (!/\.well-known/.test(dir)) dir = dir.replace(/\/?$/, "") + "/.well-known/http-message-signatures-directory";
  const jwks = J((await get(fetchImpl, dir)).text);                            // follows redirects; no origin rule
  const u = new URL(request.url);
  const lines = comps.map((c) => {
    if (c === "@method") return `"@method": ${request.method.toUpperCase()}`;
    if (c === "@authority") return `"@authority": ${u.host.toLowerCase()}`;
    return `"${c}": ${String(hget(c) || "").trim()}`;
  });
  lines.push(`"@signature-params": ${rawInner.trim()}`);
  const base = lines.join("\n");
  for (const k of (jwks && jwks.keys) || []) {
    if (k.kty !== "OKP" || k.crv !== "Ed25519") continue;
    const tp = createHash("sha256").update(`{"crv":"${k.crv}","kty":"${k.kty}","x":"${k.x}"}`).digest("base64url");
    if (k.kid !== keyid && tp !== keyid) continue;                             // kid OR thumbprint
    try {
      const ok = edVerify(null, Buffer.from(base, "utf8"), createPublicKey({ key: k, format: "jwk" }), Buffer.from(sigB64, "base64"));
      if (ok) return { present: true, verified: true, keyid };
    } catch {}
  }
  return { present: true, verified: false };
}
