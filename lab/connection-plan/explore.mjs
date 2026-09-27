// NessGate — /explore adapter for the readiness pipeline (lab-only).
//
// Feeds the HOSTED /explore endpoint (deeper delegation: declared pointers to
// depth 2, org/related hosts, and official MCP-Registry federation) into the same
// readiness pipeline, and normalizes its output into the discovery shape the
// pipeline expects.
//
// NOTE ON DEPENDENCY: this runner path calls https://nessgate.com/explore as a
// DATA SOURCE for the experiment — it deliberately trades the "no runtime
// dependency on nessgate.com" property for /explore's richer recall, purely to
// MEASURE the ceiling. The local resolve()+delegate.mjs path stays dependency-free.
//
// /explore differs from resolve(): it uses `evidence`/`relationship` (not `class`),
// labels protocols by media-type (application/openapi+json, mcp-server) rather than
// by our `source`, nests federated hits under related[].resources[], and does not
// carry inline security/raw/introspection. That is fine — the readiness layer
// re-fetches those per protocol; /explore's job here is to widen recall.

import { safeGet } from "./readiness.mjs";

const OPENAPI_RE = /openapi|swagger/i;

// Map an /explore resource (source+type+url) to a connectable protocol, or null
// if it is a pointer/human link. Uses the media-type and URL shape /explore emits.
export function deriveProtocol(source, type, url) {
  const t = String(type || "").toLowerCase();
  let path = "", host = "";
  try { const u = new URL(url); path = u.pathname.toLowerCase(); host = u.hostname.toLowerCase(); } catch {}
  if (t.includes("openapi") || OPENAPI_RE.test(path)) return "openapi";
  if (t.includes("mcp") || /(^|\/)mcp(\b|\/|$)/.test(path) || host.startsWith("mcp.")) return "mcp";
  if (t.includes("agent-card") || /agent-card\.json|\/\.well-known\/agent\.json|\/agent\.json$/.test(path)) return "a2a-agent-card";
  if (source === "ucp" || t.includes("ucp")) return "ucp";
  if (source === "aid") return "aid";
  return null; // llms.txt, human docs, status pages, etc. → pointer/lead
}

// Pure: /explore JSON → discovery-shaped { domain, resources[], discovered[] }.
export function normalizeExplore(j) {
  const flat = [...((j && j.resources) || [])];
  for (const grp of (j && j.related) || []) if (grp && Array.isArray(grp.resources)) flat.push(...grp.resources);
  const out = [];
  const seen = new Set();
  for (const r of flat) {
    if (!r || typeof r.url !== "string") continue;
    // The OAuth protected-resource doc is METADATA, not an endpoint — the MCP
    // readiness resolver fetches it itself. Never handshake it as if it were one.
    if (/\/\.well-known\/oauth-protected-resource/i.test(r.url)) continue;
    if (seen.has(r.url)) continue; seen.add(r.url);
    const proto = deriveProtocol(r.source, r.type, r.url);
    const cls = r.evidence || r.relationship || r.class;
    const base = { url: r.url, sourceUrl: r.sourceUrl || r.url, class: cls, provenance: r.provenance, raw: r.raw };
    if (proto === "openapi") out.push({ ...base, source: "openapi", type: "openapi" });
    else if (proto === "mcp") out.push({ ...base, source: "mcp", type: "mcp" }); // type "mcp" → mcp readiness path
    else if (proto === "a2a-agent-card") out.push({ ...base, source: "a2a-agent-card", type: "a2a-agent-card" });
    else if (proto) out.push({ ...base, source: proto, type: proto });
    else out.push({ ...base, source: r.source, type: r.type }); // pointer/other → becomes a lead
  }
  return { domain: j && j.domain, outcome: j && j.outcome, resources: out, discovered: out.map((r) => ({ type: r.type, url: r.url })) };
}

// IO: GET the hosted /explore and normalize it.
export async function fetchExplore(domain, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const base = opts.base || "https://nessgate.com";
  const url = `${base}/explore/${encodeURIComponent(domain)}?org=1&related=1`;
  const r = await safeGet(fetchImpl, url, { timeoutMs: opts.timeoutMs || 30000, maxBytes: 3_000_000 });
  let j; try { j = JSON.parse(r.text); } catch { throw new Error("explore returned non-JSON (status " + r.status + ")"); }
  return normalizeExplore(j);
}
