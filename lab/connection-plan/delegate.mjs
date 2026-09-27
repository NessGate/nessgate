// NessGate — bounded DELEGATION for the readiness prototype (lab-only).
//
// Many domains publish only POINTER/catalog surfaces (api-catalog, llms.txt) that
// NAME the real endpoints instead of being one. This follows those pointers ONE
// level — deterministically, read-only, publisher-declared targets only — and
// appends the endpoints they name to the discovery result so the readiness
// pipeline can assess them. This is the local, library-side counterpart of the
// hosted /explore delegation.
//
// SAFE + BOUNDED: depth 1 only (no recursion), https-only + host-guarded fetches
// (via safeGet), a hard per-domain cap, and it follows ONLY machine-readable
// links the publisher itself declared (RFC 9727 service-desc; strict machine-spec
// URLs in llms.txt). Human doc/status/marketing links are ignored. Every added
// record is tagged evidence "publisher-declared" with a provenance hop.

import { safeGet } from "./readiness.mjs";

const MAX_DELEGATED = 8; // hard cap on endpoints added per domain

// Pure: pull OpenAPI service descriptions out of an RFC 9727 api-catalog linkset.
// service-desc = the machine API description; service-doc/status/etc. are human
// pages and are deliberately skipped.
export function endpointsFromApiCatalog(json, catalogUrl) {
  if (!json || !Array.isArray(json.linkset)) return [];
  const out = [];
  for (const entry of json.linkset) {
    const descs = Array.isArray(entry && entry["service-desc"]) ? entry["service-desc"] : [];
    for (const d of descs) {
      const href = d && typeof d.href === "string" ? d.href : null;
      if (href && /^https:\/\//i.test(href)) out.push({ source: "openapi", type: "openapi", url: href, sourceUrl: catalogUrl, via: "api-catalog" });
    }
  }
  return out;
}

// Pure: extract ONLY machine-spec links from an llms.txt (markdown). Human doc
// links (the overwhelming majority) are ignored — llms.txt is mostly a docs index.
const SPEC_PATTERNS = [
  { re: /openapi(\.json|\.ya?ml)?(\?|#|$)/i, proto: "openapi" },
  { re: /swagger(\.json)?(\?|#|$)/i, proto: "openapi" },
  { re: /\/\.well-known\/(agent-card|agent)\.json/i, proto: "a2a-agent-card" },
  { re: /(agent-card|agent)\.json(\?|#|$)/i, proto: "a2a-agent-card" },
  { re: /(\/mcp\b|server-card)/i, proto: "mcp" },
];
// A URL ending in a document extension is a docs page (e.g. /docs/mcp.md), not a
// machine endpoint — never treat it as one, even if the path contains "mcp".
const DOC_EXT = /\.(md|mdx|html?|txt|pdf|rst)(\?|#|$)/i;
export function endpointsFromLlmsTxt(text, sourceUrl) {
  if (typeof text !== "string") return [];
  const urls = new Set();
  // Markdown links [text](url) and bare https URLs.
  for (const m of text.matchAll(/\]\((https:\/\/[^)\s]+)\)/gi)) urls.add(m[1]);
  for (const m of text.matchAll(/(?:^|\s)(https:\/\/[^\s)]+)/gi)) urls.add(m[1]);
  const out = [];
  for (const raw of urls) {
    const url = raw.replace(/[.,]$/, "");
    if (DOC_EXT.test(url)) continue; // documentation page, not an endpoint
    const hit = SPEC_PATTERNS.find((p) => p.re.test(url));
    if (hit) out.push({ source: hit.proto, type: hit.proto, url, sourceUrl, via: "llms.txt" });
  }
  return out;
}

// IO: given a discovery result, follow its pointer surfaces one level and return a
// NEW discovery with the named endpoints appended (deduped, capped, provenanced).
export async function expandByDelegation(discovery, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  const discovered = Array.isArray(discovery.discovered) ? discovery.discovered : [];
  const found = [];
  const followed = [];

  for (const d of discovered) {
    if (found.length >= MAX_DELEGATED) break;
    try {
      if (d.type === "api-catalog") {
        const r = await safeGet(fetchImpl, d.url, opts);
        let json = null; try { json = JSON.parse(r.text); } catch {}
        found.push(...endpointsFromApiCatalog(json, d.url));
        followed.push({ via: "api-catalog", url: d.url });
      } else if (d.type === "llms.txt") {
        const r = await safeGet(fetchImpl, d.url, opts);
        found.push(...endpointsFromLlmsTxt(r.text, d.url));
        followed.push({ via: "llms.txt", url: d.url });
      }
    } catch { /* pointer unreachable — absence, not invention */ }
  }

  // Dedupe against what discovery already had, and against itself; cap; tag.
  const existing = new Set((discovery.resources || []).map((r) => r.url));
  const seen = new Set();
  const added = [];
  for (const e of found) {
    if (added.length >= MAX_DELEGATED) break;
    if (existing.has(e.url) || seen.has(e.url)) continue;
    seen.add(e.url);
    added.push({
      source: e.source, type: e.type, url: e.url, sourceUrl: e.sourceUrl,
      class: "publisher-declared", // the publisher's own catalog named this target
      provenance: [{ via: e.via, from: e.sourceUrl }, { resource: e.url }],
    });
  }

  return {
    delegated: added.length,
    followed,
    discovery: added.length
      ? { ...discovery, resources: [...(discovery.resources || []), ...added], discovered: [...discovered, ...added.map((a) => ({ type: a.type, url: a.url, via: "delegation" }))] }
      : discovery,
  };
}
