// NessGate resolver — embeddable, dependency-free, decentralized.
//
// Give it a domain; it reads the standard machine-discovery files the domain
// ITSELF publishes and returns one normalized list of that domain's official
// machine-readable resources. There is NO runtime dependency on nessgate.com:
// this code fetches the target domain directly. Bring your own `fetch`
// (defaults to the global one), so it runs in browsers, Node, Deno, Workers,
// and agent runtimes.
//
// It reads (never defines) these standards and reuses each one's OWN labels —
// NessGate invents no taxonomy: llms.txt, ARD / ai-catalog.json, A2A agent
// card, RFC 9727 api-catalog, ai-info.json, OpenAPI, Open Resource Discovery,
// an /.well-known/awp.json manifest, and RFC 6415 host-meta.
//
// The normalization below is identical to the NessGate reference resolver
// (src/worker.js); a parity test in the test suite keeps them from drifting.
//
// SSRF WARNING: this library fetches the domain you pass in and follows normal
// redirects. In browsers the network sandbox applies, but in Node/server
// environments a caller that passes an UNTRUSTED domain MUST validate it first
// (reject private/reserved addresses, keep redirects on-host). The hosted
// resolver at https://nessgate.com/discover/{domain} performs these checks.

export const PROBES = [
  { type: "llms.txt", paths: ["/llms.txt"], kind: "text" },
  { type: "ard-catalog", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" },
  { type: "a2a-agent-card", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" },
  { type: "api-catalog", paths: ["/.well-known/api-catalog"], kind: "json" },
  { type: "ai-info.json", paths: ["/ai-info.json"], kind: "json" },
  { type: "openapi", paths: ["/openapi.json"], kind: "json" },
  { type: "ord", paths: ["/.well-known/open-resource-discovery"], kind: "json" },
  { type: "awp", paths: ["/.well-known/awp.json"], kind: "json" },
  { type: "host-meta", paths: ["/.well-known/host-meta.json"], kind: "json" },
];

const MAX_DISCOVER_RESOURCES = 200;
const MAX_PER_SOURCE = 50;

// Reject catch-all rewrites: SPA hosts return 200 + their HTML shell for every
// path. (Identical to the reference resolver.)
export function validateProbeContent(kind, text) {
  if (typeof text !== "string" || text.trim() === "") return false;
  if (kind === "json") {
    try {
      const obj = JSON.parse(text);
      return !!obj && typeof obj === "object";
    } catch {
      return false;
    }
  }
  const head = text.trimStart().slice(0, 15).toLowerCase();
  return !head.startsWith("<!doctype") && !head.startsWith("<html");
}

// Confirm the document looks like the standard we probed for, so a JSON
// catch-all ({} for every unknown path) is not a false positive. IDENTICAL to
// src/worker.js (kept in sync by a parity test).
export function probeShapeOk(type, kind, text) {
  if (kind !== "json") return true;
  let obj;
  try { obj = JSON.parse(text); } catch { return false; }
  if (!obj || typeof obj !== "object") return false;
  switch (type) {
    case "ard-catalog": return Array.isArray(obj.entries);
    case "a2a-agent-card": return typeof obj.name === "string" || Array.isArray(obj.supportedInterfaces) || typeof obj.url === "string";
    case "api-catalog": return Array.isArray(obj.linkset);
    case "awp": return obj.protocols !== undefined;
    case "host-meta": return Array.isArray(obj.links);
    case "openapi": return typeof obj.openapi === "string" || typeof obj.swagger === "string";
    default: return true;
  }
}

// Normalize one fetched standard document into a flat list of resource records.
// Thin by design; reuses each source's own labels; never throws. IDENTICAL to
// src/worker.js normalizeResources (kept in sync by a parity test).
export function normalizeResources(type, kind, text, sourceUrl) {
  try {
    const rec = (r) => ({ source: type, sourceUrl, ...r });
    if (kind !== "json") {
      return [rec({ type, url: sourceUrl })];
    }
    let obj;
    try {
      obj = JSON.parse(text);
    } catch {
      return [];
    }
    const str = (v) => (typeof v === "string" ? v : undefined);
    const cap = (arr) => arr.filter(Boolean).slice(0, MAX_PER_SOURCE);

    switch (type) {
      case "ard-catalog": {
        const entries = Array.isArray(obj.entries) ? obj.entries : [];
        return cap(
          entries.map((e) => {
            if (!e || typeof e !== "object") return null;
            const u = str(e.url);
            if (u) return rec({ type: str(e.type) || "ard-entry", name: str(e.displayName), url: u, id: str(e.identifier), raw: e });
            if (e.data !== undefined) return rec({ type: str(e.type) || "ard-entry", name: str(e.displayName), url: sourceUrl, id: str(e.identifier), inline: true, raw: e });
            return null;
          })
        );
      }
      case "host-meta": {
        const links = Array.isArray(obj.links) ? obj.links : [];
        return cap(
          links.map((l) =>
            l && str(l.href) ? rec({ type: str(l.type) || str(l.rel) || "link", rel: str(l.rel), url: l.href, raw: l }) : null
          )
        );
      }
      case "api-catalog": {
        const contexts = Array.isArray(obj.linkset) ? obj.linkset : [];
        const out = [];
        for (const ctx of contexts) {
          if (!ctx || typeof ctx !== "object") continue;
          for (const [rel, val] of Object.entries(ctx)) {
            if (!Array.isArray(val)) continue;
            for (const link of val) {
              if (link && str(link.href)) out.push(rec({ type: str(link.type) || rel, rel, url: link.href, raw: link }));
            }
          }
        }
        return cap(out);
      }
      case "awp": {
        const p = obj.protocols;
        const out = [];
        if (Array.isArray(p)) {
          for (const it of p) {
            const url = it && (str(it.url) || str(it.href) || str(it.endpoint));
            if (url) out.push(rec({ type: str(it.type) || str(it.protocol) || "awp-protocol", url, raw: it }));
          }
        } else if (p && typeof p === "object") {
          for (const [k, v] of Object.entries(p)) {
            const url = str(v) || (v && (str(v.url) || str(v.href) || str(v.endpoint)));
            if (url) out.push(rec({ type: k, url, raw: v }));
          }
        }
        return cap(out);
      }
      case "a2a-agent-card": {
        // A2A v1.0 moved endpoints from a top-level `url` into supportedInterfaces[].
        const ifaces = Array.isArray(obj.supportedInterfaces) ? obj.supportedInterfaces : [];
        const ifaceUrl = ifaces.map((i) => (i ? str(i.url) : undefined)).find(Boolean);
        return [rec({ type: "a2a-agent-card", name: str(obj.name), url: str(obj.url) || ifaceUrl || sourceUrl, raw: { name: str(obj.name), description: str(obj.description), version: str(obj.version), url: str(obj.url), supportedInterfaces: ifaces.length ? ifaces : undefined } })];
      }
      case "openapi": {
        return [rec({ type: "openapi", name: obj.info && str(obj.info.title), url: sourceUrl })];
      }
      default:
        return [rec({ type, url: sourceUrl })];
    }
  } catch {
    return [];
  }
}

// Lightweight domain normalization (strip scheme/path/port/leading www).
export function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split("/")[0].split("?")[0].split("#")[0];
  d = d.replace(/:\d+$/, "").replace(/\.+$/, "");
  if (d.startsWith("www.")) d = d.slice(4);
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d) ? d : null;
}

async function fetchText(fetchImpl, url, timeoutMs, maxBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
      headers: { Accept: "application/json, text/plain;q=0.9, */*;q=0.1", "User-Agent": "NessGate-Resolver/1.1" },
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const text = await res.text();
    if (text.length > maxBytes) throw new Error("too large");
    return text;
  } finally {
    clearTimeout(timer);
  }
}

// resolve(domain) -> { domain, discovered, resources, checked, provenance }
// discovered = which standards the domain publishes and where (the routing map)
// resources  = the normalized union of what those documents contain
// Every resource carries `source`, `sourceUrl` (fetch it to verify against the
// domain directly), `url`, and, where useful, name/rel/id/raw.
export async function resolve(domain, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("no fetch available; pass opts.fetch");
  const timeoutMs = opts.timeoutMs || 8000;
  const maxBytes = opts.maxBytes || 1_000_000;
  const d = normalizeDomain(domain);
  if (!d) throw new Error("invalid domain");

  const hits = (
    await Promise.all(
      PROBES.map(async (p) => {
        for (const path of p.paths) {
          const url = "https://" + d + path;
          let text;
          try {
            text = await fetchText(fetchImpl, url, timeoutMs, maxBytes);
          } catch {
            continue;
          }
          if (validateProbeContent(p.kind, text) && probeShapeOk(p.type, p.kind, text)) return { type: p.type, url, kind: p.kind, text };
        }
        return null;
      })
    )
  ).filter(Boolean);

  const discovered = hits.map((h) => ({ type: h.type, url: h.url }));
  const resources = hits.flatMap((h) => normalizeResources(h.type, h.kind, h.text, h.url)).slice(0, MAX_DISCOVER_RESOURCES);
  return { domain: d, provenance: "self-published", discovered, resources, checked: PROBES.map((p) => p.type) };
}

export default { resolve, normalizeResources, normalizeDomain, validateProbeContent, probeShapeOk, PROBES };
