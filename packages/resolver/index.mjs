// NessGate resolver — embeddable, dependency-free, decentralized.
//
// Give it a domain; it reads the standard machine-discovery surfaces the domain
// ITSELF publishes and returns one normalized list of that domain's
// machine-readable resources. There is NO runtime dependency on nessgate.com:
// this code fetches the target domain directly (DNS lookups use a public DoH
// endpoint). Bring your own `fetch` (defaults to the global one), so it runs in
// browsers, Node, Deno, Workers, and agent runtimes.
//
// It reads (never defines) these mechanisms and reuses each one's OWN labels —
// NessGate invents no taxonomy. Channels: fixed well-known paths, an ARD
// <link rel="ard">, an ARD robots.txt Agentmap directive, and a DNS-AID TXT
// record. The adapter table and normalization below are identical to the
// reference resolver (src/worker.js); a parity test keeps them from drifting.
//
// SSRF WARNING: this library fetches the domain you pass in and follows normal
// redirects. In browsers the network sandbox applies, but in Node/server
// environments a caller that passes an UNTRUSTED domain MUST validate it first
// (reject private/reserved addresses, keep redirects on-host). The hosted
// resolver at https://nessgate.com/discover/{domain} performs these checks.

export const ADAPTERS = [
  { id: "llms.txt", channel: "well-known", paths: ["/llms.txt"], kind: "text" },
  { id: "ard-catalog", channel: "well-known", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" },
  { id: "a2a-agent-card", channel: "well-known", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" },
  { id: "api-catalog", channel: "well-known", paths: ["/.well-known/api-catalog"], kind: "json" },
  { id: "ai-info.json", channel: "well-known", paths: ["/ai-info.json"], kind: "json" },
  { id: "openapi", channel: "well-known", paths: ["/openapi.json"], kind: "json" },
  { id: "ord", channel: "well-known", paths: ["/.well-known/open-resource-discovery"], kind: "json" },
  { id: "awp", channel: "well-known", paths: ["/.well-known/awp.json"], kind: "json" },
  { id: "host-meta", channel: "well-known", paths: ["/.well-known/host-meta.json"], kind: "json" },
  { id: "anp", channel: "well-known", paths: ["/.well-known/agent-descriptions"], kind: "json" },
  { id: "ucp", channel: "well-known", paths: ["/.well-known/ucp", "/.well-known/ucp/manifest.json"], kind: "json" },
  { id: "ard-link", channel: "link-rel", rels: ["ard", "ai-catalog"], normalizeAs: "ard-catalog" },
  { id: "ard-agentmap", channel: "robots", directive: "agentmap", normalizeAs: "ard-catalog" },
  { id: "dns-aid", channel: "dns", node: "_agent" },
];

const MAX_DISCOVER_RESOURCES = 200;
const MAX_PER_SOURCE = 50;
const MAX_LINKED_CATALOGS = 5;

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

// Confirm the document looks like the mechanism we probed for, so a JSON
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
    case "anp": return Array.isArray(obj.items) || obj["@type"] === "CollectionPage";
    case "ucp": return Array.isArray(obj.capabilities) || typeof obj.ucp_version === "string";
    default: return true;
  }
}

// Extract href values from <link rel="..."> tags whose rel matches any of `rels`.
export function parseLinkRel(html, rels) {
  if (typeof html !== "string") return [];
  const want = new Set(rels.map((r) => r.toLowerCase()));
  const out = [];
  const tags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const relM = tag.match(/\brel\s*=\s*["']?([^"'>]+)["']?/i);
    const hrefM = tag.match(/\bhref\s*=\s*["']([^"']+)["']/i);
    if (!relM || !hrefM) continue;
    const relTokens = relM[1].trim().toLowerCase().split(/\s+/);
    if (relTokens.some((t) => want.has(t))) out.push(hrefM[1].trim());
  }
  return out;
}

// Extract URLs from a robots.txt directive (ARD's `Agentmap: <url>`).
export function parseAgentmap(robots, directive) {
  if (typeof robots !== "string") return [];
  const re = new RegExp("^\\s*" + directive + "\\s*:\\s*(\\S+)", "i");
  const out = [];
  for (const line of robots.split(/\r?\n/)) {
    const m = line.match(re);
    if (m) out.push(m[1].trim());
  }
  return out;
}

// Parse an AID / DNS-AID TXT record: a semicolon-delimited string of key=value
// pairs (draft-nemethi-aid). Keys have short aliases (v/version, u/uri, p/proto,
// a/auth, s/desc, d/docs). Returns null unless it carries a version and a uri.
export function parseAidRecord(txt) {
  if (typeof txt !== "string") return null;
  const kv = {};
  for (const part of txt.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    const v = part.slice(i + 1).trim();
    if (k) kv[k] = v;
  }
  const pick = (a, b) => (kv[a] !== undefined ? kv[a] : kv[b]);
  const version = pick("v", "version");
  const uri = pick("u", "uri");
  if (!version || !uri) return null;
  return { version, uri, proto: pick("p", "proto"), auth: pick("a", "auth"), desc: pick("s", "desc"), docs: pick("d", "docs"), raw: kv };
}

// Normalize one fetched document into a flat list of resource records. Thin by
// design; reuses each source's own labels; never throws. IDENTICAL to
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
        const ifaces = Array.isArray(obj.supportedInterfaces) ? obj.supportedInterfaces : [];
        const ifaceUrl = ifaces.map((i) => (i ? str(i.url) : undefined)).find(Boolean);
        return [rec({ type: "a2a-agent-card", name: str(obj.name), url: str(obj.url) || ifaceUrl || sourceUrl, raw: { name: str(obj.name), description: str(obj.description), version: str(obj.version), url: str(obj.url), supportedInterfaces: ifaces.length ? ifaces : undefined } })];
      }
      case "openapi": {
        return [rec({ type: "openapi", name: obj.info && str(obj.info.title), url: sourceUrl })];
      }
      case "anp": {
        const items = Array.isArray(obj.items) ? obj.items : [];
        return cap(
          items.map((it) =>
            it && str(it["@id"]) ? rec({ type: "agent-description", name: str(it.name), url: it["@id"], raw: it }) : null
          )
        );
      }
      case "ucp": {
        const caps = Array.isArray(obj.capabilities) ? obj.capabilities : [];
        const out = [];
        for (const c of caps) {
          if (!c || typeof c !== "object") continue;
          const label = str(c.name) || str(c.id) || str(c.type) || "ucp-capability";
          const transports = Array.isArray(c.transports) ? c.transports : [];
          let emitted = false;
          for (const t of transports) {
            const url = t && (str(t.url) || str(t.endpoint));
            if (url) { out.push(rec({ type: str(t.type) || label, name: str(c.name), url, raw: c })); emitted = true; }
          }
          const direct = str(c.url) || str(c.endpoint);
          if (!emitted && direct) out.push(rec({ type: label, name: str(c.name), url: direct, raw: c }));
        }
        return out.length ? cap(out) : [rec({ type: "ucp", url: sourceUrl, raw: { ucp_version: str(obj.ucp_version) } })];
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

function onDomain(host, domain) {
  host = String(host).toLowerCase().replace(/\.+$/, "");
  return host === domain || host === "www." + domain || host.endsWith("." + domain);
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

async function dohTxt(fetchImpl, name, timeoutMs) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=TXT", {
        signal: controller.signal,
        headers: { Accept: "application/dns-json" },
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return [];
    const data = await res.json();
    const out = [];
    for (const a of data.Answer || []) {
      if (a.type !== 16) continue;
      out.push(String(a.data).replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
    }
    return out;
  } catch {
    return [];
  }
}

// Run one adapter over its channel. Failures collapse to empty.
async function runAdapter(a, domain, fetchImpl, timeoutMs, maxBytes) {
  const get = (pathOrUrl) => {
    const url = /^https?:\/\//i.test(pathOrUrl) ? pathOrUrl : "https://" + domain + pathOrUrl;
    return fetchText(fetchImpl, url, timeoutMs, maxBytes);
  };
  try {
    if (a.channel === "well-known") {
      for (const path of a.paths) {
        let text;
        try { text = await get(path); } catch { continue; }
        if (validateProbeContent(a.kind, text) && probeShapeOk(a.id, a.kind, text)) {
          const url = "https://" + domain + path;
          return { discovered: [{ type: a.id, url }], resources: normalizeResources(a.id, a.kind, text, url) };
        }
      }
      return { discovered: [], resources: [] };
    }
    if (a.channel === "link-rel" || a.channel === "robots") {
      const src = a.channel === "link-rel" ? "/" : "/robots.txt";
      let doc;
      try { doc = await get(src); } catch { return { discovered: [], resources: [] }; }
      const targets = a.channel === "link-rel" ? parseLinkRel(doc, a.rels) : parseAgentmap(doc, a.directive);
      const discovered = [], resources = [];
      for (const t of targets.slice(0, MAX_LINKED_CATALOGS)) {
        let abs;
        try { abs = new URL(t, "https://" + domain + "/"); } catch { continue; }
        if (abs.protocol !== "https:" || !onDomain(abs.hostname, domain)) continue; // on-domain only
        let text;
        try { text = await get(abs.toString()); } catch { continue; }
        if (validateProbeContent("json", text) && probeShapeOk(a.normalizeAs, "json", text)) {
          discovered.push({ type: a.id, url: abs.toString() });
          resources.push(...normalizeResources(a.normalizeAs, "json", text, abs.toString()));
        }
      }
      return { discovered, resources };
    }
    if (a.channel === "dns") {
      const name = a.node + "." + domain;
      const records = await dohTxt(fetchImpl, name, timeoutMs);
      const discovered = [], resources = [];
      for (const r of records) {
        const aid = parseAidRecord(r);
        if (aid) {
          discovered.push({ type: a.id, url: aid.uri });
          resources.push({ source: "dns-aid", sourceUrl: "dns:" + name, type: aid.proto || "aid", name: aid.desc, url: aid.uri, raw: aid });
        }
      }
      return { discovered, resources };
    }
    return { discovered: [], resources: [] };
  } catch {
    return { discovered: [], resources: [] };
  }
}

// resolve(domain) -> { domain, provenance, discovered, resources, checked }
// discovered = which mechanisms the domain publishes and where (the routing map)
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

  const results = await Promise.all(ADAPTERS.map((a) => runAdapter(a, d, fetchImpl, timeoutMs, maxBytes)));
  const discovered = results.flatMap((r) => r.discovered);
  const resources = results.flatMap((r) => r.resources).slice(0, MAX_DISCOVER_RESOURCES);
  return { domain: d, provenance: "self-published", discovered, resources, checked: ADAPTERS.map((a) => a.id) };
}

export default { resolve, normalizeResources, normalizeDomain, validateProbeContent, probeShapeOk, parseLinkRel, parseAgentmap, parseAidRecord, ADAPTERS };
