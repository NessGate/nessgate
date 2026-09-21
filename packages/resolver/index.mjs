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
// <link rel="ard">, an ARD robots.txt Agentmap directive, and an AID TXT
// record (v=aid1 at _agent — the AID draft, not the IETF DNS-AID SVCB draft).
// The adapter table and normalization below are identical to the
// reference resolver (src/worker.js); a parity test keeps them from drifting.
//
// GB/Z 185.4 (China): a GB/Z 185.4 agent description ("ACS") is recognised by
// content and normalized (source "gbz-185-4") — no GB/Z-specific path is guessed.
// GB/Z 185.5 discovery is OPTIONAL and library-only: pass opts.gbz to query a
// caller-CONFIGURED ACPs gateway with your OWN authenticated fetch. It is never
// auto-discovered and is not part of the hosted resolver.
//
// SSRF WARNING: this library fetches the domain you pass in and follows normal
// redirects. In browsers the network sandbox applies, but in Node/server
// environments a caller that passes an UNTRUSTED domain MUST validate it first
// (reject private/reserved addresses, keep redirects on-host). The hosted
// resolver at https://nessgate.com/discover/{domain} performs these checks.

export const ADAPTERS = [
  { id: "llms.txt", channel: "well-known", paths: ["/llms.txt", "/llms-full.txt"], kind: "text" },
  { id: "ard-catalog", channel: "well-known", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" },
  { id: "a2a-agent-card", channel: "well-known", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" },
  { id: "api-catalog", channel: "well-known", paths: ["/.well-known/api-catalog"], kind: "json" },
  { id: "ai-info.json", channel: "well-known", paths: ["/ai-info.json"], kind: "json" },
  { id: "openapi", channel: "well-known", paths: ["/openapi.json", "/openapi.yaml", "/openapi.yml"], kind: "json" },
  { id: "ord", channel: "well-known", paths: ["/.well-known/open-resource-discovery"], kind: "json" },
  { id: "awp", channel: "well-known", paths: ["/.well-known/awp.json"], kind: "json" },
  { id: "host-meta", channel: "well-known", paths: ["/.well-known/host-meta.json"], kind: "json" },
  { id: "anp", channel: "well-known", paths: ["/.well-known/agent-descriptions"], kind: "json" },
  { id: "ucp", channel: "well-known", paths: ["/.well-known/ucp", "/.well-known/ucp/manifest.json"], kind: "json" },
  { id: "ard-link", channel: "link-rel", rels: ["ard", "ai-catalog"], normalizeAs: "ard-catalog" },
  { id: "ard-agentmap", channel: "robots", directive: "agentmap", normalizeAs: "ard-catalog" },
  { id: "aid", channel: "dns", node: "_agent" }, // AID TXT (v=aid1) at _agent — NOT the IETF DNS-AID SVCB draft (_agents), a separate mechanism
];

// Alternate ARD locators beyond the well-known path. Per ARD v0.91 a conforming
// consumer MUST honour the rel="ard" HTML link (link-rel channel), so it runs in
// DEFAULT (complete) mode. The robots.txt Agentmap directive is optional for
// consumers, but is also included by default for complete discovery. The opt-in
// `fast` mode (opts.fast / ?fast=1) SKIPS both to save a homepage + robots fetch
// — a labeled performance trade that is NOT fully ARD-conformant (a catalog
// advertised only via <link rel="ard"> can be missed). Default stays conformant.
const FAST_MODE_SKIP = new Set(["link-rel", "robots"]);

const MAX_DISCOVER_RESOURCES = 200;
const MAX_PER_SOURCE = 50;
const MAX_LINKED_CATALOGS = 5;
const MAX_CAPABILITIES = 40; // cap on verbatim declared capabilities per resource
// MCP introspection (opt-in): bounded, read-only enumeration of what an MCP
// endpoint declares about itself via the protocol's own handshake.
const MCP_INTROSPECT_MAX_ENDPOINTS = 3; // endpoints introspected per resolution
const MCP_INTROSPECT_MAX_BYTES = 262144; // response cap per POST (tool lists are small)
const MCP_PROTOCOL_VERSION = "2025-06-18"; // newest version this client implements
// The COMPLETE set of JSON-RPC methods introspection may ever send. Read-only
// metadata enumeration only — tools/call and every other method are
// structurally absent (behaviorally negative-tested).
const MCP_INTROSPECTION_METHODS = ["initialize", "notifications/initialized", "tools/list"];
// Resource type labels that declare an MCP endpoint (the sources' own labels:
// AWP protocol key / AID p=mcp / self-declared "mcp"; ARD's community media
// type for server cards). No path guessing — only declared resources qualify.
const MCP_TYPE_LABELS = new Set(["mcp", "application/mcp-server-card+json"]);
// OpenAPI specs are frequently multi-MB, but detection (the openapi/swagger
// version marker) and our pointer-only record (info.title) live in the document
// HEAD. Read only a bounded prefix so a large spec is found without downloading
// or parsing megabytes. Separate from the generic 1 MB document cap so we do
// not loosen limits for every other protocol.
const OPENAPI_PREFIX_BYTES = 65536;

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
  // HTML is detected after skipping leading comments: a shell page opening with
  // <!-- ... --> must not pass as text, while a genuine text file with a
  // comment header still does.
  let head = text.trimStart();
  for (let i = 0; i < 5 && head.startsWith("<!--"); i++) {
    const end = head.indexOf("-->");
    if (end === -1) return false;
    head = head.slice(end + 3).trimStart();
  }
  return !head.startsWith("<");
}

// Confirm the document looks like the mechanism we probed for, so a JSON
// catch-all ({} for every unknown path) is not a false positive. IDENTICAL to
// src/worker.js (kept in sync by a parity test).
export function probeShapeOk(type, kind, text) {
  if (kind !== "json") return true;
  let obj;
  try { obj = JSON.parse(text); } catch { return false; }
  return probeShapeOkObj(type, obj);
}

// Object variant: one parse per document even when classifying against many
// types (repeated JSON.parse of large specs is the dominant CPU cost).
export function probeShapeOkObj(type, obj) {
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
    case "gbz-185-4": return isAcs(obj); // GB/Z 185.4 ACS agent description
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

// Parse an AID TXT record (v=aid1): a semicolon-delimited string of key=value
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

// GB/Z 185.4 (China) agent description ("ACS") — an A2A-family card plus GB/Z
// extensions (aic, mTLS scheme, certificate block). Recognised by content, never
// a guessed path; normalized wherever legitimately encountered.
export function isAcs(obj) {
  if (!obj || typeof obj !== "object") return false;
  const marker =
    Object.prototype.hasOwnProperty.call(obj, "aic") ||
    (obj.certificate && typeof obj.certificate === "object" && obj.certificate.requestedValidity !== undefined);
  if (!marker) return false;
  return !!(typeof obj.name === "string" || Array.isArray(obj.skills) || (obj.capabilities && typeof obj.capabilities === "object"));
}

// Verbatim skill declarations (A2A agent cards + GB/Z ACS share the `skills`
// shape) → the unified capabilities envelope. Publisher's OWN id / name /
// description / tags, capped, nothing inferred, nothing renamed, nothing
// classified. Returns null when the card declares no skills.
function declaredSkills(obj) {
  const skills = Array.isArray(obj.skills) ? obj.skills : [];
  const str = (v) => (typeof v === "string" ? v : undefined);
  const out = [];
  for (const s of skills) {
    if (!s || typeof s !== "object") continue;
    const entry = { id: str(s.id), name: str(s.name), description: str(s.description), tags: Array.isArray(s.tags) ? s.tags.filter((t) => typeof t === "string").slice(0, 16) : undefined };
    // A skill that declares none of id/name/description surfaces nothing — skip
    // it (absence, not invention; empty {} entries would be pure noise).
    if (entry.id === undefined && entry.name === undefined && entry.description === undefined) continue;
    if (out.length >= MAX_CAPABILITIES) return { capabilities: out, capabilitiesTruncated: true };
    out.push(entry);
  }
  return out.length ? { capabilities: out } : null;
}

function normalizeAcs(obj, sourceUrl) {
  const str = (v) => (typeof v === "string" ? v : undefined);
  const eps = Array.isArray(obj.endPoints) ? obj.endPoints : [];
  const epUrl = eps.map((e) => (e ? str(e.url) || str(e.endpoint) || str(e.address) : undefined)).find(Boolean);
  return [{
    source: "gbz-185-4",
    sourceUrl,
    type: "gbz-185-4-acs",
    name: str(obj.name),
    url: str(obj.webAppUrl) || epUrl || sourceUrl,
    ...(declaredSkills(obj) || {}),
    raw: {
      aic: str(obj.aic),
      name: str(obj.name),
      description: str(obj.description),
      version: str(obj.version),
      protocolVersion: str(obj.protocolVersion),
      provider: obj.provider,
      securitySchemes: obj.securitySchemes,
      certificate: obj.certificate,
      capabilities: obj.capabilities,
      skills: Array.isArray(obj.skills) ? obj.skills : undefined,
      endPoints: eps.length ? eps : undefined,
    },
  }];
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
      case "gbz-185-4":
        return normalizeAcs(obj, sourceUrl);
      case "a2a-agent-card": {
        if (isAcs(obj)) return normalizeAcs(obj, sourceUrl);
        const ifaces = Array.isArray(obj.supportedInterfaces) ? obj.supportedInterfaces : [];
        const ifaceUrl = ifaces.map((i) => (i ? str(i.url) : undefined)).find(Boolean);
        // capabilities = the card's OWN declared skills (verbatim, capped); the
        // card-level capabilities object (streaming etc.) rides along in raw.
        return [rec({ type: "a2a-agent-card", name: str(obj.name), url: str(obj.url) || ifaceUrl || sourceUrl, ...(declaredSkills(obj) || {}), raw: { name: str(obj.name), description: str(obj.description), version: str(obj.version), url: str(obj.url), capabilities: obj.capabilities && typeof obj.capabilities === "object" && !Array.isArray(obj.capabilities) ? obj.capabilities : undefined, supportedInterfaces: ifaces.length ? ifaces : undefined } })];
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

// Bounded read → { text, truncated, finalUrl }. LITERAL cap: at most maxBytes of body data
// are ever retained in memory — the final chunk is trimmed to the remaining
// allowance before buffering, then the stream is cancelled. `truncated` is true
// only when there were MORE bytes beyond the cap (a body that ends exactly at
// the cap is complete, not truncated), so callers can tell a cap-truncated
// document from a complete one. (The network/runtime may have buffered bytes
// under fetch before we cancel; NessGate itself retains and processes no more
// than maxBytes.) `finalUrl` is the URL the bytes actually came from — the
// post-redirect response URL when fetchImpl followed redirects (res.url), else
// the requested URL — so callers can attribute content to its real origin.
// `contentLength` is the server's own declared size (when present and sane) so
// callers can skip re-reads that could never complete within a cap.
export async function fetchBounded(fetchImpl, url, timeoutMs, maxBytes) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
      headers: { Accept: "application/json, text/plain;q=0.9, */*;q=0.1", "User-Agent": "NessGate-Resolver/1.3" },
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const finalUrl = (typeof res.url === "string" && res.url) || url;
    const clRaw = res.headers && typeof res.headers.get === "function" ? res.headers.get("content-length") : null;
    const contentLength = clRaw != null && /^\d+$/.test(String(clRaw).trim()) ? Number(clRaw) : undefined;
    const reader = res.body && typeof res.body.getReader === "function" ? res.body.getReader() : null;
    if (reader) {
      const chunks = [];
      let size = 0;
      let truncated = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const remaining = maxBytes - size;
        if (value.length >= remaining) {
          chunks.push(value.subarray(0, remaining)); // retain ONLY up to the cap
          size += remaining;
          if (value.length > remaining) truncated = true;
          else { const nxt = await reader.read(); if (!nxt.done) truncated = true; } // exact-cap: peek for more
          try { await reader.cancel(); } catch {}
          break;
        }
        chunks.push(value);
        size += value.length;
      }
      const buf = new Uint8Array(size);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      return { text: new TextDecoder().decode(buf), truncated, finalUrl, contentLength };
    }
    const text = await res.text();
    return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true, finalUrl, contentLength } : { text, truncated: false, finalUrl, contentLength };
  } finally {
    clearTimeout(timer);
  }
}

// → { text, finalUrl }: content plus the URL it actually came from, so probe
// records can attribute redirected documents to their real (post-redirect) origin.
async function fetchText(fetchImpl, url, timeoutMs, maxBytes) {
  const r = await fetchBounded(fetchImpl, url, timeoutMs, maxBytes);
  return { text: r.text, finalUrl: r.finalUrl };
}

// OpenAPI detection. If the body completed within our cap (`truncated` false) we
// require valid JSON with an openapi/swagger version — a complete-but-malformed
// document is REJECTED. Only when WE truncated the body (it exceeded the prefix
// cap) do we fall back to the bounded head-marker scan, since a genuinely large
// spec cannot be JSON-parsed from its head alone. Pointer-only: we never need
// the full paths object.
export function detectOpenApi(text, truncated = false) {
  if (typeof text !== "string" || !text) return { ok: false };
  try {
    const o = JSON.parse(text);
    if (o && typeof o === "object" && (typeof o.openapi === "string" || typeof o.swagger === "string")) {
      return { ok: true, title: o.info && typeof o.info.title === "string" ? o.info.title : undefined };
    }
    return { ok: false };
  } catch {
    if (!truncated) return { ok: false }; // complete but malformed → reject (do NOT trust the marker)
    if (!/^﻿?\s*\{/.test(text)) return { ok: false }; // truncated: must still look like a JSON object
    const ver = /"(?:openapi|swagger)"\s*:\s*"(\d[^"]*)"/.exec(text);
    if (!ver) return { ok: false };
    const title = /"title"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(text);
    return { ok: true, title: title ? title[1] : undefined, truncated: true };
  }
}

// Verbatim OpenAPI declarations — the publisher's OWN operations (method, path,
// operationId, summary) and security schemes (components.securitySchemes /
// Swagger-2 securityDefinitions), extracted 1:1 from a COMPLETE document.
// Nothing is inferred, renamed, or reclassified: NessGate surfaces what the
// spec says or nothing at all (a truncated document yields no capabilities —
// partial extraction could misrepresent the API). Returns null when the
// document doesn't parse or declares nothing. Identical worker/library
// (parity-tested).
export function extractOpenApiCapabilities(text) {
  try {
    const obj = JSON.parse(text);
    if (!obj || typeof obj !== "object") return null;
    const str = (v) => (typeof v === "string" ? v : undefined);
    const out = {};
    const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
    const caps = [];
    let more = false;
    if (obj.paths && typeof obj.paths === "object") {
      for (const [p, item] of Object.entries(obj.paths)) {
        if (!item || typeof item !== "object") continue;
        for (const m of METHODS) {
          const op = item[m];
          if (!op || typeof op !== "object") continue;
          if (caps.length >= MAX_CAPABILITIES) { more = true; break; }
          caps.push({ method: m.toUpperCase(), path: p, operationId: str(op.operationId), summary: str(op.summary) });
        }
        if (more) break;
      }
    }
    if (caps.length) { out.capabilities = caps; if (more) out.capabilitiesTruncated = true; }
    const schemes =
      obj.components && typeof obj.components === "object" && obj.components.securitySchemes && typeof obj.components.securitySchemes === "object"
        ? obj.components.securitySchemes
        : obj.securityDefinitions && typeof obj.securityDefinitions === "object"
          ? obj.securityDefinitions
          : null;
    if (schemes) {
      const sec = [];
      let secMore = false;
      for (const [name, s] of Object.entries(schemes)) {
        if (!s || typeof s !== "object") continue;
        if (sec.length >= MAX_CAPABILITIES) { secMore = true; break; }
        sec.push({ name, type: str(s.type), scheme: str(s.scheme), in: str(s.in) });
      }
      if (sec.length) { out.security = sec; if (secMore) out.securityTruncated = true; } // no silent caps
    }
    return out.capabilities || out.security ? out : null;
  } catch {
    return null;
  }
}

/* --- MCP introspection (opt-in, read-only) — pure parts parity-tested --- */

// Parse the JSON-RPC message(s) out of a Streamable-HTTP response body: plain
// JSON, or SSE framing (data: lines accumulated per event). Verbatim; malformed
// frames are dropped, never guessed at.
export function parseMcpMessages(text, contentType) {
  const out = [];
  const push = (s) => { if (!s) return; try { const o = JSON.parse(s); if (o && typeof o === "object") out.push(o); } catch {} };
  const ct = String(contentType || "").split(";")[0].trim().toLowerCase();
  if (ct === "text/event-stream") {
    let data = [];
    for (const raw of String(text).split(/\r?\n/)) {
      if (raw === "") { push(data.join("\n")); data = []; continue; }
      if (raw.startsWith("data:")) data.push(raw.slice(5).replace(/^ /, ""));
    }
    push(data.join("\n"));
  } else {
    push(text);
  }
  return out;
}

// The server's OWN declared tools → the unified capabilities envelope. Verbatim
// name / description / inputSchema (the spec requires name; entries without one
// carry nothing usable and are skipped). Capped and labeled, never silent.
export function mcpToolCapabilities(result) {
  const tools = result && typeof result === "object" && Array.isArray(result.tools) ? result.tools : [];
  const out = [];
  for (const t of tools) {
    if (!t || typeof t !== "object" || typeof t.name !== "string") continue;
    if (out.length >= MAX_CAPABILITIES) return { capabilities: out, capabilitiesTruncated: true };
    out.push({
      name: t.name,
      description: typeof t.description === "string" ? t.description : undefined,
      inputSchema: t.inputSchema && typeof t.inputSchema === "object" ? t.inputSchema : undefined,
    });
  }
  return out.length ? { capabilities: out } : null;
}

// One bounded POST of one JSON-RPC frame. Never follows redirects (a redirected
// POST is recorded as a failure, not chased). Returns status + content type +
// capped body text + response headers.
async function mcpPost(fetchImpl, url, frame, extraHeaders, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "User-Agent": "NessGate-Introspect/1.0 (+https://nessgate.com)",
        ...(extraHeaders || {}),
      },
      body: JSON.stringify(frame),
    });
    // LITERAL cap (audit fix): never buffer beyond the limit before checking.
    let text = "";
    if (res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const chunks = [];
      let size = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MCP_INTROSPECT_MAX_BYTES) { try { await reader.cancel(); } catch {} throw new Error("response too large"); }
        chunks.push(value);
      }
      const buf = new Uint8Array(size);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      text = new TextDecoder().decode(buf);
    } else {
      text = await res.text();
      if (text.length > MCP_INTROSPECT_MAX_BYTES) throw new Error("response too large");
    }
    return { status: res.status, contentType: (res.headers && typeof res.headers.get === "function" && res.headers.get("content-type")) || "", text, headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}

// Introspect ONE declared MCP endpoint with the protocol's own read-only
// handshake: initialize → notifications/initialized → tools/list. Nothing else
// is ever sent (MCP_INTROSPECTION_METHODS is the complete set): no tool
// execution, no credentials — an auth wall is an honest observation
// ("auth-required"), never retried with secrets. Failures collapse to labeled
// statuses; nothing is guessed.
async function introspectMcpEndpoint(fetchImpl, url, timeoutMs) {
  const fail = (status) => ({ introspection: { ok: false, status } });
  try {
    const init = await mcpPost(fetchImpl, url, {
      jsonrpc: "2.0", id: 1, method: MCP_INTROSPECTION_METHODS[0],
      params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "NessGate-Introspect", version: "1.0" } },
    }, null, timeoutMs);
    if (init.status === 401 || init.status === 403) return fail("auth-required");
    if (init.status === 405) return fail("legacy-transport"); // pre-2025 HTTP+SSE servers reject POST at the SSE URL
    if (init.status < 200 || init.status >= 300) return fail("error");
    const initMsg = parseMcpMessages(init.text, init.contentType).find((m) => m.id === 1);
    if (!initMsg || !initMsg.result || typeof initMsg.result !== "object") return fail("error");
    const session = init.headers && typeof init.headers.get === "function" ? init.headers.get("mcp-session-id") : null;
    const negotiated = typeof initMsg.result.protocolVersion === "string" ? initMsg.result.protocolVersion : undefined;
    const extra = { ...(session ? { "Mcp-Session-Id": session } : {}), ...(negotiated ? { "MCP-Protocol-Version": negotiated } : {}) };
    try { await mcpPost(fetchImpl, url, { jsonrpc: "2.0", method: MCP_INTROSPECTION_METHODS[1] }, extra, timeoutMs); } catch {}
    const lst = await mcpPost(fetchImpl, url, { jsonrpc: "2.0", id: 2, method: MCP_INTROSPECTION_METHODS[2], params: {} }, extra, timeoutMs);
    if (lst.status === 401 || lst.status === 403) return fail("auth-required");
    if (lst.status < 200 || lst.status >= 300) return fail("error");
    const lstMsg = parseMcpMessages(lst.text, lst.contentType).find((m) => m.id === 2);
    if (!lstMsg || !lstMsg.result || typeof lstMsg.result !== "object") return fail("error");
    const si = initMsg.result.serverInfo;
    const serverInfo = si && typeof si === "object"
      ? { name: typeof si.name === "string" ? si.name : undefined, version: typeof si.version === "string" ? si.version : undefined }
      : undefined;
    return { introspection: { ok: true, protocolVersion: negotiated, serverInfo }, ...(mcpToolCapabilities(lstMsg.result) || {}) };
  } catch {
    return fail("error");
  }
}

// Pick the declared MCP endpoints eligible for introspection: declared type
// label only (no path guessing), HTTPS, same registrable domain as the query,
// deduped, capped. Declared EXTERNAL endpoints are never introspected.
function mcpIntrospectionCandidates(resources, domain) {
  const out = [];
  const seen = new Set();
  for (const r of resources) {
    if (!MCP_TYPE_LABELS.has(String(r.type).toLowerCase())) continue;
    let u;
    try { u = new URL(r.url); } catch { continue; }
    if (u.protocol !== "https:") continue;
    const h = u.hostname.toLowerCase().replace(/\.+$/, "");
    if (h !== domain && !h.endsWith("." + domain)) continue;
    if (seen.has(r.url)) continue;
    seen.add(r.url);
    out.push(r);
    if (out.length >= MCP_INTROSPECT_MAX_ENDPOINTS) break;
  }
  return out;
}

// Bounded YAML OpenAPI detection — the document's own top-level
// `openapi: <version>` marker on a non-HTML body; title read verbatim from the
// info block when the simple line structure allows. No YAML parser (the
// library stays dependency-free), so YAML specs are detected as pointer
// records without capability enumeration — a documented limitation, never a
// guess. Identical worker/library (parity-tested).
export function detectOpenApiYaml(text) {
  if (typeof text !== "string" || !text || /^\s*</.test(text)) return { ok: false };
  const ver = /^openapi:\s*['"]?(\d[\d.]*)/m.exec(text);
  if (!ver) return { ok: false };
  const title = /^\s{1,8}title:\s*['"]?([^'"\n]{1,160})/m.exec(text);
  return { ok: true, title: title ? title[1].trim() : undefined };
}

// Pure: map an HTTP status (0 = network-level failure) to an honest
// reachability state — STATUS-ONLY knowledge; classifyDenial upgrades it with
// header/body evidence where available. Deliberately conservative:
//   ok            — the endpoint answered (2xx/3xx; 405/406 count — alive,
//                   only method/representation negotiation differs, normal
//                   for POST-only protocol endpoints)
//   auth-required — 401/407: the protocol says credentials are required
//   unknown       — bare 403: could be authorization OR a bot-wall — a status
//                   code alone cannot tell, and we never assume
//   rate-limited  — 429: alive; the server asked us to slow down
//   not-found     — 404/410: the publisher declared it, nothing is there
//   unreachable   — network failures, timeouts, 5xx: NOT shown usable
// "ok" asserts the endpoint responded to a safe request — never that every
// operation succeeds. Identical worker/library (parity-tested).
export function reachabilityFromStatus(status) {
  const s = Number(status) || 0;
  if ((s >= 200 && s < 400) || s === 405 || s === 406) return "ok";
  if (s === 401 || s === 407) return "auth-required";
  if (s === 403) return "unknown";
  if (s === 429) return "rate-limited";
  if (s === 404 || s === 410) return "not-found";
  return "unreachable";
}

// Pure: classify a probe response using status PLUS evidence — a small,
// conservative signal list, never an arms race. Anti-bot identification must
// be RELIABLE or it stays "unknown" (the user rule: never assume a denial is
// bot protection, and never assume it is auth either).
//   headers: plain object, lowercase keys (allowlisted by the probe)
//   bodySnippet: ≤2 KB of the denial body (only fetched for unexplained
//   403/503) — inspected here, NEVER stored or returned
// Returns { reachability, signal?, retryAfterSeconds? }. Signals are names
// only (e.g. "cf-challenge"), so evidence can be preserved without carrying
// any response content. Identical worker/library (parity-tested).
export function classifyDenial({ status, headers = {}, bodySnippet = "" } = {}) {
  const s = Number(status) || 0;
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = String(v == null ? "" : v);
  const ra = /^\d+$/.test(String(h["retry-after"] || "").trim()) ? Number(h["retry-after"]) : undefined;
  const out = (reachability, signal) => ({ reachability, ...(signal ? { signal } : {}), ...(ra !== undefined ? { retryAfterSeconds: ra } : {}) });

  // Authentication is only claimed on protocol evidence, never assumed.
  if (h["www-authenticate"]) return out("auth-required", "www-authenticate");
  if (s === 401 || s === 407) return out("auth-required");

  // Challenge signals — checked ONLY on denial-ish statuses (a 200 page may
  // legitimately embed a captcha widget; that is not a wall).
  if (s === 403 || s === 503 || s === 429) {
    if ((h["cf-mitigated"] || "").includes("challenge")) return out("blocked", "cf-challenge");
    for (const k of Object.keys(h)) {
      if (k.startsWith("x-datadome")) return out("blocked", "datadome");
      if (k.startsWith("x-px") || k === "x-perimeterx") return out("blocked", "perimeterx");
    }
    if (["challenge", "captcha"].includes(h["x-amzn-waf-action"] || "")) return out("blocked", "aws-waf");
    const b = String(bodySnippet || "").slice(0, 2048);
    if (/cf_chl_|challenge-platform|Just a moment\.\.\./.test(b)) return out("blocked", "cf-challenge");
    if (/geo\.captcha-delivery\.com/.test(b)) return out("blocked", "datadome");
    if (/_Incapsula_Resource|Incapsula incident/.test(b)) return out("blocked", "imperva");
    if (/errors\.edgesuite\.net/.test(b)) return out("blocked", "akamai");
    if (/hcaptcha\.com\/captcha|www\.google\.com\/recaptcha\/api/.test(b)) return out("blocked", "captcha");
  }
  if (s === 429) return out("rate-limited", ra !== undefined ? "retry-after" : undefined);
  return out(reachabilityFromStatus(s));
}

// Pure: drop duplicate records produced when ONE document is legitimately
// reachable through several channels (well-known path + rel="ard" link +
// robots Agentmap all naming the same catalog). Keeps the first occurrence
// (channel order = priority). Identical worker/library (parity-tested).
export function dedupeResources(resources) {
  const seen = new Set();
  return resources.filter((r) => { const k = r.source + "|" + r.url + "|" + r.sourceUrl; if (seen.has(k)) return false; seen.add(k); return true; });
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

/* --- Probe-outcome honesty (pure, identical in src/worker.js; parity-tested) --- */

// Classify one FAILED probe from its error message. "answered" = the domain
// gave a definitive answer that nothing is at that location (clean 404/410, no
// public DNS record, or a redirect pointing away) — absence is CONFIRMED there.
// "refused" = the domain (or its protection layer) would not let the check
// happen (auth/rate/5xx statuses, timeouts, network failures) — absence is
// UNKNOWN there. Unknown failure shapes default to "refused": overcaution may
// label a flaky site blocked, but can never claim absence that was not shown.
export function probeFailureKind(message) {
  const msg = String(message || "");
  const m = /HTTP (\d+)/.exec(msg);
  if (m) {
    const s = Number(m[1]);
    return s === 404 || s === 410 ? "answered" : "refused";
  }
  if (/does not resolve/.test(msg)) return "answered"; // no public host — nothing is published there
  if (/left the target domain|too many redirects|redirect without a target/.test(msg)) return "answered"; // the domain answered by pointing away
  if (/response is too large/.test(msg)) return "answered"; // it answered; the content just exceeds our cap
  return "refused";
}

// The single honest outcome label for a resolution:
//   found      — validated resources exist.
//   blocked    — nothing found AND refusals dominate (refused >= answered,
//                refused > 0): the checks were prevented, absence is UNKNOWN.
//   none-found — the checks completed; no supported declaration exists at the
//                locations checked.
// A lone flaky timeout among many clean 404s stays none-found (with the
// refusal count still disclosed via blockedProbes) — blocked requires refusals
// to be at least as common as clean answers.
export function resolutionOutcome(resourceCount, probes) {
  if (resourceCount > 0) return "found";
  const r = (probes && probes.refused) || 0;
  const a = (probes && probes.answered) || 0;
  return r > 0 && r >= a ? "blocked" : "none-found";
}

// Run one adapter over its channel. Failures collapse to empty.
async function runAdapter(a, domain, fetchImpl, timeoutMs, maxBytes, probes) {
  // probes (optional): shared failure tally for the outcome label — every
  // failed fetch is classified answered-vs-refused by probeFailureKind.
  // NXDOMAIN is an ANSWER (the host does not exist → nothing is published
  // there), distinguishable in Node via the error cause chain; runtimes
  // without cause.code keep the older, overcautious classification. Deadline
  // skips (see resolve) are our own budget, neither answered nor refused.
  const miss = (e) => {
    if (!probes || (e && e.deadlineSkip)) return;
    probes[e && e.cause && e.cause.code === "ENOTFOUND" ? "answered" : probeFailureKind(e && e.message)]++;
  };
  const get = (pathOrUrl) => {
    const url = /^https?:\/\//i.test(pathOrUrl) ? pathOrUrl : "https://" + domain + pathOrUrl;
    return fetchText(fetchImpl, url, timeoutMs, maxBytes);
  };
  try {
    if (a.channel === "well-known") {
      for (const path of a.paths) {
        const url = "https://" + domain + path;
        // OpenAPI: read a bounded prefix and detect from the head, so large specs
        // (multi-MB) are found without downloading/parsing the whole document.
        if (a.id === "openapi") {
          let r;
          try { r = await fetchBounded(fetchImpl, url, timeoutMs, OPENAPI_PREFIX_BYTES); } catch (e) { miss(e); continue; }
          // YAML specs: detected by the document's own top-level marker;
          // pointer record only (no capability enumeration without a parser).
          if (/\.ya?ml$/.test(path)) {
            const det = detectOpenApiYaml(r.text);
            if (det.ok) return { discovered: [{ type: a.id, url: r.finalUrl }], resources: [{ source: "openapi", sourceUrl: r.finalUrl, type: "openapi", name: det.title, url: r.finalUrl }] };
            continue;
          }
          const det = detectOpenApi(r.text, r.truncated);
          if (det.ok) {
            // Declared capabilities need the COMPLETE document. If the prefix
            // held it all, parse that; else ONE additional bounded fetch (the
            // generic byte cap). A spec still larger than the cap stays
            // detected-but-not-enumerated — never partially extracted.
            let capSrc = r.truncated ? null : r.text;
            // Content-Length guard: when the server itself declares a size
            // beyond the byte cap, the full read can never complete — skip it.
            if (r.truncated && !(typeof r.contentLength === "number" && r.contentLength > maxBytes)) {
              try { const full = await fetchBounded(fetchImpl, url, timeoutMs, maxBytes); if (!full.truncated) capSrc = full.text; } catch {}
            }
            const decl = capSrc ? extractOpenApiCapabilities(capSrc) : null;
            return { discovered: [{ type: a.id, url: r.finalUrl }], resources: [{ source: "openapi", sourceUrl: r.finalUrl, type: "openapi", name: det.title, url: r.finalUrl, ...(decl || {}) }] };
          }
          continue;
        }
        let r;
        try { r = await get(path); } catch (e) { miss(e); continue; }
        if (validateProbeContent(a.kind, r.text) && probeShapeOk(a.id, a.kind, r.text)) {
          // Record the FINAL (post-redirect) URL: when fetchImpl followed a
          // redirect the bytes came from there, and classifyResource labels a
          // cross-registrable landing honestly (verified-external-location).
          return { discovered: [{ type: a.id, url: r.finalUrl }], resources: normalizeResources(a.id, a.kind, r.text, r.finalUrl) };
        }
      }
      return { discovered: [], resources: [] };
    }
    if (a.channel === "link-rel" || a.channel === "robots") {
      const src = a.channel === "link-rel" ? "/" : "/robots.txt";
      let doc;
      try { doc = await get(src); } catch (e) { miss(e); return { discovered: [], resources: [] }; }
      const targets = a.channel === "link-rel" ? parseLinkRel(doc.text, a.rels) : parseAgentmap(doc.text, a.directive);
      const discovered = [], resources = [];
      for (const t of targets.slice(0, MAX_LINKED_CATALOGS)) {
        let abs;
        // Relative targets resolve against the document's FINAL URL (HTML base
        // semantics: links belong to the page that actually served them).
        try { abs = new URL(t, doc.finalUrl || "https://" + domain + "/"); } catch { continue; }
        if (abs.protocol !== "https:" || !onDomain(abs.hostname, domain)) continue; // on-domain only
        let r;
        try { r = await get(abs.toString()); } catch (e) { miss(e); continue; }
        if (validateProbeContent("json", r.text) && probeShapeOk(a.normalizeAs, "json", r.text)) {
          discovered.push({ type: a.id, url: r.finalUrl });
          resources.push(...normalizeResources(a.normalizeAs, "json", r.text, r.finalUrl));
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
          resources.push({ source: "aid", sourceUrl: "dns:" + name, type: aid.proto || "aid", name: aid.desc, url: aid.uri, raw: aid });
        }
      }
      return { discovered, resources };
    }
    return { discovered: [], resources: [] };
  } catch {
    return { discovered: [], resources: [] };
  }
}

// GB/Z 185.5 discovery gateway — OPTIONAL, library/Node only, OFF unless the
// caller configures it. NessGate does NOT auto-discover the gateway (there is no
// domain-native mechanism) and NEVER runs this on the hosted service. The caller
// supplies the gateway base URL, their OWN authenticated fetch (for mTLS/OIDC —
// no credential handling is embedded here), and the semantic query. We POST to
// the standard {gateway}/acps-adp-v2/discover endpoint (the real path from the
// ACPs reference implementation) and normalize any GB/Z 185.4 ACS records it
// returns, tagging each provenance:"gbz-185-5-gateway". No guessed endpoints; no
// fake conformance.
export function normalizeAcsGatewayResponse(body, sourceUrl) {
  let obj = body;
  if (typeof body === "string") { try { obj = JSON.parse(body); } catch { return []; } }
  if (!obj || typeof obj !== "object") return [];
  let entries = [];
  if (Array.isArray(obj)) entries = obj;
  else for (const k of ["results", "agents", "items", "data", "matches", "acs"]) {
    if (Array.isArray(obj[k])) { entries = obj[k]; break; }
  }
  const out = [];
  for (const e of entries) {
    if (isAcs(e)) for (const r of normalizeAcs(e, sourceUrl)) out.push({ ...r, provenance: "gbz-185-5-gateway" });
  }
  return out.slice(0, MAX_PER_SOURCE);
}

async function queryGbzGateway(gbz, timeoutMs) {
  const fetchImpl = gbz.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("gbz.fetch required (bring your own authenticated fetch)");
  const base = String(gbz.gatewayUrl).replace(/\/+$/, "");
  const url = base + "/acps-adp-v2/discover";
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", ...(gbz.headers || {}) },
      body: JSON.stringify(gbz.query || {}),
      signal: ctrl.signal,
    });
    if (!res || !res.ok) return { discovered: [], resources: [] };
    const text = await res.text();
    const resources = normalizeAcsGatewayResponse(text, url);
    return { discovered: resources.length ? [{ type: "gbz-185-5", url }] : [], resources };
  } catch {
    return { discovered: [], resources: [] };
  } finally {
    clearTimeout(timer);
  }
}

// One SAFE reachability probe for the verify pass: HEAD first; one bounded
// GET fallback when HEAD is unsupported (405/501), failed at the network
// level, or produced an UNEXPLAINED denial (403/503 with no signal headers —
// the ≤2 KB body snippet is what makes reliable bot-wall identification
// possible; it is classified, never stored). Never POSTs, never executes
// anything. Returns { status, headers (allowlisted, lowercase), snippet }.
const VERIFY_MAX_TARGETS = 8;
const VERIFY_HEADER_ALLOWLIST = ["www-authenticate", "retry-after", "cf-mitigated", "x-amzn-waf-action", "x-perimeterx"];
const VERIFY_HEADER_PREFIXES = ["x-datadome", "x-px"];
function pickVerifyHeaders(res) {
  // Real Headers are iterable in every supported runtime; a non-iterable
  // stand-in simply yields no evidence (classification falls back to
  // status-only, which is the honest floor).
  const out = {};
  try {
    for (const [k, v] of res.headers) {
      const key = String(k).toLowerCase();
      if (VERIFY_HEADER_ALLOWLIST.includes(key) || VERIFY_HEADER_PREFIXES.some((p) => key.startsWith(p))) out[key] = String(v);
    }
  } catch {}
  return out;
}
// LITERAL-cap snippet read: at most ~2 KB is ever retained; the stream is
// cancelled immediately after (a hostile multi-megabyte denial page must not
// be buffered). Falls back to text() only for body-less test doubles.
async function boundedSnippet(res, cap = 2048) {
  try {
    if (res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const chunks = [];
      let size = 0;
      while (size < cap) {
        const { done, value } = await reader.read();
        if (done) break;
        const room = cap - size;
        chunks.push(value.length > room ? value.subarray(0, room) : value);
        size += Math.min(value.length, room);
        if (value.length > room) break;
      }
      try { await reader.cancel(); } catch {}
      const buf = new Uint8Array(size);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      return new TextDecoder().decode(buf);
    }
    if (typeof res.text === "function") return String(await res.text()).slice(0, cap);
  } catch {}
  return "";
}
async function probeReachability(fetchImpl, url, timeoutMs) {
  const attempt = async (method, wantSnippet) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      // redirect:"manual": a denial page's redirect is never blind-followed
      // (per-hop validation is the rule everywhere else); a 3xx IS an answer —
      // the endpoint is alive — and maps to "ok". Runtimes that cannot do
      // manual redirects surface the followed response instead, which only
      // makes the classification more generous, never less safe server-side.
      const res = await fetchImpl(url, { method, redirect: "manual", signal: ctrl.signal, headers: { "User-Agent": "NessGate-Verify/1.0 (+https://nessgate.com)", Accept: "*/*" } });
      let snippet = "";
      if (method === "GET") {
        if (wantSnippet) snippet = await boundedSnippet(res);
        else if (res.body && typeof res.body.cancel === "function") { try { await res.body.cancel(); } catch {} }
      }
      return { status: res.status || 0, headers: pickVerifyHeaders(res), snippet };
    } catch {
      return { status: 0, headers: {}, snippet: "" };
    } finally {
      clearTimeout(timer);
    }
  };
  const head = await attempt("HEAD", false);
  const unexplainedDenial = (r) => (r.status === 403 || r.status === 503) && !Object.keys(r.headers).some((k) => k !== "retry-after");
  if (head.status === 405 || head.status === 501 || head.status === 0) {
    const get = await attempt("GET", true);
    if (get.status !== 0 || head.status === 0) return get;
    return head;
  }
  if (unexplainedDenial(head)) {
    const get = await attempt("GET", true);
    if (get.status !== 0) return get;
  }
  return head;
}

// resolve(domain, opts) -> { domain, provenance, discovered, resources, checked }
// discovered = which mechanisms the domain publishes and where (the routing map)
// resources  = the normalized union of what those documents contain
// Every resource carries `source`, `sourceUrl` (the FINAL fetched URL after any
// redirects — fetch it to verify directly), `url`, and, where useful,
// name/rel/id/raw.
// opts.fast (optional): SKIP the alternate ARD locators (homepage <link rel="ard">,
//   robots Agentmap) to save 2 fetches. NOT fully ARD-conformant (v0.91 requires
//   honouring rel="ard"), so it is opt-in and the result is labeled mode:"fast".
//   Default discovery is complete and conformant.
// opts.gbz (optional, Node/embedded only): { gatewayUrl, fetch, query, headers }
//   enables GB/Z 185.5 discovery against a caller-CONFIGURED ACPs gateway with a
//   caller-supplied authenticated fetch. Never auto-discovered; never used by the
//   hosted resolver or in a browser.
// opts.mcp (optional, OFF by default): read-only MCP introspection of declared
//   MCP endpoints (initialize + tools/list only — never tools/call, never
//   credentials). Adds the server's own declared tools to the resource's
//   capabilities envelope and an `introspection` status; result is labeled
//   top-level `introspected: ["mcp"]`. Same-registrable-domain HTTPS endpoints
//   only, max 3 per resolution.
// opts.org (optional, OFF by default): when the exact host publishes nothing,
//   probe a bounded set of plausible same-registrable-domain hosts —
//   homepage-linked subdomains with developer/doc-facing labels first, then a
//   conventional shortlist (docs./developers./cloud./api.) — for llms.txt,
//   ard.json and openapi.json. The library counterpart of the hosted
//   /explore?org=1. ≤4 hosts × 3 paths; hosts attempted are reported in
//   `orgChecked`; findings classify normally (same registrable domain,
//   fetched + validated → verified-publisher-location).
// opts.deadlineMs (default 20000): a GLOBAL wall-clock budget for the whole
//   resolution (the hosted worker has always had one). Past the deadline no
//   NEW fetch starts; deadline skips count as neither answered nor refused;
//   an empty, cut-short result is labeled outcome "incomplete" with
//   truncated: true — never a confident absence.
// opts.verify (optional, OFF by default): a labeled reachability pass over the
//   result. Surfaces NessGate fetched this resolution are marked
//   reachability "ok" WITHOUT any extra request (the fetch is the evidence);
//   declared pointers get ONE safe probe each (HEAD, then a bounded GET when
//   HEAD is unsupported — never a POST, never an execution), capped at 8,
//   mapped by reachabilityFromStatus, each record stamped checkedAt. Absent
//   reachability = not checked. "ok" means the endpoint answered a safe
//   request — never that operations succeed or that the caller is authorized.
//   Cross-registrable targets are probed only because the publisher itself
//   declared them; in server-side runtimes the README's SSRF note applies.
export async function resolve(domain, opts = {}) {
  const rawFetch = opts.fetch || globalThis.fetch;
  if (typeof rawFetch !== "function") throw new Error("no fetch available; pass opts.fetch");
  const timeoutMs = opts.timeoutMs || 8000;
  const maxBytes = opts.maxBytes || 1_000_000;
  const d = normalizeDomain(domain);
  if (!d) throw new Error("invalid domain");

  // Global deadline + apex-DNS-flap guard, wrapped around every fetch:
  // a transient local NXDOMAIN on the APEX must not read as a confident
  // absence — its first ENOTFOUND is retried once; only a repeated apex
  // NXDOMAIN propagates as genuine nonexistence.
  const startedAt = Date.now();
  const deadlineMs = opts.deadlineMs || 20000;
  let deadlineHit = false;
  let apexDnsRetried = false;
  const fetchImpl = async (url, init) => {
    if (Date.now() - startedAt > deadlineMs) { deadlineHit = true; const e = new Error("resolver deadline reached"); e.deadlineSkip = true; throw e; }
    try {
      return await rawFetch(url, init);
    } catch (e) {
      let host = "";
      try { host = new URL(url).hostname.toLowerCase(); } catch {}
      if (e && e.cause && e.cause.code === "ENOTFOUND" && (host === d || host === "www." + d) && !apexDnsRetried) {
        apexDnsRetried = true;
        await new Promise((r) => setTimeout(r, 300));
        return rawFetch(url, init);
      }
      throw e;
    }
  };

  // Default = COMPLETE, ARD-conformant discovery (all channels incl. the required
  // rel="ard" link). opts.fast SKIPS the alternate ARD locators for speed — a
  // labeled, non-conformant performance trade (see FAST_MODE_SKIP).
  const active = opts.fast ? ADAPTERS.filter((a) => !FAST_MODE_SKIP.has(a.channel)) : ADAPTERS;
  // probes tallies every failed fetch (answered vs refused) for the outcome label.
  const probes = { answered: 0, refused: 0 };
  const results = await Promise.all(active.map((a) => runAdapter(a, d, fetchImpl, timeoutMs, maxBytes, probes)));
  let discovered = results.flatMap((r) => r.discovered);
  let resources = results.flatMap((r) => r.resources);
  const checked = active.map((a) => a.id);
  // Canonical-host fallback (same registrable domain ONLY): when the exact host
  // publishes nothing and its homepage redirects to www./a subdomain of itself,
  // probe that canonical host for llms.txt / ard.json. A redirect to a different
  // registrable domain is never followed here. Mirrors src/worker.js.
  if (discovered.length === 0) {
    try {
      const r = await fetchImpl("https://" + d + "/", { redirect: "follow" });
      const canon = sameRegCanonicalHost(r.url, d);
      if (canon) {
        for (const [path, type, kind] of [["/llms.txt", "llms.txt", "text"], ["/.well-known/ard.json", "ard-catalog", "json"]]) {
          try {
            const p = await fetchText(fetchImpl, "https://" + canon + path, timeoutMs, maxBytes);
            if (validateProbeContent(kind, p.text) && probeShapeOk(type, kind, p.text)) {
              discovered.push({ type, url: p.finalUrl });
              resources.push(...normalizeResources(type, kind, p.text, p.finalUrl));
            }
          } catch (e) { if (!(e && e.deadlineSkip)) probes[e && e.cause && e.cause.code === "ENOTFOUND" ? "answered" : probeFailureKind(e && e.message)]++; }
        }
      }
    } catch {}
  }
  // Opt-in org discovery (see opts.org above): the library counterpart of the
  // hosted /explore?org=1 — bounded related-host probing when the exact host
  // publishes nothing.
  let orgChecked = null;
  if (opts.org && discovered.length === 0) {
    orgChecked = [];
    const DEV_LABELS = ["docs", "developers", "developer", "api", "platform", "learn", "community", "cloud", "dev"];
    let homepageHosts = [];
    try {
      const home = await fetchImpl("https://" + d + "/", { redirect: "follow" });
      const html = typeof home.text === "function" ? await home.text() : "";
      const seenH = new Set();
      for (const m of String(html).match(/https?:\/\/[a-z0-9.-]+/gi) || []) {
        try {
          const h = new URL(m).hostname.toLowerCase().replace(/\.+$/, "");
          if (h !== d && h !== "www." + d && h.endsWith("." + d) && !seenH.has(h)) { seenH.add(h); homepageHosts.push(h); }
        } catch {}
      }
    } catch {}
    const hosts = [];
    const take = (h) => { if (!hosts.includes(h) && hosts.length < 4) hosts.push(h); };
    for (const h of homepageHosts) if (DEV_LABELS.includes(h.split(".")[0])) take(h);
    for (const p of ["docs", "developers", "cloud", "api"]) take(p + "." + d);
    for (const h of hosts) {
      if (Date.now() - startedAt > deadlineMs) { deadlineHit = true; break; }
      orgChecked.push(h);
      for (const [path, type, kind] of [["/llms.txt", "llms.txt", "text"], ["/.well-known/ard.json", "ard-catalog", "json"], ["/openapi.json", "openapi", "json"]]) {
        try {
          const p = await fetchText(fetchImpl, "https://" + h + path, timeoutMs, maxBytes);
          if (type === "openapi") {
            const det = detectOpenApi(p.text, false);
            if (det.ok) { discovered.push({ type, url: p.finalUrl }); resources.push({ source: "openapi", sourceUrl: p.finalUrl, type: "openapi", name: det.title, url: p.finalUrl }); }
          } else if (validateProbeContent(kind, p.text) && probeShapeOk(type, kind, p.text)) {
            discovered.push({ type, url: p.finalUrl });
            resources.push(...normalizeResources(type, kind, p.text, p.finalUrl));
          }
        } catch (e) { if (!(e && e.deadlineSkip)) probes[e && e.cause && e.cause.code === "ENOTFOUND" ? "answered" : probeFailureKind(e && e.message)]++; }
      }
    }
  }
  // Optional GB/Z 185.5 discovery gateway — off unless the caller configures it.
  if (opts.gbz && opts.gbz.gatewayUrl) {
    const g = await queryGbzGateway(opts.gbz, timeoutMs);
    discovered.push(...g.discovered);
    resources.push(...g.resources);
    checked.push("gbz-185-5");
  }
  // One document reachable through several channels must not multiply records.
  resources = dedupeResources(resources);
  {
    const seenD = new Set();
    discovered = discovered.filter((x) => { const k = x.type + "|" + x.url; if (seenD.has(k)) return false; seenD.add(k); return true; });
  }
  resources = resources.slice(0, MAX_DISCOVER_RESOURCES).map((r) => ({ ...r, class: classifyResource(r, d) }));
  // Opt-in MCP introspection: ask each declared (same-registrable, HTTPS) MCP
  // endpoint what IT declares, via the protocol's own read-only handshake. The
  // results land on the endpoint's own resource record — additive, verbatim.
  if (opts.mcp) {
    const cands = mcpIntrospectionCandidates(resources, d);
    await Promise.all(cands.map(async (r) => { Object.assign(r, await introspectMcpEndpoint(fetchImpl, r.url, timeoutMs)); }));
  }
  // Opt-in verify pass (see opts.verify above): evidence-derived where the
  // fetch already happened, one safe probe otherwise.
  if (opts.verify) {
    const now = new Date().toISOString();
    const probed = new Map(); // url -> classification (dedupe probes across records)
    let budget = VERIFY_MAX_TARGETS;
    for (const r of resources) {
      if (typeof r.url !== "string" || !r.url.startsWith("https://")) continue;
      if (r.class === "verified-publisher-location" || r.class === "verified-external-location" || r.url === r.sourceUrl) {
        r.reachability = "ok"; // this resolution fetched and validated it — no extra request
        r.checkedAt = now;
        r.evidence = { signal: "fetched-this-resolution" };
        continue;
      }
      if (r.introspection) { // MCP introspection already answered this
        r.reachability = r.introspection.ok ? "ok" : r.introspection.status === "auth-required" ? "auth-required" : r.introspection.status === "legacy-transport" ? "ok" : "unreachable";
        r.checkedAt = now;
        r.evidence = { signal: "mcp-introspection" };
        continue;
      }
      if (!probed.has(r.url)) {
        if (budget <= 0 || Date.now() - startedAt > deadlineMs) continue; // stays not-checked, honestly absent
        budget--;
        const probe = await probeReachability(fetchImpl, r.url, timeoutMs);
        const c = classifyDenial({ status: probe.status, headers: probe.headers, bodySnippet: probe.snippet });
        probed.set(r.url, { ...c, status: probe.status });
      }
      const c = probed.get(r.url);
      r.reachability = c.reachability;
      r.checkedAt = now;
      // Evidence: status + signal NAME + retry hint only — never response content.
      r.evidence = { status: c.status, ...(c.signal ? { signal: c.signal } : {}), ...(c.retryAfterSeconds !== undefined ? { retryAfterSeconds: c.retryAfterSeconds } : {}) };
    }
  }
  const out = { domain: d, provenance: "self-published", discovered, resources, checked };
  if (opts.verify) out.verified = ["reachability"]; // labeled: the verify pass ran
  // The single honest outcome label (found / none-found / blocked), plus the
  // refusal count so uncertainty is never hidden even under none-found. In
  // runtimes without DNS-failure detail (plain fetch), NXDOMAIN reads as a
  // network failure and counts toward refusals — overcautious by design.
  out.outcome = resolutionOutcome(resources.length, probes);
  // An empty result cut short by the global deadline is "incomplete", never a
  // confident absence (mirrors /explore); blocked stays blocked.
  if (out.outcome === "none-found" && deadlineHit) out.outcome = "incomplete";
  if (deadlineHit) out.truncated = true;
  if (orgChecked) out.orgChecked = orgChecked;
  if (probes.refused) out.blockedProbes = probes.refused;
  if (opts.mcp) out.introspected = ["mcp"]; // labeled: read-only introspection ran
  if (opts.fast) out.mode = "fast"; // labeled: alternate ARD locators skipped, not fully conformant
  return out;
}

// Label each resource by how much NessGate actually verified it — an additive DX
// field on results, derived with NO extra requests:
//   verified-publisher-location — the surface NessGate fetched AND validated, on
//     the domain's own registrable domain (the resource IS the fetched document).
//   verified-external-location — the fetched-and-validated document itself, but
//     its FINAL URL (after redirects) is on a DIFFERENT registrable domain: the
//     queried domain redirected there (e.g. a wholesale rebrand). Only the
//     library emits this — it follows redirects and records the final URL; the
//     hosted resolver never leaves the queried domain, so it never emits it.
//   publisher-declared — declared inside a fetched catalog, target on the same
//     registrable domain (incl. subdomains); the target itself was NOT fetched.
//   declared-external-pointer — declared inside a fetched catalog, target on a
//     DIFFERENT registrable domain; the publisher asserts it, NessGate did not verify.
//   unsupported — no usable target URL to locate the resource.
// A "third-party association" is an /explore concept, and flagging an
// "inaccessible" resource would require fetching every declared pointer — which
// resolve() avoids to keep request counts low. Kept byte-identical to src/worker.js.
export function classifyResource(r, domain) {
  let host;
  try { host = new URL(r.url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return "unsupported"; }
  const sameReg = host === domain || host.endsWith("." + domain);
  if (r.url === r.sourceUrl) return sameReg ? "verified-publisher-location" : "verified-external-location";
  return sameReg ? "publisher-declared" : "declared-external-pointer";
}

// Pure: the same-registrable-domain canonical host implied by a homepage final
// URL. Null for the apex itself and for any cross-registrable-domain redirect.
export function sameRegCanonicalHost(finalUrl, domain) {
  let h;
  try { h = new URL(finalUrl).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return null; }
  if (h === domain) return null;
  return h.endsWith("." + domain) ? h : null;
}

export default { resolve, normalizeResources, classifyResource, normalizeDomain, validateProbeContent, probeShapeOk, probeShapeOkObj, parseLinkRel, parseAgentmap, parseAidRecord, isAcs, normalizeAcsGatewayResponse, sameRegCanonicalHost, detectOpenApi, detectOpenApiYaml, extractOpenApiCapabilities, dedupeResources, reachabilityFromStatus, classifyDenial, parseMcpMessages, mcpToolCapabilities, probeFailureKind, resolutionOutcome, fetchBounded, ADAPTERS };
