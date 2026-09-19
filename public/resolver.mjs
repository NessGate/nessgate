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
        const url = "https://" + domain + path;
        // OpenAPI: read a bounded prefix and detect from the head, so large specs
        // (multi-MB) are found without downloading/parsing the whole document.
        if (a.id === "openapi") {
          let r;
          try { r = await fetchBounded(fetchImpl, url, timeoutMs, OPENAPI_PREFIX_BYTES); } catch { continue; }
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
        try { r = await get(path); } catch { continue; }
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
      try { doc = await get(src); } catch { return { discovered: [], resources: [] }; }
      const targets = a.channel === "link-rel" ? parseLinkRel(doc.text, a.rels) : parseAgentmap(doc.text, a.directive);
      const discovered = [], resources = [];
      for (const t of targets.slice(0, MAX_LINKED_CATALOGS)) {
        let abs;
        // Relative targets resolve against the document's FINAL URL (HTML base
        // semantics: links belong to the page that actually served them).
        try { abs = new URL(t, doc.finalUrl || "https://" + domain + "/"); } catch { continue; }
        if (abs.protocol !== "https:" || !onDomain(abs.hostname, domain)) continue; // on-domain only
        let r;
        try { r = await get(abs.toString()); } catch { continue; }
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
export async function resolve(domain, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("no fetch available; pass opts.fetch");
  const timeoutMs = opts.timeoutMs || 8000;
  const maxBytes = opts.maxBytes || 1_000_000;
  const d = normalizeDomain(domain);
  if (!d) throw new Error("invalid domain");

  // Default = COMPLETE, ARD-conformant discovery (all channels incl. the required
  // rel="ard" link). opts.fast SKIPS the alternate ARD locators for speed — a
  // labeled, non-conformant performance trade (see FAST_MODE_SKIP).
  const active = opts.fast ? ADAPTERS.filter((a) => !FAST_MODE_SKIP.has(a.channel)) : ADAPTERS;
  const results = await Promise.all(active.map((a) => runAdapter(a, d, fetchImpl, timeoutMs, maxBytes)));
  const discovered = results.flatMap((r) => r.discovered);
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
          } catch {}
        }
      }
    } catch {}
  }
  // Optional GB/Z 185.5 discovery gateway — off unless the caller configures it.
  if (opts.gbz && opts.gbz.gatewayUrl) {
    const g = await queryGbzGateway(opts.gbz, timeoutMs);
    discovered.push(...g.discovered);
    resources.push(...g.resources);
    checked.push("gbz-185-5");
  }
  resources = resources.slice(0, MAX_DISCOVER_RESOURCES).map((r) => ({ ...r, class: classifyResource(r, d) }));
  const out = { domain: d, provenance: "self-published", discovered, resources, checked };
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

export default { resolve, normalizeResources, classifyResource, normalizeDomain, validateProbeContent, probeShapeOk, probeShapeOkObj, parseLinkRel, parseAgentmap, parseAidRecord, isAcs, normalizeAcsGatewayResponse, sameRegCanonicalHost, detectOpenApi, extractOpenApiCapabilities, fetchBounded, ADAPTERS };
