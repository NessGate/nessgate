// NessGate — the open, neutral compatibility resolver for the agentic web.
// Given a domain, it reads whatever that domain already publishes across the
// standard machine-discovery locations (ARD, A2A, llms.txt, API catalogs,
// OpenAPI, host-meta and more) and returns ONE normalized answer, with a link
// back to each source so an agent can always verify against the domain itself.
//
// - NessGate defines nothing and stores nothing: it reads the standards a
//   domain already publishes and normalizes them. A new standard is just a new
//   adapter (an ADAPTERS entry), never a competing format.
// - Nothing is crawled, indexed, or persisted. Each answer is computed fresh
//   and dies with its short edge cache.
// - Cloudflare KV is used ONLY for rate-limit counters.
//
// SSRF note (DNS rebinding / check-to-fetch TOCTOU): the DoH pre-check and the
// subsequent fetch resolve independently, so a rebinding window exists in
// theory. It is immaterial here: probes are read-only GETs of public,
// well-known paths, size- and redirect-capped, and Worker egress has no
// private network behind it to pivot into.

const FETCH_TIMEOUT_MS = 8000;
const MAX_JSON_BYTES = 1_000_000; // 1 MB cap on any fetched document
const MAX_REDIRECTS = 3;
const HSTS = "max-age=31536000; includeSubDomains";

export default {
  async fetch(request, env, ctx) {
    let res;
    try {
      res = await route(request, env, ctx);
    } catch (err) {
      console.error("route error:", err && err.stack ? err.stack : String(err));
      res = json({ error: "Internal error" }, 500, cors());
    }
    // Central hardening: identical security headers on EVERY response
    // (redirects, text routes, assets, errors) plus the exact build marker
    // so "production matches commit X" is objectively provable.
    const out = new Response(res.body, res);
    out.headers.set("Strict-Transport-Security", HSTS);
    out.headers.set("X-Content-Type-Options", "nosniff");
    out.headers.set("Referrer-Policy", "no-referrer");
    out.headers.set("X-Frame-Options", "DENY");
    out.headers.set("X-NessGate-Build", env.BUILD_ID || "dev");
    return out;
  },
};

const SECURITY_TXT = `Contact: mailto:security@nessgate.com
Contact: mailto:contact@nessgate.com
Expires: 2027-09-08T00:00:00.000Z
Preferred-Languages: en
Canonical: https://nessgate.com/.well-known/security.txt
`;

// nessgate.com is the self domain: discover answers for it are computed by
// dispatching probe paths through our own router in-process (never by the
// worker fetching itself over the network — safeFetch keeps refusing
// nessgate.com as defense in depth).
const SELF_DOMAIN = "nessgate.com";

// /.well-known/api-catalog — RFC 9727: a linkset (RFC 9264) describing the
// site's APIs. NessGate has exactly one API; its OpenAPI description and
// human docs are linked with the standard relations.
const API_CATALOG = {
  linkset: [
    {
      anchor: "https://nessgate.com/api",
      "service-desc": [{ href: "https://nessgate.com/openapi.json", type: "application/openapi+json" }],
      "service-doc": [{ href: "https://nessgate.com/api", type: "text/html" }],
      "service-meta": [{ href: "https://nessgate.com/spec", type: "text/html" }],
    },
  ],
};

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Canonical host: 301 www -> apex
  if (url.hostname === "www.nessgate.com") {
    url.hostname = "nessgate.com";
    return Response.redirect(url.toString(), 301);
  }

  if (request.method === "OPTIONS") return corsPreflight();

  // Google Search Console ownership verification (must be exact 200, no redirect)
  if (path === "/googleaad6665551b37b3b.html") {
    return new Response("google-site-verification: googleaad6665551b37b3b.html", {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (path === "/.well-known/security.txt") {
    return new Response(SECURITY_TXT, {
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" },
    });
  }

  if (path === "/.well-known/api-catalog") {
    return json(API_CATALOG, 200, {
      ...cors(),
      "Content-Type": "application/linkset+json",
      "Cache-Control": "public, max-age=86400",
    });
  }

  // /.well-known/mcp-registry-auth — proves control of nessgate.com to the
  // official MCP Registry (HTTP domain auth) so the "com.nessgate/*" namespace
  // can be published. Holds only the Ed25519 PUBLIC key; the private key never
  // leaves the operator's machine. Served with no extension, hence an explicit
  // route (static assets need a recognized type).
  if (path === "/.well-known/mcp-registry-auth") {
    return new Response("v=MCPv1; k=ed25519; p=dypLCrlHTOErhb8mLhd67kAW15Vd5M/TJ5cGNvkxVFM=\n", {
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" },
    });
  }

  // MCP server (Streamable HTTP, stateless). One read-only tool, so GET has no
  // stream to offer and every POST is answered with a single JSON response.
  if (path === "/mcp") {
    if (request.method === "POST") return mcpEndpoint(request, env, ctx);
    return json({ error: "Use POST with JSON-RPC (MCP Streamable HTTP transport)." }, 405, {
      ...cors(),
      Allow: "POST, OPTIONS",
    });
  }

  // Retired paths from earlier iterations (paid setup, the ownership registry).
  // NessGate is now purely the free, neutral resolver — send lingering links
  // to the guide rather than 404.
  if (path === "/setup" || path === "/setup.js") {
    return Response.redirect(`${url.origin}/guide`, 301);
  }

  if (path.startsWith("/discover/") && request.method === "GET") {
    return apiDiscover(decodeURIComponent(path.slice("/discover/".length)), env, ctx, request);
  }
  if (path.startsWith("/explore/") && request.method === "GET") {
    return apiExplore(decodeURIComponent(path.slice("/explore/".length)), env, ctx, request, []);
  }
  if (path.startsWith("/explore/") && request.method === "POST") {
    // Opt-in candidate verification: the caller's AI/search POSTs candidate URLs;
    // NessGate verifies them deterministically and labels them evidence:"candidate".
    let candidates = [];
    try {
      const b = await request.json();
      if (b && Array.isArray(b.candidates)) candidates = b.candidates;
    } catch {}
    return apiExplore(decodeURIComponent(path.slice("/explore/".length)), env, ctx, request, candidates);
  }
  if (path === "/version" && request.method === "GET") {
    return json({ build: env.BUILD_ID || "dev", spec: "v1" }, 200, cors());
  }
  if (path === "/sitemap.xml" && request.method === "GET") return sitemapStatic(env.BASE_URL || url.origin);
  if (path === "/sitemaps/static.xml" && request.method === "GET") return sitemapStatic(env.BASE_URL || url.origin);

  // Static assets (run_worker_first is enabled, so the worker serves them;
  // /favicon.ico and all brand icons are real assets in public/)
  if (request.method === "GET" || request.method === "HEAD") {
    const assetRes = await env.ASSETS.fetch(request);
    if (assetRes.status !== 404) return assetRes;
  }

  // Human-readable page: /example.com — the resolver in action (live discovery).
  // Skip segments that look like a static file (…/foo.json, .xml, .js, …) so a
  // missing asset or a retired endpoint 404s instead of being resolved as a
  // bogus "domain". None of these extensions is a real TLD.
  const seg = decodeURIComponent(path.slice(1));
  const looksLikeFile = /\.(json|xml|txt|js|mjs|css|png|jpe?g|gif|svg|ico|webmanifest|map|woff2?|pdf|wasm|html?)$/i.test(seg);
  if (request.method === "GET" && seg && !seg.includes("/") && seg.includes(".") && !looksLikeFile) {
    return domainPage(seg, url.origin, env, ctx, request);
  }

  return htmlResponse(
    pageHtml({
      title: "Not found — NessGate",
      body: `<h1>Not found</h1><p><a href="/">Back to NessGate</a></p>`,
    }),
    404
  );
}

/* ---------------------- Discovery — the resolver ---------------------- */
// GET /discover/{domain} — on-request observation of what the domain itself
// publishes at standard machine-discovery locations, normalized into one
// answer. Pure description: no storage, no index, no background crawling — the
// answer is computed fresh and dies with its 10-minute edge cache. Per-probe
// failures are simply "not listed" (fail-open is correct here because this
// endpoint makes no ownership claim; it reports what the domain serves and
// links back to each source so the caller can verify).

// The universal-resolver adapter set: the standard machine-discovery locations
// NessGate reads and normalizes into one answer. Each entry lists one or more
// candidate paths (some standards have more than one known location); the first
// that returns valid content wins. NessGate READS these — it does not define
// them — so a new standard is just a new entry here, never a competing format.
// The universal-resolver adapter set. Each adapter reads ONE discovery channel
// and normalizes what it finds. NessGate READS these; it never defines them, so
// a new mechanism is a new adapter, never a competing format. Channels:
//   well-known — GET fixed path(s) on the domain
//   link-rel   — parse <link rel> in the domain's homepage, then GET the target
//   robots     — parse an Agentmap directive in /robots.txt, then GET the target
//   dns        — DoH query a well-known TXT node
const ADAPTERS = [
  { id: "llms.txt", channel: "well-known", paths: ["/llms.txt"], kind: "text" },
  { id: "ard-catalog", channel: "well-known", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" }, // Agentic Resource Discovery
  { id: "a2a-agent-card", channel: "well-known", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" }, // A2A
  { id: "api-catalog", channel: "well-known", paths: ["/.well-known/api-catalog"], kind: "json" }, // RFC 9727
  { id: "ai-info.json", channel: "well-known", paths: ["/ai-info.json"], kind: "json" },
  { id: "openapi", channel: "well-known", paths: ["/openapi.json"], kind: "json" },
  { id: "ord", channel: "well-known", paths: ["/.well-known/open-resource-discovery"], kind: "json" }, // Open Resource Discovery
  { id: "awp", channel: "well-known", paths: ["/.well-known/awp.json"], kind: "json" }, // AWP manifest (provisional)
  { id: "host-meta", channel: "well-known", paths: ["/.well-known/host-meta.json"], kind: "json" }, // RFC 6415
  { id: "anp", channel: "well-known", paths: ["/.well-known/agent-descriptions"], kind: "json" }, // Agent Network Protocol
  { id: "ucp", channel: "well-known", paths: ["/.well-known/ucp", "/.well-known/ucp/manifest.json"], kind: "json" }, // Universal Commerce Protocol
  { id: "ard-link", channel: "link-rel", rels: ["ard", "ai-catalog"], normalizeAs: "ard-catalog" }, // ARD via <link rel="ard">
  { id: "ard-agentmap", channel: "robots", directive: "agentmap", normalizeAs: "ard-catalog" }, // ARD via robots.txt Agentmap:
  { id: "aid", channel: "dns", node: "_agent" }, // AID: TXT record (v=aid1) at _agent.<domain>. NOT the IETF DNS-AID draft (that is SVCB at _agents.<domain> — a separate mechanism, not implemented here).
];
// GB/Z 185 (China, 智能体互联). NessGate normalizes GB/Z 185.4 agent
// descriptions ("ACS") by CONTENT (see isAcs/normalizeAcs) — an ACS served at
// the agent-description location above is labelled `gbz-185-4`. There is NO GB/Z
// discovery adapter here: 185.5 is a FEDERATED gateway service with no
// domain-native path, so guessing a /.well-known location would be fake
// conformance. 185.5 gateway querying exists ONLY in the embeddable library
// (opts.gbz — caller-configured URL + bring-your-own auth, no auto-discovery);
// it is deliberately never run by this hosted worker.
const DISCOVER_CACHE_SECONDS = 600;
const DISCOVER_RATE_LIMIT_PER_HOUR = 120;
const DISCOVER_UA = "NessGate-Discover/1.0 (+https://nessgate.com)";
const MAX_DISCOVER_RESOURCES = 200; // cap on the normalized resource list
const MAX_PER_SOURCE = 50; // cap per source document (defends against huge files)
const MAX_LINKED_CATALOGS = 5; // cap on link-rel / Agentmap catalog follows
const DISCOVER_NOTE =
  "These locations are published by the domain itself at standard discovery surfaces. " +
  "NessGate reads them as-is and links back to each source (sourceUrl) so a client can " +
  "always verify against the domain directly. NessGate makes no ownership or safety claim.";

// Reject catch-all rewrites: SPA hosts return 200 + their HTML shell for every
// path, which would otherwise report ghost files across half the modern web.
function validateProbeContent(kind, text) {
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

// Beyond "is it valid JSON" (validateProbeContent), confirm the document
// actually looks like the standard we probed for — so a JSON catch-all (e.g. a
// host returning {} for every unknown path) is not reported as a false
// positive. ai-info.json (informal) and ORD (variable enterprise schema) accept
// any object; the rest require their standard's signature field.
function probeShapeOk(type, kind, text) {
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
    case "gbz-185-4": return isAcs(obj); // GB/Z 185.4 ACS agent description
    default: return true;
  }
}

// Self-probes are answered by dispatching the probe path through our own
// router in-process — byte-identical to what an external client would fetch,
// with no network round-trip and no worker-fetching-itself recursion
// (safeFetch keeps refusing nessgate.com as defense in depth). None of the
// probe paths is /discover, so the dispatch cannot loop.
async function selfProbe(path, env, ctx) {
  const res = await route(new Request(`https://${SELF_DOMAIN}${path}`), env, ctx);
  if (res.status !== 200) throw new Error(`the URL returned HTTP ${res.status}`);
  return res.text();
}

/* --- Pure parsers for the non-well-known channels (parity-tested) --- */

// Extract href values from <link rel="..."> tags whose rel matches any of `rels`.
function parseLinkRel(html, rels) {
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
function parseAgentmap(robots, directive) {
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
function parseAidRecord(txt) {
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

/* --- Worker fetch helpers (centralised SSRF via safeFetch / self-dispatch) --- */

// Fetch a path (or an absolute on-domain URL) as text. safeFetch enforces
// on-domain hosts (incl. subdomains), HTTPS, public DNS, size and redirect caps.
async function getOnDomain(domain, pathOrUrl, env, ctx) {
  const isUrl = /^https?:\/\//i.test(pathOrUrl);
  if (domain === SELF_DOMAIN) {
    if (isUrl) {
      const u = new URL(pathOrUrl);
      if (u.hostname.toLowerCase().replace(/\.+$/, "") !== SELF_DOMAIN) throw new Error("off-domain");
      return selfProbe(u.pathname + u.search, env, ctx);
    }
    return selfProbe(pathOrUrl, env, ctx);
  }
  const url = isUrl ? pathOrUrl : `https://${domain}${pathOrUrl}`;
  return safeFetch(url, domain, MAX_JSON_BYTES, false, DISCOVER_UA);
}

// DoH TXT lookup for the DNS channel. Queries Cloudflare's public resolver.
async function dohTxt(name) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
      { headers: { Accept: "application/dns-json" }, cf: { cacheTtl: 60 } }
    );
    if (!res.ok) return [];
    const data = await res.json();
    const out = [];
    for (const a of data.Answer || []) {
      if (a.type !== 16) continue; // TXT
      out.push(String(a.data).replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
    }
    return out;
  } catch {
    return [];
  }
}

// GB/Z 185.4 (China, 智能体互联) agent description ("ACS"). Structurally an
// A2A-family agent card plus GB/Z extensions: an agent identity code (`aic`), an
// mTLS security scheme, a `certificate` block, and a Chinese-licensed provider.
// Recognised by CONTENT, never by a guessed path — NessGate normalizes an ACS
// wherever it legitimately encounters one (at the agent-description location it
// already reads; and, in the embeddable library only, from a caller-configured
// GB/Z 185.5 discovery gateway). It defines no GB/Z-specific location of its own.
function isAcs(obj) {
  if (!obj || typeof obj !== "object") return false;
  const marker =
    Object.prototype.hasOwnProperty.call(obj, "aic") ||
    (obj.certificate && typeof obj.certificate === "object" && obj.certificate.requestedValidity !== undefined);
  if (!marker) return false;
  return !!(typeof obj.name === "string" || Array.isArray(obj.skills) || (obj.capabilities && typeof obj.capabilities === "object"));
}

// Map a GB/Z 185.4 ACS document into NessGate's normalized record, preserving the
// GB/Z-specific fields (aic, provider, securitySchemes, certificate, skills) and
// provenance. One ACS describes one agent → one record.
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

// Normalize one fetched standard document into a flat list of resource records.
// Deliberately THIN: NessGate reuses each source's OWN labels (ARD media types,
// host-meta/link rel, AWP protocol keys) and never invents a taxonomy of its
// own. Every record carries `source` (which standard), `sourceUrl` (the native
// document it came from — always follow this to verify against the domain), and
// `raw` (the original record) where useful. Never throws; returns [] on anything
// unexpected so a malformed file can never break resolution.
function normalizeResources(type, kind, text, sourceUrl) {
  try {
    const rec = (r) => ({ source: type, sourceUrl, ...r });
    if (kind !== "json") {
      // Text standards (llms.txt): point to the file itself; do not parse prose.
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
        // ARD / ai-catalog.json: {entries:[{type(media type), url|data, displayName, identifier}]}.
        // An ARD entry carries EITHER a url OR inline data; keep both (an inline
        // entry points back to the catalog itself as its source).
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
        // RFC 6415 JRD: {links:[{rel, type, href}]}
        const links = Array.isArray(obj.links) ? obj.links : [];
        return cap(
          links.map((l) =>
            l && str(l.href) ? rec({ type: str(l.type) || str(l.rel) || "link", rel: str(l.rel), url: l.href, raw: l }) : null
          )
        );
      }
      case "api-catalog": {
        // RFC 9727 linkset: {linkset:[{anchor, <rel>:[{href,type}], ...}]}
        const contexts = Array.isArray(obj.linkset) ? obj.linkset : [];
        const out = [];
        for (const ctx of contexts) {
          if (!ctx || typeof ctx !== "object") continue;
          for (const [rel, val] of Object.entries(ctx)) {
            if (!Array.isArray(val)) continue; // skip "anchor" and other scalars
            for (const link of val) {
              if (link && str(link.href)) out.push(rec({ type: str(link.type) || rel, rel, url: link.href, raw: link }));
            }
          }
        }
        return cap(out);
      }
      case "awp": {
        // Agent Web Protocol manifest: a `protocols` block routing to sibling
        // standards. Schema varies; extract defensively (object map or array).
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
        // GB/Z 185.4 ACS agent description (used when the doc arrives already
        // typed as GB/Z, e.g. from the optional 185.5 gateway in the library).
        return normalizeAcs(obj, sourceUrl);
      case "a2a-agent-card": {
        // A GB/Z 185.4 ACS is an A2A-family card with GB/Z extensions and may be
        // served at the agent-description location NessGate already reads; label
        // it correctly rather than as plain A2A. No GB/Z-specific path is guessed.
        if (isAcs(obj)) return normalizeAcs(obj, sourceUrl);
        // A2A agent card. v1.0 removed the top-level `url` and moved endpoints
        // into supportedInterfaces[]; accept either, preferring an explicit
        // top-level url, then the first interface url, then the card itself.
        const ifaces = Array.isArray(obj.supportedInterfaces) ? obj.supportedInterfaces : [];
        const ifaceUrl = ifaces.map((i) => (i ? str(i.url) : undefined)).find(Boolean);
        return [rec({ type: "a2a-agent-card", name: str(obj.name), url: str(obj.url) || ifaceUrl || sourceUrl, raw: { name: str(obj.name), description: str(obj.description), version: str(obj.version), url: str(obj.url), supportedInterfaces: ifaces.length ? ifaces : undefined } })];
      }
      case "openapi": {
        return [rec({ type: "openapi", name: obj.info && str(obj.info.title), url: sourceUrl })];
      }
      case "anp": {
        // ANP agent-descriptions: JSON-LD CollectionPage {items:[{@id, name}]}.
        const items = Array.isArray(obj.items) ? obj.items : [];
        return cap(
          items.map((it) =>
            it && str(it["@id"]) ? rec({ type: "agent-description", name: str(it.name), url: it["@id"], raw: it }) : null
          )
        );
      }
      case "ucp": {
        // UCP merchant profile: {capabilities:[...]} with transport bindings.
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
      // ai-info.json (loose), ord (rich enterprise schema): point to the file
      // itself rather than impose an interpretation on it.
      default:
        return [rec({ type, url: sourceUrl })];
    }
  } catch {
    return [];
  }
}

// Core resolver: returns the normalized answer object for a domain (or an
// {error} object). Shared by the REST endpoint, the MCP tool, and the
// human-readable domain page so all three can never disagree.
// Run one adapter over its channel and return {discovered, resources}. Every
// failure collapses to [] so a single bad channel never breaks resolution.
async function runAdapter(a, domain, env, ctx) {
  try {
    if (a.channel === "well-known") {
      for (const path of a.paths) {
        let text;
        try { text = await getOnDomain(domain, path, env, ctx); } catch { continue; }
        if (validateProbeContent(a.kind, text) && probeShapeOk(a.id, a.kind, text)) {
          const url = `https://${domain}${path}`;
          return { discovered: [{ type: a.id, url }], resources: normalizeResources(a.id, a.kind, text, url) };
        }
      }
      return { discovered: [], resources: [] };
    }
    if (a.channel === "link-rel" || a.channel === "robots") {
      const src = a.channel === "link-rel" ? "/" : "/robots.txt";
      let doc;
      try { doc = await getOnDomain(domain, src, env, ctx); } catch { return { discovered: [], resources: [] }; }
      const targets = a.channel === "link-rel" ? parseLinkRel(doc, a.rels) : parseAgentmap(doc, a.directive);
      const discovered = [], resources = [];
      for (const t of targets.slice(0, MAX_LINKED_CATALOGS)) {
        let abs;
        try { abs = new URL(t, `https://${domain}/`).toString(); } catch { continue; }
        let text;
        try { text = await getOnDomain(domain, abs, env, ctx); } catch { continue; } // safeFetch keeps it on-domain
        if (validateProbeContent("json", text) && probeShapeOk(a.normalizeAs, "json", text)) {
          discovered.push({ type: a.id, url: abs });
          resources.push(...normalizeResources(a.normalizeAs, "json", text, abs));
        }
      }
      return { discovered, resources };
    }
    if (a.channel === "dns") {
      const name = `${a.node}.${domain}`;
      let records = [];
      try { records = await dohTxt(name); } catch { records = []; }
      const discovered = [], resources = [];
      for (const rec of records) {
        const aid = parseAidRecord(rec);
        if (aid) {
          discovered.push({ type: a.id, url: aid.uri });
          resources.push({ source: "aid", sourceUrl: `dns:${name}`, type: aid.proto || "aid", name: aid.desc, url: aid.uri, raw: aid });
        }
      }
      return { discovered, resources };
    }
    return { discovered: [], resources: [] };
  } catch {
    return { discovered: [], resources: [] };
  }
}

async function discoverData(raw, env, ctx, request) {
  const domain = normalizeDomain(raw, true);
  if (!domain) return { status: 400, body: { error: "Invalid domain" } };
  const cache = caches.default;
  const key = new Request(`https://resolver-cache.nessgate.com/discover/${domain}`);
  const hit = await cache.match(key);
  if (hit) return { status: 200, body: await hit.json(), cached: true };
  if (!(await rateLimit(env, request, "disc", DISCOVER_RATE_LIMIT_PER_HOUR))) {
    return { status: 429, body: { error: "Too many requests. Please try again later." } };
  }
  // Run every adapter in parallel; merge the routing map (discovered) and the
  // normalized union (resources). Each adapter is self-contained per channel.
  const settled = await Promise.allSettled(ADAPTERS.map((a) => runAdapter(a, domain, env, ctx)));
  const results = settled.map((r) => (r.status === "fulfilled" && r.value ? r.value : { discovered: [], resources: [] }));
  const discovered = results.flatMap((r) => r.discovered);
  const resources = results.flatMap((r) => r.resources).slice(0, MAX_DISCOVER_RESOURCES);
  const body = {
    domain,
    provenance: "self-published",
    note: DISCOVER_NOTE,
    discovered,
    resources,
    checked: ADAPTERS.map((a) => a.id),
  };
  const res = new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${DISCOVER_CACHE_SECONDS}` },
  });
  if (ctx) ctx.waitUntil(cache.put(key, res));
  return { status: 200, body };
}

async function apiDiscover(raw, env, ctx, request) {
  const { status, body } = await discoverData(raw, env, ctx, request);
  const extra =
    status === 200 ? { ...cors(), "Cache-Control": `public, max-age=${DISCOVER_CACHE_SECONDS}` } : cors();
  return json(body, status, extra);
}

/* -------------------- Explore — bounded delegated discovery (v2) -------------------- */
// GET /explore/{domain} — /discover plus deterministic DELEGATED discovery. It
// keeps the exact-host answer (evidence "publisher-hosted") and then follows the
// EXPLICIT machine-readable pointers a hosted document declares (an llms.txt
// index, an ARD entry, an api-catalog link, …) up to a bounded depth — across
// hosts only because the publisher itself named the target (evidence
// "publisher-declared"). Every record carries a provenance chain. It is strictly
// bounded (EXPLORE_LIMITS) so a malicious publisher cannot turn NessGate into an
// SSRF/amplification proxy; it guesses no hosts or paths, stores nothing, runs no
// AI, and makes no ownership claim. /discover is unchanged for existing callers.
const EXPLORE_LIMITS = { maxDepth: 2, maxHosts: 8, maxRequests: 24, maxTotalBytes: 6_000_000 };
const MAX_CANDIDATES = 10; // cap on opt-in caller-supplied candidate URLs to verify (subrequest budget)
const EXPLORE_UA = "NessGate-Explore/1.0 (+https://nessgate.com)";
const EXPLORE_RATE_LIMIT_PER_HOUR = 60;
const EXPLORE_NOTE =
  "Exact-host results are served by the domain itself (publisher-hosted). Delegated results were " +
  "reached by following explicit machine-readable pointers the domain published (publisher-declared); " +
  "each carries a provenance chain. NessGate follows only what a document explicitly names — it never " +
  "guesses hosts or paths, stores nothing, runs no AI, and makes no ownership claim.";

// Pure: extract candidate URLs from an llms.txt document (markdown links + bare).
function parseLlmsLinks(text) {
  if (typeof text !== "string") return [];
  const urls = new Set();
  for (const m of text.match(/\]\((https?:\/\/[^)\s]+)\)/g) || []) urls.add(m.slice(2, -1));
  for (const b of text.match(/https?:\/\/[^\s)<>"'\]]+/g) || []) urls.add(b.replace(/[.,;]+$/, ""));
  return [...urls];
}

// Pure: is this URL specifically an llms.txt index (the only .txt we parse)?
function isLlmsPath(url) {
  let p;
  try { p = new URL(url).pathname.toLowerCase(); } catch { return false; }
  return p.endsWith("/llms.txt") || p.endsWith("/llms-full.txt");
}

// Pure: does this URL look like a machine-readable resource worth following?
// Only JSON, well-known paths, and llms.txt/llms-full.txt — NOT arbitrary .txt
// (a random security.txt/robots-style file is not a discovery index).
function looksMachineReadable(url) {
  let p;
  try { p = new URL(url).pathname.toLowerCase(); } catch { return false; }
  return /\.json$/.test(p) || p.includes("/.well-known/") || isLlmsPath(url);
}

// Pure, testable budget accounting for one Explore fetch. Adds every host the
// fetch touched (including redirect hops) to the host budget and the bytes to the
// global byte budget; flips `truncated` when either cap is exceeded. Returns
// whether exploration may continue.
function exploreBudgetAllows(budget, meta, limits) {
  for (const h of meta.hosts || []) budget.hosts.add(h);
  budget.bytes = (budget.bytes || 0) + (meta.bytes || 0);
  if (budget.hosts.size > limits.maxHosts || budget.bytes > limits.maxTotalBytes) budget.truncated = true;
  return !budget.truncated;
}

// Pure: classify a fetched JSON document as one known standard type (or null).
// Most-specific first so a card that also carries a name isn't mislabelled.
function classifyJson(text) {
  let obj;
  try { obj = JSON.parse(text); } catch { return null; }
  if (!obj || typeof obj !== "object") return null;
  for (const t of ["ard-catalog", "api-catalog", "openapi", "anp", "ucp", "host-meta", "awp", "gbz-185-4"]) {
    if (probeShapeOk(t, "json", text)) return t;
  }
  // A2A only when the doc has A2A-specific structure. A bare {name}/{url} document
  // (e.g. an ai-info.json profile) must NOT be mislabelled as an agent card — for
  // a followed document, missing it is far better than inventing a wrong type.
  if (Array.isArray(obj.supportedInterfaces) || (obj.capabilities && Array.isArray(obj.skills))) return "a2a-agent-card";
  return null;
}

// Pure: verify one fetched candidate document into evidence:"candidate" records —
// empty unless it is genuinely a recognized machine-readable resource (an
// llms.txt index or a classifiable JSON standard). NessGate confirms the
// resource's existence/type, never its relationship to any domain.
function verifyCandidateRecords(url, text) {
  const prov = ["ai-candidate", url];
  if (isLlmsPath(url)) return [{ source: "llms.txt", sourceUrl: url, type: "llms.txt", url, evidence: "candidate", provenance: prov, depth: 1 }];
  const t = classifyJson(text);
  if (!t) return [];
  return normalizeResources(t, "json", text, url).map((rec) => ({ ...rec, evidence: "candidate", provenance: prov, depth: 1 }));
}

// Attributed MCP Registry federation. The official registry domain-authenticates
// its "com.<reverse-domain>" namespaces, so a com.<domain>/* server is strong,
// INDEPENDENT evidence that the domain owner published it. NessGate reports this
// with class "namespace-verified" and always ATTRIBUTES the verification to the
// registry — it never re-claims the registry's check as its own.
const MCP_REGISTRY_API = "https://registry.modelcontextprotocol.io/v0.1/servers";

// Pure: reverse a domain into its MCP Registry reverse-DNS namespace (example.com
// -> com.example). Only exact-domain namespaces are federated (no PSL/registrable
// guessing), so a subdomain resolves to its own literal namespace.
function domainToNamespace(domain) {
  if (typeof domain !== "string" || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(domain)) return null;
  return domain.toLowerCase().split(".").reverse().join(".");
}

// Pure: extract namespace-verified MCP servers from a registry response for the
// EXACT namespace. Skips non-active entries. Every record is attributed to the
// registry; a github-authed (io.github.*) name can never match a com.<domain>
// namespace, so matches here are genuinely domain-authenticated.
function mcpRegistryRecords(json, namespace, domain) {
  let obj = json;
  if (typeof json === "string") { try { obj = JSON.parse(json); } catch { return []; } }
  const servers = obj && Array.isArray(obj.servers) ? obj.servers : [];
  const prefix = namespace + "/";
  const src = MCP_REGISTRY_API + "?search=" + encodeURIComponent(namespace);
  const out = [];
  for (const entry of servers) {
    const s = (entry && entry.server) || entry;
    if (!s || typeof s.name !== "string" || !s.name.startsWith(prefix)) continue;
    const meta = entry && entry._meta && entry._meta["io.modelcontextprotocol.registry/official"];
    if (meta && meta.status && meta.status !== "active") continue;
    const remotes = Array.isArray(s.remotes) ? s.remotes : [];
    const remote = remotes.find((r) => r && typeof r.url === "string");
    const url = (remote && remote.url) || (s.repository && typeof s.repository.url === "string" ? s.repository.url : null);
    out.push({
      source: "mcp-registry",
      sourceUrl: src,
      type: "mcp-server",
      name: s.name,
      url: url || null,
      evidence: "namespace-verified",
      attribution: `Listed in the official MCP Registry, which verified control of the namespace "${namespace}" (the reverse-DNS of ${domain}). NessGate did not verify this itself.`,
      provenance: [`mcp-registry:${namespace}`, s.name],
      depth: 0,
      raw: {
        version: typeof s.version === "string" ? s.version : undefined,
        description: typeof s.description === "string" ? s.description : undefined,
      },
    });
  }
  return out;
}

// One bounded request to the MCP Registry (a fixed, trusted read API — not a
// publisher-controlled host, so no SSRF surface). Its full-text search is slow for
// very large namespaces (io.github.* can take >20s), so this uses a short timeout
// and degrades gracefully to "" — federation is best-effort, never a hang.
const REGISTRY_TIMEOUT_MS = 5000;
async function fetchMcpRegistry(namespace) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REGISTRY_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(`${MCP_REGISTRY_API}?search=${encodeURIComponent(namespace)}&limit=50`, {
        headers: { Accept: "application/json", "User-Agent": EXPLORE_UA },
        signal: ctrl.signal,
        cf: { cacheTtl: 300 },
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return "";
    return await res.text();
  } catch {
    return "";
  }
}

async function exploreData(raw, env, ctx, request, candidates = []) {
  const domain = normalizeDomain(raw, true);
  if (!domain) return { status: 400, body: { error: "Invalid domain" } };
  const hasCandidates = Array.isArray(candidates) && candidates.length > 0;
  const cache = caches.default;
  const key = new Request(`https://resolver-cache.nessgate.com/explore/${domain}`);
  // Candidate requests are per-body and never cached (input varies per call).
  const hit = hasCandidates ? null : await cache.match(key);
  if (hit) return { status: 200, body: await hit.json(), cached: true };
  if (!(await rateLimit(env, request, "explore", EXPLORE_RATE_LIMIT_PER_HOUR))) {
    return { status: 429, body: { error: "Too many requests. Please try again later." } };
  }

  const budget = { requests: 0, bytes: 0, hosts: new Set(), seen: new Set(), truncated: false };
  const out = [];
  const rootUrl = `https://${domain}/`;

  // Attributed MCP Registry federation — ISSUED FIRST (so it grabs an early
  // subrequest slot before exact-host/delegated fetches can exhaust Cloudflare's
  // per-invocation cap), run CONCURRENTLY with the rest (no added latency), and
  // awaited at the end. Short-timeout + best-effort, so a slow namespace never
  // stalls /explore.
  const namespace = domainToNamespace(domain);
  const registryPromise = namespace ? fetchMcpRegistry(namespace) : Promise.resolve("");

  // Bounded, SSRF-safe fetch of a single delegated URL (cross-host allowed because
  // the publisher named it; self is dispatched in-process).
  // Returns { text, finalUrl } (finalUrl may differ from url after redirects) or
  // null. Counts requests, and — via exploreBudgetAllows — every host touched
  // (including redirect hops) and the bytes fetched against the global budgets.
  async function fetchDoc(url) {
    let host;
    try { host = new URL(url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return null; }
    if (budget.seen.has(url)) return null;
    budget.seen.add(url);
    if (budget.truncated || budget.requests >= EXPLORE_LIMITS.maxRequests) { budget.truncated = true; return null; }
    if (!budget.hosts.has(host) && budget.hosts.size >= EXPLORE_LIMITS.maxHosts) { budget.truncated = true; return null; }
    budget.requests++;
    try {
      if (domain === SELF_DOMAIN && host === SELF_DOMAIN) {
        const u = new URL(url);
        const text = await selfProbe(u.pathname + u.search, env, ctx);
        exploreBudgetAllows(budget, { hosts: [host], bytes: text.length }, EXPLORE_LIMITS);
        budget.seen.add(u.toString());
        return { text, finalUrl: u.toString() };
      }
      const meta = await safeFetch(url, domain, MAX_JSON_BYTES, false, EXPLORE_UA, true, true);
      exploreBudgetAllows(budget, meta, EXPLORE_LIMITS); // counts redirect hosts + bytes
      budget.seen.add(meta.finalUrl); // the resolved URL is now accounted for
      return { text: meta.text, finalUrl: meta.finalUrl };
    } catch {
      return null;
    }
  }

  // Add records for one fetched doc (keyed by its FINAL url) and return the
  // pointers it explicitly names. Only a real llms.txt/llms-full.txt is parsed as
  // an index; a followed .json is classified; any other followed .txt is recorded
  // as a plain text pointer (never mislabelled llms.txt), with no link parsing.
  function ingest(url, text, provenance, depth) {
    const follow = [];
    if (isLlmsPath(url)) {
      out.push({ source: "llms.txt", sourceUrl: url, type: "llms.txt", url, evidence: "publisher-declared", provenance, depth });
      for (const link of parseLlmsLinks(text).slice(0, MAX_PER_SOURCE)) if (looksMachineReadable(link)) follow.push(link);
      return follow;
    }
    const t = classifyJson(text);
    if (t) {
      for (const rec of normalizeResources(t, "json", text, url)) {
        out.push({ ...rec, evidence: "publisher-declared", provenance, depth });
        if (rec.url && rec.url !== url && looksMachineReadable(rec.url)) follow.push(rec.url);
      }
      return follow;
    }
    let path = "";
    try { path = new URL(url).pathname.toLowerCase(); } catch {}
    if (path.endsWith(".txt")) {
      out.push({ source: "text", sourceUrl: url, type: "generic-text", url, evidence: "publisher-declared", provenance, depth });
    }
    return follow;
  }

  async function walk(url, depth, provenance) {
    const doc = await fetchDoc(url);
    if (!doc) return;
    // If a redirect moved the content to a different final URL, provenance and the
    // record's source reflect that final URL — never the pre-redirect one.
    const prov = doc.finalUrl && doc.finalUrl !== url ? [...provenance, doc.finalUrl] : provenance;
    const follow = ingest(doc.finalUrl, doc.text, prov, depth);
    if (depth < EXPLORE_LIMITS.maxDepth) {
      for (const t of follow) if (!budget.seen.has(t)) await walk(t, depth + 1, [...prov, t]);
    }
  }

  // Phase 1 — exact host (same adapters as /discover), tagged by evidence.
  const settled = await Promise.allSettled(ADAPTERS.map((a) => runAdapter(a, domain, env, ctx)));
  const results = settled.map((r) => (r.status === "fulfilled" && r.value ? r.value : { discovered: [], resources: [] }));
  const exactResources = results.flatMap((r) => r.resources);
  const discovered = results.flatMap((r) => r.discovered);
  for (const rec of exactResources) {
    const hosted = rec.url === rec.sourceUrl; // the served document itself
    out.push({
      ...rec,
      evidence: hosted ? "publisher-hosted" : "publisher-declared",
      provenance: hosted ? [rec.url] : [rec.sourceUrl, rec.url].filter(Boolean),
      depth: 0,
    });
  }

  // Phase 2 — follow explicit pointers (depth 1..maxDepth).
  const targets = []; // { url, chain }
  const llms = discovered.find((d) => d.type === "llms.txt");
  if (llms) {
    const doc = await fetchDoc(llms.url);
    if (doc) for (const link of parseLlmsLinks(doc.text).slice(0, MAX_PER_SOURCE)) {
      if (looksMachineReadable(link)) targets.push({ url: link, chain: [doc.finalUrl, link] });
    }
  }
  for (const rec of exactResources) {
    if (rec.url && rec.url !== rec.sourceUrl && looksMachineReadable(rec.url)) {
      targets.push({ url: rec.url, chain: [rec.sourceUrl, rec.url].filter(Boolean) });
    }
  }
  for (const { url, chain } of targets) {
    if (budget.requests >= EXPLORE_LIMITS.maxRequests) { budget.truncated = true; break; }
    await walk(url, 1, chain);
  }

  // Merge the concurrent registry federation (namespace-verified evidence).
  const regText = await registryPromise;
  if (namespace && regText) for (const rec of mcpRegistryRecords(regText, namespace, domain)) out.push(rec);

  // Phase 4 — OPTIONAL candidate verification (opt-in via POST body). NessGate
  // runs NO AI itself and stores nothing: the caller's AI/search supplies the
  // candidate URLs, and NessGate fetches each (bounded, SSRF-safe) and verifies it
  // is a real machine-readable resource. A verified candidate is labelled
  // evidence:"candidate" — its RELATIONSHIP to the domain is UNVERIFIED and
  // NessGate makes no ownership claim; only its existence/type is confirmed.
  if (hasCandidates) {
    for (const cand of candidates.slice(0, MAX_CANDIDATES)) {
      if (typeof cand !== "string") continue;
      let cu;
      try { cu = new URL(cand); } catch { continue; }
      if (cu.protocol !== "https:") continue;
      const doc = await fetchDoc(cand);
      if (!doc) continue;
      for (const rec of verifyCandidateRecords(doc.finalUrl, doc.text)) out.push(rec);
    }
  }

  // Dedup (source|url|sourceUrl), keep first (earliest/strongest evidence), cap.
  const seenRec = new Set();
  const resources = [];
  for (const r of out) {
    const k = `${r.source}|${r.url}|${r.sourceUrl}`;
    if (seenRec.has(k)) continue;
    seenRec.add(k);
    resources.push(r);
    if (resources.length >= MAX_DISCOVER_RESOURCES) break;
  }

  const body = {
    domain,
    note: EXPLORE_NOTE,
    checked: ADAPTERS.map((a) => a.id),
    resources,
    federated: ["mcp-registry"],
    stats: {
      publisherHosted: resources.filter((r) => r.evidence === "publisher-hosted").length,
      publisherDeclared: resources.filter((r) => r.evidence === "publisher-declared").length,
      namespaceVerified: resources.filter((r) => r.evidence === "namespace-verified").length,
      candidate: resources.filter((r) => r.evidence === "candidate").length,
      requests: budget.requests,
      hosts: budget.hosts.size,
      bytes: budget.bytes,
      truncated: budget.truncated,
    },
    limits: EXPLORE_LIMITS,
  };
  const res = new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${DISCOVER_CACHE_SECONDS}` },
  });
  if (ctx && !hasCandidates) ctx.waitUntil(cache.put(key, res));
  return { status: 200, body };
}

async function apiExplore(raw, env, ctx, request, candidates = []) {
  const { status, body } = await exploreData(raw, env, ctx, request, candidates);
  const hasCand = Array.isArray(candidates) && candidates.length > 0;
  const extra =
    status === 200
      ? { ...cors(), "Cache-Control": hasCand ? "no-store" : `public, max-age=${DISCOVER_CACHE_SECONDS}` }
      : cors();
  return json(body, status, extra);
}

/* ----------------------- MCP server (read-only tool) ----------------------- */
// POST /mcp — Model Context Protocol over Streamable HTTP, stateless JSON
// responses. Exposes the resolver as a tool so AI agents can call it directly
// instead of scraping it. Same rate limits and caches as the REST endpoint
// (the tool dispatches to the same handler).

const MCP_SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26"];
const MCP_SERVER_INFO = { name: "nessgate", title: "NessGate — the neutral resolver for the agentic web", version: "1.3.1" };
const MCP_INSTRUCTIONS =
  "Use discover_domain to resolve a domain to the machine-readable resources it publishes " +
  "across the supported discovery locations (ARD, A2A, llms.txt, API catalogs, OpenAPI, and " +
  "more), normalized into one answer with a link back to each source. No authentication required.";

const MCP_DOMAIN_INPUT = {
  type: "object",
  properties: { domain: { type: "string", description: "Registrable domain, e.g. example.com" } },
  required: ["domain"],
};

const MCP_TOOLS = [
  {
    name: "discover_domain",
    title: "Resolve a domain's machine-readable resources",
    description:
      "Given a domain, read whatever it publishes at the standard machine-discovery locations " +
      "(llms.txt, /.well-known/ard.json, /.well-known/agent-card.json, /.well-known/api-catalog, " +
      "ai-info.json, openapi.json, and more) and return one normalized answer. Each resource keeps a " +
      "sourceUrl pointing back to the domain so the caller can verify. NessGate reads the domain live " +
      "and stores nothing; it makes no ownership or safety claim.",
    inputSchema: MCP_DOMAIN_INPUT,
  },
];

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function mcpEndpoint(request, env, ctx) {
  const headers = { ...cors() };
  const msg = await readJsonBody(request);
  if (msg === null) return json(rpcError(null, -32700, "Parse error"), 400, headers);
  if (Array.isArray(msg)) {
    return json(rpcError(null, -32600, "Batching is not supported; send one message per request."), 400, headers);
  }
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return json(rpcError(null, -32600, "Invalid Request"), 400, headers);
  }
  // Notifications (no id member, e.g. notifications/initialized) are
  // acknowledged without a body, per the Streamable HTTP transport.
  if (!("id" in msg)) return new Response(null, { status: 202, headers });

  if (msg.method === "initialize") {
    const requested = msg.params && msg.params.protocolVersion;
    return json(
      rpcResult(msg.id, {
        protocolVersion: MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : MCP_SUPPORTED_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: MCP_SERVER_INFO,
        instructions: MCP_INSTRUCTIONS,
      }),
      200,
      headers
    );
  }
  if (msg.method === "ping") return json(rpcResult(msg.id, {}), 200, headers);
  if (msg.method === "tools/list") return json(rpcResult(msg.id, { tools: MCP_TOOLS }), 200, headers);
  if (msg.method === "tools/call") {
    const name = msg.params && msg.params.name;
    if (name !== "discover_domain") {
      return json(rpcError(msg.id, -32602, `Unknown tool: ${String(name)}`), 200, headers);
    }
    const args = (msg.params && msg.params.arguments) || {};
    let result;
    try {
      result = await mcpToolResult(args, env, ctx, request);
    } catch {
      result = {
        content: [{ type: "text", text: "Resolver temporarily unavailable. Please try again shortly." }],
        isError: true,
      };
    }
    return json(rpcResult(msg.id, result), 200, headers);
  }
  return json(rpcError(msg.id, -32601, `Method not found: ${msg.method}`), 200, headers);
}

// The tool dispatches to the same handler as the REST endpoint — one behavior,
// two transports.
async function mcpToolResult(args, env, ctx, request) {
  const domain = normalizeDomain(args.domain, true);
  if (!domain) {
    return {
      content: [{ type: "text", text: "Invalid domain. Provide a bare registrable domain like example.com." }],
      isError: true,
    };
  }
  const { status, body } = await discoverData(domain, env, ctx, request);
  const text = JSON.stringify(body, null, 2);
  const out = { content: [{ type: "text", text }], isError: status === 429 || status >= 500 };
  if (body && typeof body === "object" && !Array.isArray(body)) out.structuredContent = body;
  return out;
}

/* ------------------- Human-readable domain page ------------------- */
// GET /example.com — the resolver in action, rendered for humans (and good for
// SEO). Runs a live discovery and lists what the domain publishes, each with a
// link back to its source.
async function domainPage(raw, origin, env, ctx, request) {
  const domain = normalizeDomain(raw, true);
  if (!domain) {
    return htmlResponse(
      pageHtml({ title: "Not found — NessGate", body: `<h1>Not found</h1><p><a href="/">Back to NessGate</a></p>` }),
      404
    );
  }
  const base = env.BASE_URL || origin;
  const canonical = `${base}/${domain}`;
  const safeDomain = escapeHtml(domain);

  let body = null;
  try {
    ({ body } = await discoverData(domain, env, ctx, request));
  } catch {
    body = null;
  }
  const discovered = body && Array.isArray(body.discovered) ? body.discovered : [];

  if (discovered.length === 0) {
    return htmlResponse(
      pageHtml({
        title: `${safeDomain} — NessGate`,
        canonical,
        description: `${safeDomain} publishes no supported discovery files on this exact host; related product hosts or external registries may publish more.`,
        body:
          `<h1>${safeDomain}</h1>` +
          `<div class="panel"><p class="status no">No supported resources found on this exact host</p>` +
          `<p class="meta">NessGate checked the standard discovery locations on ${safeDomain} itself ` +
          `(ARD, A2A, llms.txt, API catalogs, OpenAPI and more) and found none. This is an exact-host ` +
          `result — related product hosts (e.g. a developer or docs subdomain) or external registries ` +
          `may still publish machine-readable resources.</p></div>` +
          `<p class="meta"><a href="/check">How to make a domain AI-discoverable →</a></p>`,
      }),
      200,
      { "Cache-Control": "public, max-age=600" }
    );
  }

  const items = discovered
    .map((r) => {
      const safeUrl = escapeHtml(r.url);
      const type = escapeHtml(r.type || "resource");
      return (
        `<div class="res">` +
        `<p class="label">${type}</p>` +
        `<p class="url"><a href="${safeUrl}" rel="nofollow">${safeUrl}</a></p>` +
        `</div>`
      );
    })
    .join("");
  return htmlResponse(
    pageHtml({
      title: `${safeDomain} — NessGate`,
      canonical,
      description: `The machine-readable resources ${safeDomain} publishes, resolved by NessGate into one answer.`,
      body:
        `<h1>${safeDomain}</h1>` +
        `<div class="panel">` +
        `<p class="status ok">${discovered.length} machine-readable ${discovered.length === 1 ? "resource" : "resources"} published</p>` +
        items +
        `<p class="meta">Read live from ${safeDomain} at standard well-known locations. ` +
        `NessGate stores nothing and makes no ownership claim. ` +
        `<a href="/discover/${safeDomain}" rel="nofollow">JSON</a>.</p>` +
        `</div>`,
    }),
    200,
    { "Cache-Control": "public, max-age=600" }
  );
}

/* ------------------------------- Sitemap ------------------------------- */
const STATIC_PAGES = [
  "", "check", "guide", "api", "spec", "charter", "changelog", "about", "privacy", "terms", "contact",
  "blog", "blog/state-of-ai-discovery-september-2026", "blog/what-is-ard-ai-catalog-json",
];

// /sitemap.xml — fixed set of NessGate pages; cached for 24 h. There is no
// registry, so there are no per-domain URLs to enumerate.
function sitemapStatic(base) {
  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    STATIC_PAGES.map((p) => `  <url><loc>${escapeHtml(`${base}/${p}`)}</loc></url>`).join("\n") +
    `\n</urlset>\n`;
  return new Response(xml, {
    headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=86400" },
  });
}

/* ------------------- Domain + URL validation, SSRF ------------------- */

const FORBIDDEN_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".in-addr.arpa", ".ip6.arpa"];

function isForbiddenHost(host) {
  if (host === "localhost" || host === "nessgate.com" || host.endsWith(".nessgate.com")) return true;
  if (host.includes(":")) return true; // IPv6 literal
  if (/^\d+(\.\d+){3}$/.test(host)) return true; // IPv4 literal
  return FORBIDDEN_SUFFIXES.some((s) => host.endsWith(s));
}

// allowSelf: the resolver accepts the apex self domain so nessgate.com can be
// resolved through its own probes (answered by in-process dispatch, never a
// network fetch of itself). nessgate.com subdomains stay rejected everywhere.
function normalizeDomain(input, allowSelf = false) {
  if (typeof input !== "string" || input.length > 300) return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme
  d = d.split("/")[0].split("?")[0].split("#")[0]; // path/query
  d = d.replace(/:\d+$/, ""); // port
  d = d.replace(/\.+$/, ""); // trailing dots
  if (d.startsWith("www.")) d = d.slice(4);
  if (d.length < 4 || d.length > 253) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) return null;
  const tld = d.split(".").pop();
  // Allow plain alphabetic TLDs (.com, .org, .uk …) and valid ACE/punycode TLDs
  // (xn-- followed by at least one alphanumeric, e.g. xn--p1ai for .рф).
  if (!/^([a-z]{2,}|xn--[a-z0-9]([a-z0-9-]*[a-z0-9])?)$/.test(tld)) return null;
  if (allowSelf && d === SELF_DOMAIN) return d;
  if (isForbiddenHost(d)) return null;
  return d;
}

function hostAllowedForDomain(host, domain) {
  return host === domain || host === `www.${domain}` || host.endsWith(`.${domain}`);
}

// Fetch constrained to the target domain: HTTPS only, public DNS only,
// redirects kept on-domain, capped size, short timeout. With strictHosts,
// every hop (including redirects) must stay on the apex of the domain.
async function safeFetch(url, allowedDomain, maxBytes, strictHosts = false, userAgent = "NessGate-Discover/1.0 (+https://nessgate.com)", allowCrossHost = false, returnMeta = false) {
  let current = url;
  const redirectChain = []; // every validated URL actually fetched, in order
  const hosts = new Set(); // every host touched, including via redirects
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const u = new URL(current);
    if (u.protocol !== "https:") throw new Error("only HTTPS is allowed");
    const host = u.hostname.toLowerCase().replace(/\.+$/, "");
    // allowCrossHost (used only by /explore for publisher-declared targets): drop
    // the on-domain restriction but keep EVERY other SSRF guard — no forbidden
    // hosts (localhost, self, IP literals, internal suffixes) and a public-DNS
    // check on this hop and every redirect below.
    const hostOk = allowCrossHost
      ? true
      : strictHosts
      ? host === allowedDomain
      : hostAllowedForDomain(host, allowedDomain);
    if (isForbiddenHost(host) || !hostOk) {
      throw new Error(allowCrossHost ? "target host is not allowed" : "request left the target domain");
    }
    await assertPublicDns(host);
    redirectChain.push(u.toString());
    hosts.add(host);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(u.toString(), {
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": userAgent,
          Accept: "application/json, text/plain;q=0.9, */*;q=0.1",
        },
        cf: { cacheTtl: 0 },
      });
    } catch {
      throw new Error("the URL could not be fetched (timeout or network error)");
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) throw new Error("redirect without a target");
      current = new URL(loc, u).toString();
      continue;
    }
    if (res.status !== 200) throw new Error(`the URL returned HTTP ${res.status}`);

    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error("the response is too large");
      }
      chunks.push(value);
    }
    const buf = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.length;
    }
    const text = new TextDecoder().decode(buf);
    // Explore mode needs the final URL (redirects can move content to another
    // host), every host touched (so redirect hosts count against the budget) and
    // the byte count (for the global byte budget). /discover callers get the
    // string unchanged.
    if (returnMeta) return { text, finalUrl: u.toString(), redirectChain, hosts: [...hosts], bytes: size };
    return text;
  }
  throw new Error("too many redirects");
}

// Isolate-scoped DNS check cache. Every safeFetch validates the host's IPs, and
// a single /discover or /explore touches the same host across many adapters — 2
// DoH lookups each would blow Cloudflare's 50-subrequest-per-invocation cap. A
// short-TTL cache collapses repeats to one check (the DNS-rebinding window this
// opens is already documented and immaterial: Worker egress has no private
// network, and probes assert nothing).
const DNS_CHECK_CACHE = new Map(); // host -> { ok, err, expires }
const DNS_CHECK_TTL_MS = 60_000;

async function assertPublicDns(host) {
  const now = Date.now();
  const cached = DNS_CHECK_CACHE.get(host);
  if (cached && cached.expires > now) {
    if (!cached.ok) throw new Error(cached.err);
    return;
  }
  const ips = [];
  for (const type of ["A", "AAAA"]) {
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
        { headers: { Accept: "application/dns-json" }, cf: { cacheTtl: 60 } }
      );
      if (!res.ok) continue;
      const data = await res.json();
      for (const a of data.Answer || []) {
        if (a.type === 1 || a.type === 28) ips.push(a.data);
      }
    } catch {
      // DNS lookup failure for one record type is not fatal by itself
    }
  }
  let ok = true;
  let err = "";
  if (ips.length === 0) { ok = false; err = "the domain does not resolve to a public address"; }
  else if (ips.some((ip) => isPrivateIp(ip))) { ok = false; err = "the domain resolves to a non-public address"; }
  if (DNS_CHECK_CACHE.size > 500) DNS_CHECK_CACHE.delete(DNS_CHECK_CACHE.keys().next().value);
  DNS_CHECK_CACHE.set(host, { ok, err, expires: now + DNS_CHECK_TTL_MS });
  if (!ok) throw new Error(err);
}

function isPrivateIp(ip) {
  const s = String(ip).toLowerCase().trim();
  if (s.includes(":")) {
    // IPv6: loopback, unspecified, link-local, unique-local, v4-mapped, doc range
    return (
      s === "::1" ||
      s === "::" ||
      s.startsWith("fc") ||
      s.startsWith("fd") ||
      s.startsWith("fe8") ||
      s.startsWith("fe9") ||
      s.startsWith("fea") ||
      s.startsWith("feb") ||
      s.startsWith("::ffff:") ||
      s.startsWith("2001:db8")
    );
  }
  const p = s.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/* ----------------------------- Rate limiting ---------------------------- */

async function rateLimit(env, request, bucket, limit = DISCOVER_RATE_LIMIT_PER_HOUR) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  // First line: Cloudflare-native edge rate limiter (burst control). Note:
  // this limiter is per-colo and eventually consistent — intentionally
  // permissive abuse protection, not an exact global counter. The KV hourly
  // cap below is likewise approximate. Both are adequate for this API.
  if (env.API_RL) {
    try {
      const { success } = await env.API_RL.limit({ key: `${bucket}:${ip}` });
      if (!success) return false;
    } catch {
      // fall through to the KV hourly cap
    }
  }
  const hour = Math.floor(Date.now() / 3_600_000);
  const key = `rl:${bucket}:${ip}:${hour}`;
  const n = parseInt((await env.NESSGATE_KV.get(key)) || "0", 10) + 1;
  if (n > limit) return false;
  await env.NESSGATE_KV.put(key, String(n), { expirationTtl: 3700 });
  return true;
}

/* ------------------------------- Helpers ------------------------------- */

async function readJsonBody(request) {
  try {
    const text = await request.text();
    if (text.length > 20_000) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security": HSTS,
      ...extra,
    },
  });
}

function cors() {
  return { "Access-Control-Allow-Origin": "*" };
}

function corsPreflight() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Protocol-Version, Mcp-Session-Id",
      "Access-Control-Max-Age": "86400",
    },
  });
}

function htmlResponse(html, status = 200, extra = {}) {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security": HSTS,
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'",
      ...extra,
    },
  });
}

function pageHtml({ title, body, canonical, description }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
${description ? `<meta name="description" content="${description}">` : ""}
${canonical ? `<link rel="canonical" href="${escapeHtml(canonical)}">` : ""}
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon.ico" sizes="any"><link rel="icon" href="/favicon-32x32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180"><link rel="mask-icon" href="/safari-pinned-tab.svg" color="#0F2D4A"><link rel="manifest" href="/site.webmanifest"><meta name="theme-color" content="#0F2D4A">
<meta property="og:site_name" content="NessGate">
<meta property="og:type" content="website">
<meta property="og:title" content="${title}">
${description ? `<meta property="og:description" content="${description}">` : ""}
${canonical ? `<meta property="og:url" content="${escapeHtml(canonical)}">` : ""}
<meta property="og:image" content="https://nessgate.com/og.png">
<meta name="twitter:card" content="summary_large_image">
<style>
  @font-face{font-family:'Space Grotesk';src:url('/fonts/space-grotesk.woff2') format('woff2');font-weight:300 700;font-display:swap}
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;max-width:42rem;margin:0 auto;padding:2.25rem 1.5rem 2rem;color:#0F2D4A;line-height:1.65;background:#fff}
  .site-head{display:flex;align-items:center;justify-content:space-between;padding-bottom:1.1rem;border-bottom:1px solid #E5E7EB;margin-bottom:2.25rem}
  .brand{display:inline-flex;align-items:center;gap:.55rem;font-family:'Space Grotesk',system-ui,sans-serif;font-weight:700;font-size:1.02rem;letter-spacing:-.015em;color:#0F2D4A;text-decoration:none}
  .brand-accent{color:#00B39C}
  .brand-logo{display:block;height:28px;width:auto}
  .top-nav{display:flex;gap:1.2rem}
  .top-nav a{color:#46586a;font-size:.88rem;font-weight:500}
  .top-nav a:hover{color:#0F2D4A;text-decoration:none}
  .nav-gh{color:#0F2D4A;font-weight:600}
  .foot-src{margin:.7rem 0 0}
  .foot-src a{font-weight:600}
  .meta{font-size:.82rem;color:#7c8b99;margin:.6rem 0 0}
  h1{font-family:'Space Grotesk',system-ui,sans-serif;font-size:1.65rem;font-weight:700;letter-spacing:-.025em;margin:1.5rem 0 .75rem;word-break:break-all}
  a{color:#007a6b;text-decoration:none}
  a:hover{text-decoration:underline}
  .panel{border:1px solid #E5E7EB;border-radius:12px;padding:1.4rem 1.5rem;background:#fff}
  .status{font-weight:600;font-size:.95rem;margin:.2rem 0 .9rem}
  .status::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:.5rem;vertical-align:1px}
  .status.ok{color:#007a6b}
  .status.ok::before{background:#00B39C}
  .status.no{color:#8a6d00}
  .status.no::before{background:#c9a227}
  .label{font-size:.76rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#46586a;margin:0 0 .3rem}
  .res{margin:0 0 1rem}
  .res:last-of-type{margin-bottom:0}
  .res-type{display:inline-block;margin-left:.45rem;padding:.05rem .55rem;border:1px solid #E5E7EB;border-radius:999px;font-size:.68rem;font-weight:600;letter-spacing:.04em;color:#46586a;text-transform:lowercase;vertical-align:1px}
  .url{word-break:break-all;font-family:ui-monospace,'SF Mono',Consolas,monospace;font-size:.88rem;background:#f7f9fb;border:1px solid #E5E7EB;border-radius:8px;padding:.7rem .85rem;margin:0}
  footer{margin-top:4.25rem;padding-top:1.4rem;border-top:1px solid #E5E7EB;font-size:.82rem;color:#7c8b99;text-align:center}
  footer nav{display:flex;flex-wrap:wrap;justify-content:center;gap:.4rem 1.15rem}
  footer nav a{color:#7c8b99}
  footer nav a:hover{color:#0F2D4A;text-decoration:none}
  footer p{margin:.7rem 0 0}
  @media (max-width:640px){body{padding:1.6rem 1.15rem 1.5rem}h1{font-size:1.35rem}}
</style>
</head>
<body>
<header class="site-head"><a class="brand" href="/"><img src="/logo-horizontal.svg" alt="NessGate" width="143" height="28" class="brand-logo"></a><nav class="top-nav" aria-label="Primary"><a href="/check">Check</a><a href="/guide">Guide</a><a href="/api">API</a><a href="/spec">Spec</a><a href="/about">About</a><a class="nav-gh" href="https://github.com/NessGate/nessgate" rel="noopener">GitHub</a></nav></header>
<main>${body}</main>
<footer>
  <nav aria-label="Footer"><a href="/">Home</a><a href="/check">Check</a><a href="/guide">Guide</a><a href="/api">API</a><a href="/spec">Spec</a><a href="/charter">Charter</a><a href="/blog">Blog</a><a href="/about">About</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a></nav>
  <p class="foot-src"><a href="https://github.com/NessGate/nessgate" rel="noopener">GitHub</a> &middot; <a href="https://www.npmjs.com/package/@nessgate/resolver" rel="noopener">npm</a></p>
  <p>© 2026 NessGate</p>
</footer>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Named exports for the regression test suite (scripts/test.mjs); unused by
// the Workers runtime itself. All exports MUST be functions — the module
// Worker runtime treats a non-function named export as a (broken) handler
// entrypoint, so the data constants are exposed through accessor functions.
function selfDomain() { return SELF_DOMAIN; }
function apiCatalog() { return API_CATALOG; }
function mcpTools() { return MCP_TOOLS; }
function adapters() { return ADAPTERS; }
export { normalizeDomain, escapeHtml, validateProbeContent, probeShapeOk, parseLinkRel, parseAgentmap, parseAidRecord, isPrivateIp, hostAllowedForDomain, isForbiddenHost, normalizeResources, isAcs, parseLlmsLinks, looksMachineReadable, isLlmsPath, classifyJson, exploreBudgetAllows, domainToNamespace, mcpRegistryRecords, verifyCandidateRecords, selfDomain, apiCatalog, mcpTools, adapters };
