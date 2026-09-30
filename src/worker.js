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
// Every DNS-over-HTTPS lookup carries its own abort timer: an untimed DoH await
// was the one unbounded wait in the request path, and a stalled resolver could
// hang the whole invocation until the edge killed it (production 504s).
const DOH_TIMEOUT_MS = 5000;
const MAX_JSON_BYTES = 1_000_000; // 1 MB cap on any fetched document
// OpenAPI specs are frequently multi-MB, but detection + our pointer-only record
// live in the document HEAD, so we read only a bounded prefix for /openapi.json —
// separate from the generic cap, so other protocols keep the 1 MB limit.
const OPENAPI_PREFIX_BYTES = 65536;
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
    const org = url.searchParams.get("org") === "1";
    const related = url.searchParams.get("related") === "1";
    const readiness = url.searchParams.get("readiness") === "1";
    return apiExplore(decodeURIComponent(path.slice("/explore/".length)), env, ctx, request, [], org, related, readiness);
  }
  if (path.startsWith("/explore/") && request.method === "POST") {
    // Opt-in candidate verification: the caller's AI/search POSTs candidate URLs;
    // NessGate verifies them deterministically and labels them evidence:"candidate".
    let candidates = [];
    let org = url.searchParams.get("org") === "1";
    let related = url.searchParams.get("related") === "1";
    let readiness = url.searchParams.get("readiness") === "1";
    try {
      const b = await request.json();
      if (b && Array.isArray(b.candidates)) candidates = b.candidates;
      if (b && b.org === true) org = true;
      if (b && b.related === true) related = true;
      if (b && b.readiness === true) readiness = true;
    } catch {}
    return apiExplore(decodeURIComponent(path.slice("/explore/".length)), env, ctx, request, candidates, org, related, readiness);
  }
  if (path.startsWith("/connect/") && request.method === "POST") {
    // Connection plan: the caller POSTs its client capabilities; NessGate matches
    // them against what the domain publishes and returns how to connect. The
    // client's capabilities are input only — nothing is stored.
    let client = {};
    try { const b = await request.json(); client = (b && (b.client || b)) || {}; } catch {}
    return apiConnect(decodeURIComponent(path.slice("/connect/".length)), env, ctx, request, client);
  }
  if (path === "/connect" || path.startsWith("/connect/") || path === "/connect/") {
    return json(
      { error: "POST /connect/{domain} with a JSON body { client: { supports: [{ protocol, versions?, transports?, auth? }], prefer? } }." },
      405,
      { ...cors(), Allow: "POST, OPTIONS" }
    );
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
  { id: "llms.txt", channel: "well-known", paths: ["/llms.txt", "/llms-full.txt"], kind: "text" },
  { id: "ard-catalog", channel: "well-known", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" }, // Agentic Resource Discovery
  { id: "a2a-agent-card", channel: "well-known", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" }, // A2A
  { id: "api-catalog", channel: "well-known", paths: ["/.well-known/api-catalog"], kind: "json" }, // RFC 9727
  { id: "ai-info.json", channel: "well-known", paths: ["/ai-info.json"], kind: "json" },
  { id: "openapi", channel: "well-known", paths: ["/openapi.json", "/openapi.yaml", "/openapi.yml"], kind: "json" },
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
// Alternate ARD locators beyond the well-known path. Per ARD v0.91 a conforming
// consumer MUST honour the rel="ard" HTML link (link-rel), so it runs in DEFAULT
// (complete) mode; robots Agentmap is included too. The opt-in `fast` mode
// (?fast=1) SKIPS both to save a homepage + robots fetch — a LABELED performance
// trade (result carries mode:"fast") that is not fully ARD-conformant. Default
// discovery stays complete and conformant; the optimization is never silent.
const FAST_MODE_SKIP = new Set(["link-rel", "robots"]);
const DISCOVER_CACHE_SECONDS = 600;
const DISCOVER_RATE_LIMIT_PER_HOUR = 120;
const DISCOVER_UA = "NessGate-Discover/1.0 (+https://nessgate.com)";
const MAX_DISCOVER_RESOURCES = 200; // cap on the normalized resource list
const MAX_PER_SOURCE = 50; // cap per source document (defends against huge files)
const MAX_LINKED_CATALOGS = 5; // cap on link-rel / Agentmap catalog follows
const MAX_CAPABILITIES = 40; // cap on verbatim declared capabilities per resource
// MCP introspection (opt-in ?mcp=1): bounded, read-only enumeration of what an
// MCP endpoint declares about itself via the protocol's own handshake.
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
const DISCOVER_NOTE =
  "These locations are published by the domain itself at standard discovery surfaces. " +
  "NessGate reads them as-is and links back to each source (sourceUrl) so a client can " +
  "always verify against the domain directly. NessGate makes no ownership or safety claim.";

// Reject catch-all rewrites: SPA hosts return 200 + their HTML shell for every
// path, which would otherwise report ghost files across half the modern web.
// For text probes, HTML is detected after skipping leading comments: an HTML
// login/shell page that opens with <!-- ... --> must not pass as llms.txt,
// while a genuine plain-text file that starts with a comment header still does
// (its next content is text, not a tag).
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
  let head = text.trimStart();
  for (let i = 0; i < 5 && head.startsWith("<!--"); i++) {
    const end = head.indexOf("-->");
    if (end === -1) return false; // unterminated comment: not a text document
    head = head.slice(end + 3).trimStart();
  }
  return !head.startsWith("<");
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
  return probeShapeOkObj(type, obj);
}

// Object variant so callers that already parsed the document pay for ONE parse
// — classifyJson tests one doc against many types, and repeated JSON.parse of
// large specs was the dominant CPU cost on heavy routes (1102 resource limits).
function probeShapeOkObj(type, obj) {
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

/* --- Probe-outcome honesty (pure, identical in the library; parity-tested) --- */

// Classify one FAILED probe from its error message. "answered" = the domain
// gave a definitive answer that nothing is at that location (clean 404/410, no
// public DNS record, or a redirect pointing away) — absence is CONFIRMED there.
// "refused" = the domain (or its protection layer) would not let the check
// happen (auth/rate/5xx statuses, timeouts, network failures) — absence is
// UNKNOWN there. Unknown failure shapes default to "refused": overcaution may
// label a flaky site blocked, but can never claim absence that was not shown.
function probeFailureKind(message) {
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
function resolutionOutcome(resourceCount, probes) {
  if (resourceCount > 0) return "found";
  const r = (probes && probes.refused) || 0;
  const a = (probes && probes.answered) || 0;
  return r > 0 && r >= a ? "blocked" : "none-found";
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
// Bounded DoH query. The abort timer stays armed through the body read, so a
// resolver that stalls mid-response cannot hang the invocation either. Returns
// the parsed dns-json object, or null on any failure.
async function dohQuery(name, type, cacheTtl = 60) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: "application/dns-json" }, signal: ctrl.signal, cf: { cacheTtl } }
    );
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function dohTxt(name) {
  const data = await dohQuery(name, "TXT");
  const out = [];
  for (const a of (data && data.Answer) || []) {
    if (a.type !== 16) continue; // TXT
    out.push(String(a.data).replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
  }
  return out;
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

// Verbatim skill declarations (A2A agent cards + GB/Z ACS share the `skills`
// shape) → the unified capabilities envelope. Publisher's OWN id / name /
// description / tags, capped, nothing inferred, nothing renamed, nothing
// classified. Returns null when the card declares no skills. Identical to the
// library (packages/resolver), enforced by the normalization parity test.
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
        // capabilities = the card's OWN declared skills (verbatim, capped); the
        // card-level capabilities object (streaming etc.) rides along in raw.
        return [rec({ type: "a2a-agent-card", name: str(obj.name), url: str(obj.url) || ifaceUrl || sourceUrl, ...(declaredSkills(obj) || {}), raw: { name: str(obj.name), description: str(obj.description), version: str(obj.version), url: str(obj.url), capabilities: obj.capabilities && typeof obj.capabilities === "object" && !Array.isArray(obj.capabilities) ? obj.capabilities : undefined, supportedInterfaces: ifaces.length ? ifaces : undefined } })];
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
// OpenAPI detection from a (possibly truncated) document HEAD — byte-for-byte
// the same logic as the embeddable library (packages/resolver, public/resolver.mjs).
// A small spec is parsed authoritatively; a large one is confirmed by the version
// marker that opens the document, so a multi-MB spec is found from its first bytes.
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
    if (!/^﻿?\s*\{/.test(text)) return { ok: false };
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

// Bounded YAML OpenAPI detection — the document's own top-level
// `openapi: <version>` marker on a non-HTML body; title read verbatim from the
// info block when the simple line structure allows. No YAML parser, so YAML
// specs are detected as pointer records without capability enumeration — a
// documented limitation, never a guess. Identical to the library
// (parity-tested).
export function detectOpenApiYaml(text) {
  if (typeof text !== "string" || !text || /^\s*</.test(text)) return { ok: false };
  const ver = /^openapi:\s*['"]?(\d[\d.]*)/m.exec(text);
  if (!ver) return { ok: false };
  const title = /^\s{1,8}title:\s*['"]?([^'"\n]{1,160})/m.exec(text);
  return { ok: true, title: title ? title[1].trim() : undefined };
}

// Pure: map an HTTP status (0 = network-level failure) to an honest
// reachability state — STATUS-ONLY knowledge; classifyDenial upgrades it with
// header/body evidence where available. ok = answered a safe request
// (2xx/3xx/405/406); auth-required = 401/407 (protocol evidence only);
// unknown = bare 403 (auth OR bot-wall — a status alone cannot tell, and we
// never assume); rate-limited = 429; not-found = 404/410; unreachable =
// network/timeout/5xx. Identical to the library (parity-tested).
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
// be RELIABLE or it stays "unknown". Signals are names only (never response
// content). Identical to the library (parity-tested).
export function classifyDenial({ status, headers = {}, bodySnippet = "" } = {}) {
  const s = Number(status) || 0;
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = String(v == null ? "" : v);
  const ra = /^\d+$/.test(String(h["retry-after"] || "").trim()) ? Number(h["retry-after"]) : undefined;
  const out = (reachability, signal) => ({ reachability, ...(signal ? { signal } : {}), ...(ra !== undefined ? { retryAfterSeconds: ra } : {}) });
  if (h["www-authenticate"]) return out("auth-required", "www-authenticate");
  if (s === 401 || s === 407) return out("auth-required");
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

// One SAFE reachability probe for ?verify=1: HEAD first; on 405/501 one GET
// whose body is cancelled immediately. Never POSTs, never executes anything.
// Cross-registrable targets are probed ONLY because the publisher itself
// declared them (the /explore precedent); forbidden-host and public-DNS
// guards always apply; the SELF domain dispatches in-process.
const VERIFY_HEADER_ALLOWLIST = ["www-authenticate", "retry-after", "cf-mitigated", "x-amzn-waf-action", "x-perimeterx"];
const VERIFY_HEADER_PREFIXES = ["x-datadome", "x-px"];
function pickVerifyHeaders(res) {
  const out = {};
  try {
    for (const [k, v] of res.headers) {
      const key = String(k).toLowerCase();
      if (VERIFY_HEADER_ALLOWLIST.includes(key) || VERIFY_HEADER_PREFIXES.some((p) => key.startsWith(p))) out[key] = String(v);
    }
  } catch {}
  return out;
}
async function probeReachabilityWorker(url, env, ctx, domain) {
  let u;
  try { u = new URL(url); } catch { return { status: 0, headers: {}, snippet: "" }; }
  if (u.protocol !== "https:") return { status: 0, headers: {}, snippet: "" };
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (domain === SELF_DOMAIN && host === SELF_DOMAIN) {
    try { const res = await route(new Request(url), env, ctx); return { status: res.status || 0, headers: {}, snippet: "" }; } catch { return { status: 0, headers: {}, snippet: "" }; }
  }
  if (isForbiddenHost(host)) return { status: 0, headers: {}, snippet: "" }; // opaque, like every other guard
  try { await assertPublicDns(host); } catch { return { status: 0, headers: {}, snippet: "" }; }
  const attempt = async (method, wantSnippet) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      // redirect:"manual" (audit fix): a denial page's redirect is never
      // blind-followed — per-hop validation is the rule everywhere else; a
      // 3xx IS an answer (alive) and maps to "ok".
      const res = await fetch(url, { method, redirect: "manual", signal: controller.signal, headers: { "User-Agent": "NessGate-Verify/1.0 (+https://nessgate.com)", Accept: "*/*" }, cf: { cacheTtl: 0 } });
      let snippet = "";
      if (method === "GET") {
        if (wantSnippet && res.body && typeof res.body.getReader === "function") {
          // LITERAL-cap read (audit fix): retain at most ~2 KB, then cancel.
          try {
            const reader = res.body.getReader();
            const chunks = [];
            let size = 0;
            while (size < 2048) {
              const { done, value } = await reader.read();
              if (done) break;
              const room = 2048 - size;
              chunks.push(value.length > room ? value.subarray(0, room) : value);
              size += Math.min(value.length, room);
              if (value.length > room) break;
            }
            try { await reader.cancel(); } catch {}
            const buf = new Uint8Array(size);
            let off = 0;
            for (const c of chunks) { buf.set(c, off); off += c.length; }
            snippet = new TextDecoder().decode(buf);
          } catch {}
        } else if (res.body && typeof res.body.cancel === "function") { try { await res.body.cancel(); } catch {} }
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
const VERIFY_MAX_TARGETS = 8;

// Pure: drop duplicate records produced when ONE document is legitimately
// reachable through several channels (well-known path + rel="ard" link +
// robots Agentmap all naming the same catalog). Keeps the first occurrence
// (channel order = priority). Identical to the library (parity-tested).
export function dedupeResources(resources) {
  const seen = new Set();
  return resources.filter((r) => { const k = r.source + "|" + r.url + "|" + r.sourceUrl; if (seen.has(k)) return false; seen.add(k); return true; });
}

// Fetch a bounded prefix of an on-domain document (for OpenAPI: read only the
// head). Returns { text, truncated } — truncated true only when the body
// exceeded the cap, so the caller can distinguish a cap-truncated document from
// a complete one.
async function getOnDomainPrefix(domain, path, env, ctx, prefixBytes) {
  if (domain === SELF_DOMAIN) return { text: await getOnDomain(domain, path, env, ctx), truncated: false }; // self docs are small
  return safeFetch(`https://${domain}${path}`, domain, prefixBytes, false, DISCOVER_UA, false, false, true);
}

/* --- MCP introspection (opt-in ?mcp=1, read-only) — pure parts parity-tested --- */

// Parse the JSON-RPC message(s) out of a Streamable-HTTP response body: plain
// JSON, or SSE framing (data: lines accumulated per event). Verbatim; malformed
// frames are dropped, never guessed at. Identical to the library.
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
// Identical to the library.
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

// One bounded POST of one JSON-RPC frame, with every SSRF guard safeFetch
// applies to GETs: HTTPS only, on-domain host, forbidden-host + public-DNS
// checks, timeout, literal byte cap. POST redirects are never followed. The
// SELF domain dispatches in-process through route() (safeFetch-style
// self-refusal stays intact); this cannot recurse — introspection sends only
// initialize/initialized/tools/list and the /mcp handler never calls /discover.
async function mcpPostWorker(url, frame, extraHeaders, env, ctx, domain) {
  const u = new URL(url);
  if (u.protocol !== "https:") throw new Error("only HTTPS is allowed");
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "User-Agent": "NessGate-Introspect/1.0 (+https://nessgate.com)",
    ...(extraHeaders || {}),
  };
  if (domain === SELF_DOMAIN && host === SELF_DOMAIN) {
    const res = await route(new Request(url, { method: "POST", headers, body: JSON.stringify(frame) }), env, ctx);
    const text = await res.text();
    if (text.length > MCP_INTROSPECT_MAX_BYTES) throw new Error("response too large");
    return { status: res.status, contentType: res.headers.get("content-type") || "", text, headers: res.headers };
  }
  if (isForbiddenHost(host) || !hostAllowedForDomain(host, domain)) throw new Error("target host is not allowed");
  await assertPublicDns(host);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(url, { method: "POST", redirect: "manual", signal: controller.signal, headers, body: JSON.stringify(frame), cf: { cacheTtl: 0 } });
  } catch {
    throw new Error("the URL could not be fetched (timeout or network error)");
  } finally {
    clearTimeout(timer);
  }
  if (res.status >= 300 && res.status < 400) throw new Error("redirected POST is not followed");
  let text = "";
  const reader = res.body && typeof res.body.getReader === "function" ? res.body.getReader() : null;
  if (reader) {
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MCP_INTROSPECT_MAX_BYTES) { await reader.cancel(); throw new Error("response too large"); }
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
  return { status: res.status, contentType: res.headers.get("content-type") || "", text, headers: res.headers };
}

// Introspect ONE declared MCP endpoint with the protocol's own read-only
// handshake: initialize → notifications/initialized → tools/list. Nothing else
// is ever sent (MCP_INTROSPECTION_METHODS is the complete set): no tool
// execution, no credentials — an auth wall is an honest observation
// ("auth-required"), never retried with secrets. Failures collapse to labeled
// statuses; nothing is guessed. Same flow as the library.
async function introspectMcpEndpoint(url, env, ctx, domain) {
  const fail = (status) => ({ introspection: { ok: false, status } });
  try {
    const init = await mcpPostWorker(url, {
      jsonrpc: "2.0", id: 1, method: MCP_INTROSPECTION_METHODS[0],
      params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "NessGate-Introspect", version: "1.0" } },
    }, null, env, ctx, domain);
    if (init.status === 401 || init.status === 403) return fail("auth-required");
    if (init.status === 405) return fail("legacy-transport"); // pre-2025 HTTP+SSE servers reject POST at the SSE URL
    if (init.status < 200 || init.status >= 300) return fail("error");
    const initMsg = parseMcpMessages(init.text, init.contentType).find((m) => m.id === 1);
    if (!initMsg || !initMsg.result || typeof initMsg.result !== "object") return fail("error");
    const session = init.headers && typeof init.headers.get === "function" ? init.headers.get("mcp-session-id") : null;
    const negotiated = typeof initMsg.result.protocolVersion === "string" ? initMsg.result.protocolVersion : undefined;
    const extra = { ...(session ? { "Mcp-Session-Id": session } : {}), ...(negotiated ? { "MCP-Protocol-Version": negotiated } : {}) };
    try { await mcpPostWorker(url, { jsonrpc: "2.0", method: MCP_INTROSPECTION_METHODS[1] }, extra, env, ctx, domain); } catch {}
    const lst = await mcpPostWorker(url, { jsonrpc: "2.0", id: 2, method: MCP_INTROSPECTION_METHODS[2], params: {} }, extra, env, ctx, domain);
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
// Identical to the library.
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

async function runAdapter(a, domain, env, ctx, probes) {
  // probes (optional): shared failure tally for the outcome label — every
  // failed fetch is classified answered-vs-refused by probeFailureKind.
  const miss = (e) => { if (probes) probes[probeFailureKind(e && e.message)]++; };
  try {
    if (a.channel === "well-known") {
      for (const path of a.paths) {
        const url = `https://${domain}${path}`;
        // OpenAPI: bounded-prefix read + head detection, so large specs are found
        // without downloading/parsing megabytes.
        if (a.id === "openapi") {
          let r;
          try { r = await getOnDomainPrefix(domain, path, env, ctx, OPENAPI_PREFIX_BYTES); } catch (e) { miss(e); continue; }
          // YAML specs: detected by the document's own top-level marker;
          // pointer record only (no capability enumeration without a parser).
          if (/\.ya?ml$/.test(path)) {
            const det = detectOpenApiYaml(r.text);
            if (det.ok) return { discovered: [{ type: a.id, url }], resources: [{ source: "openapi", sourceUrl: url, type: "openapi", name: det.title, url }] };
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
            if (r.truncated && !(typeof r.contentLength === "number" && r.contentLength > MAX_JSON_BYTES)) {
              try { const full = await getOnDomainPrefix(domain, path, env, ctx, MAX_JSON_BYTES); if (!full.truncated) capSrc = full.text; } catch {}
            }
            const decl = capSrc ? extractOpenApiCapabilities(capSrc) : null;
            return { discovered: [{ type: a.id, url }], resources: [{ source: "openapi", sourceUrl: url, type: "openapi", name: det.title, url, ...(decl || {}) }] };
          }
          continue;
        }
        let text;
        try { text = await getOnDomain(domain, path, env, ctx); } catch (e) { miss(e); continue; }
        if (validateProbeContent(a.kind, text) && probeShapeOk(a.id, a.kind, text)) {
          return { discovered: [{ type: a.id, url }], resources: normalizeResources(a.id, a.kind, text, url) };
        }
      }
      return { discovered: [], resources: [] };
    }
    if (a.channel === "link-rel" || a.channel === "robots") {
      const src = a.channel === "link-rel" ? "/" : "/robots.txt";
      let doc;
      try { doc = await getOnDomain(domain, src, env, ctx); } catch (e) { miss(e); return { discovered: [], resources: [] }; }
      const targets = a.channel === "link-rel" ? parseLinkRel(doc, a.rels) : parseAgentmap(doc, a.directive);
      const discovered = [], resources = [];
      for (const t of targets.slice(0, MAX_LINKED_CATALOGS)) {
        let abs;
        try { abs = new URL(t, `https://${domain}/`).toString(); } catch { continue; }
        let text;
        try { text = await getOnDomain(domain, abs, env, ctx); } catch (e) { miss(e); continue; } // safeFetch keeps it on-domain
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
  // Default = COMPLETE, ARD-conformant discovery (all channels incl. the required
  // rel="ard" link). ?fast=1 SKIPS the alternate ARD locators (homepage <link rel>,
  // robots Agentmap) to save 2 fetches — a labeled, non-conformant speed trade,
  // cached under a separate key and flagged mode:"fast" in the response.
  let fast = false;
  let mcp = false;
  let verify = false;
  try {
    const q = new URL(request.url).searchParams;
    fast = q.get("fast") === "1";
    mcp = q.get("mcp") === "1"; // opt-in read-only MCP introspection (labeled)
    verify = q.get("verify") === "1"; // opt-in reachability pass (labeled)
  } catch {}
  const active = fast ? ADAPTERS.filter((a) => !FAST_MODE_SKIP.has(a.channel)) : ADAPTERS;
  const cache = caches.default;
  // Cloudflare logs every Cache API op into the worker zone's request
  // analytics regardless of the key's hostname (match miss = empty-UA GET 504,
  // put = PUT 204, match hit = GET 200) — but under the KEY's path. The
  // /cache-op/ prefix keeps that bookkeeping out of every /discover//explore
  // path-filtered metric, where misses read as phantom caller-facing 504s.
  // (.invalid host = RFC 2606, clearly synthetic; keys are never fetched.)
  const key = new Request(`https://resolver-cache.nessgate.invalid/cache-op/discover/${fast ? "fast/" : ""}${mcp ? "mcp/" : ""}${verify ? "verify/" : ""}${domain}`);
  const hit = await cache.match(key);
  if (hit) return { status: 200, body: await hit.json(), cached: true };
  if (!(await rateLimit(env, request, "disc", DISCOVER_RATE_LIMIT_PER_HOUR))) {
    return { status: 429, body: { error: "Too many requests. Please try again later." } };
  }
  // Run every adapter in parallel; merge the routing map (discovered) and the
  // normalized union (resources). Each adapter is self-contained per channel.
  // probes tallies every failed fetch (answered vs refused) for the outcome label.
  const probes = { answered: 0, refused: 0 };
  const settled = await Promise.allSettled(active.map((a) => runAdapter(a, domain, env, ctx, probes)));
  const results = settled.map((r) => (r.status === "fulfilled" && r.value ? r.value : { discovered: [], resources: [] }));
  let discovered = results.flatMap((r) => r.discovered);
  let resources = results.flatMap((r) => r.resources);

  // Canonical-host fallback (general rule; same registrable domain ONLY). When
  // the exact host publishes nothing and its homepage 301s to www./a subdomain
  // of itself, the site's real canonical host may hold the files (measured on
  // real publishers). Bounded: one homepage fetch + two probes; a redirect to a
  // DIFFERENT registrable domain is never followed here (safeFetch stays
  // domain-locked), so this can never change whose resources are reported.
  if (discovered.length === 0 && domain !== SELF_DOMAIN) {
    try {
      const home = await safeFetch(`https://${domain}/`, domain, MAX_JSON_BYTES, false, DISCOVER_UA, false, true);
      const canon = sameRegCanonicalHost(home.finalUrl, domain);
      if (canon) {
        for (const [path, type, kind] of [["/llms.txt", "llms.txt", "text"], ["/.well-known/ard.json", "ard-catalog", "json"]]) {
          try {
            const text = await safeFetch(`https://${canon}${path}`, domain, MAX_JSON_BYTES, false, DISCOVER_UA);
            if (validateProbeContent(kind, text) && probeShapeOk(type, kind, text)) {
              const url = `https://${canon}${path}`;
              discovered.push({ type, url });
              resources.push(...normalizeResources(type, kind, text, url));
            }
          } catch (e) { probes[probeFailureKind(e && e.message)]++; }
        }
      }
    } catch {}
  }
  // One document reachable through several channels (well-known + rel="ard" +
  // robots Agentmap) must not multiply records.
  resources = dedupeResources(resources);
  {
    const seenD = new Set();
    discovered = discovered.filter((x) => { const k = x.type + "|" + x.url; if (seenD.has(k)) return false; seenD.add(k); return true; });
  }
  resources = resources.slice(0, MAX_DISCOVER_RESOURCES).map((r) => ({ ...r, class: classifyResource(r, domain) }));
  // Opt-in MCP introspection: ask each declared (same-registrable, HTTPS) MCP
  // endpoint what IT declares, via the protocol's own read-only handshake. The
  // results land on the endpoint's own resource record — additive, verbatim.
  if (mcp) {
    const cands = mcpIntrospectionCandidates(resources, domain);
    await Promise.all(cands.map(async (r) => { Object.assign(r, await introspectMcpEndpoint(r.url, env, ctx, domain)); }));
  }
  // Opt-in ?verify=1: labeled reachability pass. Surfaces this resolution
  // fetched are "ok" with NO extra request (the fetch is the evidence); MCP
  // records reuse introspection when present; declared pointers get one safe
  // probe each, capped. Absent reachability = not checked, honestly.
  if (verify) {
    const now = new Date().toISOString();
    const probed = new Map();
    let vBudget = VERIFY_MAX_TARGETS;
    const vStart = Date.now(); // audit fix: time cap alongside the request cap
    for (const r of resources) {
      if (Date.now() - vStart > 12000) break; // remaining records stay not-checked, honestly
      if (typeof r.url !== "string" || !r.url.startsWith("https://")) continue;
      if (r.class === "verified-publisher-location" || r.url === r.sourceUrl) {
        r.reachability = "ok";
        r.checkedAt = now;
        r.evidence = { signal: "fetched-this-resolution" };
        continue;
      }
      if (r.introspection) {
        r.reachability = r.introspection.ok ? "ok" : r.introspection.status === "auth-required" ? "auth-required" : r.introspection.status === "legacy-transport" ? "ok" : "unreachable";
        r.checkedAt = now;
        r.evidence = { signal: "mcp-introspection" };
        continue;
      }
      if (!probed.has(r.url)) {
        if (vBudget <= 0) continue; // stays not-checked
        vBudget--;
        const probe = await probeReachabilityWorker(r.url, env, ctx, domain);
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
  let note = fast ? DISCOVER_NOTE + " (fast mode: the optional alternate ARD locators — rel=\"ard\" link and robots Agentmap — were skipped for speed; a catalog advertised only via those may be missed. Omit ?fast for complete, ARD-conformant discovery.)" : DISCOVER_NOTE;
  if (mcp) note += " (mcp introspection: declared MCP endpoints on this domain were queried READ-ONLY — initialize and tools/list only, no tool execution, no credentials; results are the servers' own declarations.)";
  const body = {
    domain,
    provenance: "self-published",
    note,
    // The single honest outcome label: found / none-found / blocked.
    // blockedProbes discloses refusals even when the outcome is none-found
    // (e.g. one flaky timeout among clean 404s), so uncertainty is never hidden.
    outcome: resolutionOutcome(resources.length, probes),
    ...(probes.refused ? { blockedProbes: probes.refused } : {}),
    ...(fast ? { mode: "fast" } : {}),
    ...(mcp ? { introspected: ["mcp"] } : {}),
    ...(verify ? { verified: ["reachability"] } : {}),
    discovered,
    resources,
    checked: active.map((a) => a.id),
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
// deadlineMs is a HARD wall-clock cap for one /explore request: sequential
// best-effort fetches against slow or stalling hosts must never stack into
// minutes. Once the deadline passes, no NEW fetch starts (an in-flight one still
// honors its own 8s timeout, so worst case ≈ deadline + one fetch); the answer
// returns with whatever was gathered and stats.truncated = true.
// maxDepth is a RUNAWAY BACKSTOP only, not the effective limit: an explicit
// publisher-declared chain (company.com → agents.company.com catalog →
// mcp.api.agents.company.com) is followed to arbitrary depth — the REAL
// limiters are requests/bytes/hosts/deadline plus the seen-set (loop
// detection) and per-hop validation. Raised from 2 (which cut legitimate
// declaration chains) per the 2026-09-21 evidence-based-discovery review.
const EXPLORE_LIMITS = { maxDepth: 8, maxHosts: 8, maxRequests: 24, maxTotalBytes: 6_000_000, deadlineMs: 20_000 };
const MAX_CANDIDATES = 10; // cap on opt-in caller-supplied candidate URLs to verify (subrequest budget)

// Organization Discovery (opt-in, ?org=1). Major organizations publish their
// machine-readable resources on related hosts (developers.openai.com) rather
// than the apex. Org mode probes a BOUNDED set of plausible same-organization
// hosts — subdomains the homepage itself links to, plus a small fixed
// conventional shortlist — and reports ONLY verified machine-readable resources,
// each labelled evidence:"same-domain-host" (same registrable domain controls the
// DNS; the relationship is organizational, not independently verified). This is
// not crawling: at most ORG_MAX_HOSTS hosts × ORG_PROBE_PATHS paths, sharing the
// same request/host/byte budget, content-validated before being reported.
const ORG_SUBDOMAIN_SHORTLIST = ["docs", "developers", "cloud", "api", "developer", "platform", "learn"];
const ORG_MAX_HOSTS = 6; // 6 hosts × 3 paths + homepage stays inside maxRequests (24); over-budget probes degrade gracefully (truncated:true)
const ORG_PROBE_PATHS = ["/llms.txt", "/.well-known/ard.json", "/.well-known/ai-catalog.json"];
// Leftmost labels that mark a host as developer/documentation-facing. Used ONLY
// to ORDER the bounded probe list (which hosts get the few slots) — never as an
// authority signal. "community" earns its place empirically: Discourse-hosted
// community.* sites auto-serve llms.txt (community.openai.com). "cloud" too:
// cloud.google.com serves llms.txt while docs./developers.google.com do not.
const ORG_DEV_LABELS = new Set(["docs", "developers", "developer", "api", "platform", "learn", "community", "cloud", "dev", "ai", "open"]);
const ORG_NOTE =
  "Organization Discovery results (evidence \"same-domain-host\") are machine-readable resources " +
  "verified on hosts under the same registrable domain — subdomains the homepage links to, or a " +
  "small conventional shortlist. Same registrable domain; the organizational relationship is not " +
  "independently verified. Explore a related host directly for its full resource graph.";

// Pure: extract same-registrable-domain subdomain hosts referenced anywhere in an
// HTML page (absolute URLs only). Excludes the apex and www; unique, order kept.
function parseSameOrgHosts(html, domain) {
  if (typeof html !== "string") return [];
  const out = [];
  const seen = new Set();
  const suffix = "." + domain;
  for (const m of html.match(/https?:\/\/[a-z0-9.-]+/gi) || []) {
    let host;
    try { host = new URL(m).hostname.toLowerCase().replace(/\.+$/, ""); } catch { continue; }
    if (!host.endsWith(suffix)) continue;
    if (host === "www." + domain || host === domain) continue;
    if (seen.has(host)) continue;
    seen.add(host);
    out.push(host);
  }
  return out;
}

// Pure: turn one fetched probe document into evidence-classed records — empty
// unless it is genuinely a recognized machine-readable resource.
function docRecords(url, text, evidence, prov) {
  if (isLlmsPath(url)) {
    if (!validateProbeContent("text", text)) return [];
    return [{ source: "llms.txt", sourceUrl: url, type: "llms.txt", url, evidence, provenance: prov, depth: 1 }];
  }
  const t = classifyJson(text);
  if (!t) return [];
  return normalizeResources(t, "json", text, url).map((rec) => ({ ...rec, evidence, provenance: prov, depth: 1 }));
}

// Pure: turn one fetched org-host document into same-domain-host records.
function orgRecordsFromDoc(url, text, via) {
  return docRecords(url, text, "same-domain-host", ["org:" + via, url]);
}

// Pure: the queried domain's OWN homepage redirect to a DIFFERENT registrable
// domain (aws.com → aws.amazon.com). Publisher configuration, reported as an
// honest observation so a caller isn't stranded on an empty shell domain —
// never merged into resources, never treated as the same authoritative host.
function homepageRedirectInfo(finalUrl, domain) {
  if (!finalUrl) return null;
  let h;
  try { h = new URL(finalUrl).hostname.toLowerCase().replace(/^www\./, ""); } catch { return null; }
  return isCrossRegistrable(h, domain) ? { from: "https://" + domain + "/", to: finalUrl } : null;
}

// Pure: probes genuinely REACHED an answer for a host when one returned
// content (200), a clean not-found (404/410 — the host answered; nothing is
// published there), or the host has no public DNS record at all (-2 — it does
// not publicly exist, which equally means nothing is published there).
// Network-level failures and refusal statuses (401/403/405/429, 5xx) mean the
// host would not let us look, so absence there is UNKNOWN — the org check
// reports such hosts in orgBlocked instead of implying they publish nothing.
function orgHostResponded(statuses) {
  return statuses.some((s) => s === 200 || s === 404 || s === 410 || s === -2);
}

// Pure: choose WHICH bounded set of same-organization hosts to probe. Homepage
// HTML yields every same-domain absolute URL in DOM order — on large sites
// that is CDN/telemetry/nav hosts first (cdn-dynmedia-1., wcpstatic., tv.),
// which used to crowd the few probe slots out of the hosts that actually
// publish (docs., developers.). Priority, deterministic:
//   1. homepage-linked hosts whose leftmost label is developer/doc-facing
//      (publisher evidence AND a plausible publishing host),
//   2. the conventional shortlist (docs.{d}, developers.{d}, …),
//   3. remaining homepage-linked hosts, original order.
// Ordering only — a probed host still must serve a validated machine-readable
// document to be reported at all.
function selectOrgHosts(homepageHosts, domain) {
  const seen = new Set();
  const out = [];
  const take = (h, via) => {
    if (seen.has(h) || out.length >= ORG_MAX_HOSTS) return;
    seen.add(h);
    out.push({ h, via });
  };
  const devFacing = (h) => ORG_DEV_LABELS.has(String(h).split(".")[0]);
  for (const h of homepageHosts) if (devFacing(h)) take(h, "homepage-link");
  for (const p of ORG_SUBDOMAIN_SHORTLIST) take(`${p}.${domain}`, "conventional");
  for (const h of homepageHosts) take(h, "homepage-link");
  return out;
}

/* ----- Related Discovery (cross-registrable-domain; see docs/related-discovery-rules.md) ----- */
// Evidence model: only a purpose-built declaration served by the QUERIED domain
// (legacy Related Website Set, Digital Asset Links web statements) or a
// domain-verifying registry naming the specific candidate can produce a strong
// class (publisher-declared-related / registry-verified-related). Technical
// signals (NS containment, …) are corroborating ONLY — cited in signals[],
// never promoted, never "official"/"same organization". Hyperlinks never count.
const RELATED_MAX_HOSTS = 5;
const RWS_PATH = "/.well-known/related-website-set.json";

// Pure: is `host` outside the queried registrable domain (approximation:
// not the apex and not a subdomain of it)?
function isCrossRegistrable(host, domain) {
  if (typeof host !== "string" || !host) return false;
  const h = host.toLowerCase().replace(/\.+$/, "");
  return h !== domain && !h.endsWith("." + domain);
}

// Label each resource by how much NessGate actually verified it — an additive DX
// field on /discover results, derived with NO extra requests:
//   verified-publisher-location — the surface NessGate fetched AND validated, on
//     the domain's own registrable domain (the resource IS the fetched document).
//   verified-external-location — the fetched-and-validated document itself, but
//     its FINAL URL is on a DIFFERENT registrable domain. The hosted worker can
//     NEVER emit this (safeFetch refuses cross-registrable redirects); only the
//     embeddable library — which follows redirects and records the final URL —
//     produces it. The branch lives here so worker and library stay identical.
//   publisher-declared — declared inside a fetched catalog, target on the same
//     registrable domain (incl. subdomains); the target itself was NOT fetched.
//   declared-external-pointer — declared inside a fetched catalog, target on a
//     DIFFERENT registrable domain; the publisher asserts it, NessGate did not verify.
//   unsupported — no usable target URL to locate the resource.
// Two taxonomy classes are deliberately NOT emitted here: a "third-party
// association" is an /explore concept, and flagging an "inaccessible" resource
// would require fetching every declared pointer — which /discover avoids to keep
// request counts low. Kept byte-identical to the library (packages/resolver).
function classifyResource(r, domain) {
  let host;
  try { host = new URL(r.url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return "unsupported"; }
  const sameReg = host === domain || host.endsWith("." + domain);
  if (r.url === r.sourceUrl) return sameReg ? "verified-publisher-location" : "verified-external-location";
  return sameReg ? "publisher-declared" : "declared-external-pointer";
}

// Pure: the same-registrable-domain canonical host implied by a homepage final
// URL (apex → www./subdomain of itself). Returns null for the apex itself and
// for any cross-registrable-domain redirect — those are never treated as the
// same authoritative host.
function sameRegCanonicalHost(finalUrl, domain) {
  let h;
  try { h = new URL(finalUrl).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return null; }
  if (h === domain) return null;
  return h.endsWith("." + domain) ? h : null;
}

// Pure: parse a Related Website Set file. If the file's primary is the queried
// domain, returns the declared member sites with roles; if it names another
// primary, returns { memberOf } (useful for reciprocity checks); else null.
function parseRwsDeclaration(text, domain) {
  let obj;
  try { obj = JSON.parse(text); } catch { return null; }
  if (!obj || typeof obj !== "object") return null;
  const toHost = (v) => {
    if (typeof v !== "string") return null;
    try { return new URL(v).hostname.toLowerCase().replace(/^www\./, ""); } catch { return null; }
  };
  const primary = toHost(obj.primary);
  if (!primary) return null;
  if (primary !== domain) return { memberOf: primary };
  const sites = [];
  for (const [key, role] of [["associatedSites", "associated"], ["serviceSites", "service"], ["ccTLDs", "ccTLD"]]) {
    const v = obj[key];
    const list = Array.isArray(v) ? v : v && typeof v === "object" ? Object.values(v).flat() : [];
    for (const s of list) {
      const h = toHost(s);
      if (h && !sites.some((x) => x.host === h)) sites.push({ host: h, role });
    }
  }
  return { primary, sites };
}

// Pure: does a candidate's RWS file reciprocate by naming the queried domain
// as its primary?
function rwsReciprocal(text, domain) {
  const p = parseRwsDeclaration(text, domain);
  return !!(p && (p.primary === domain || p.memberOf === domain));
}

// Pure: Digital Asset Links — extract web-namespace target sites (cross-domain
// association statements; app statements are ignored).
function parseAssetLinksWeb(text) {
  let arr;
  try { arr = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const st of arr) {
    const t = st && st.target;
    if (!t || t.namespace !== "web" || typeof t.site !== "string") continue;
    try {
      const h = new URL(t.site).hostname.toLowerCase().replace(/^www\./, "");
      if (h && !out.includes(h)) out.push(h);
    } catch {}
  }
  return out;
}

// Pure: which of a candidate's authoritative nameservers are hosts UNDER the
// queried domain (e.g. youtube.com served by ns1.google.com)? Corroborating
// signal only — inverts for DNS providers, so it never implies ownership.
function nsContained(nsHosts, domain) {
  if (!Array.isArray(nsHosts)) return [];
  const suffix = "." + domain;
  return nsHosts
    .map((n) => String(n).toLowerCase().replace(/\.+$/, ""))
    .filter((n) => n === domain || n.endsWith(suffix));
}

// DoH NS lookup (Cloudflare resolver), best-effort.
async function dohNs(name) {
  const data = await dohQuery(name, "NS", 300);
  return ((data && data.Answer) || []).filter((a) => a.type === 2).map((a) => String(a.data));
}
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
    if (probeShapeOkObj(t, obj)) return t; // single parse; shape checks on the object
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
function verifyCandidateRecords(finalUrl, text, chain) {
  // Preserve the full original→final redirect path the caller's suggestion took.
  const prov = ["ai-candidate", ...(Array.isArray(chain) && chain.length ? chain : [finalUrl])];
  if (isLlmsPath(finalUrl)) return [{ source: "llms.txt", sourceUrl: finalUrl, type: "llms.txt", url: finalUrl, evidence: "candidate", provenance: prov, depth: 1 }];
  const t = classifyJson(text);
  if (!t) return [];
  return normalizeResources(t, "json", text, finalUrl).map((rec) => ({ ...rec, evidence: "candidate", provenance: prov, depth: 1 }));
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
const MCP_REGISTRY_MAX_BYTES = 500_000; // registry pages are ~10-100 KB; cap defensively
async function fetchMcpRegistry(namespace) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REGISTRY_TIMEOUT_MS);
  try {
    const res = await fetch(`${MCP_REGISTRY_API}?search=${encodeURIComponent(namespace)}&limit=50`, {
      headers: { Accept: "application/json", "User-Agent": EXPLORE_UA },
      signal: ctrl.signal,
      cf: { cacheTtl: 300 },
    });
    if (!res.ok) return null; // registry answered abnormally — UNAVAILABLE, not "empty"
    // Bounded read with the abort timer still armed: the registry is a trusted
    // party, but its response is still an external body — cap it so an oversized
    // or slow-trickling reply can neither bloat nor hang the invocation.
    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MCP_REGISTRY_MAX_BYTES) {
        try { await reader.cancel(); } catch {}
        return null; // could not read the registry reliably — UNAVAILABLE
      }
      chunks.push(value);
    }
    const buf = new Uint8Array(size);
    let off = 0;
    for (const chunk of chunks) { buf.set(chunk, off); off += chunk.length; }
    return new TextDecoder().decode(buf);
  } catch {
    return null; // timeout / network failure — UNAVAILABLE, never silently "no results"
  } finally {
    clearTimeout(timer);
  }
}

async function exploreData(raw, env, ctx, request, candidates = [], org = false, related = false, readiness = false) {
  const domain = normalizeDomain(raw, true);
  if (!domain) return { status: 400, body: { error: "Invalid domain" } };
  const hasCandidates = Array.isArray(candidates) && candidates.length > 0;
  const cache = caches.default;
  // /cache-op/ key prefix — see discoverData for why (analytics phantoms).
  // The readiness flag is part of the key so a ?readiness=1 answer is never served
  // for a plain request, or vice versa.
  const key = new Request(`https://resolver-cache.nessgate.invalid/cache-op/explore${org ? "-org" : ""}${related ? "-rel" : ""}${readiness ? "-rdy" : ""}/${domain}`);
  // Candidate requests are per-body and never cached (input varies per call).
  const hit = hasCandidates ? null : await cache.match(key);
  if (hit) return { status: 200, body: await hit.json(), cached: true };
  if (!(await rateLimit(env, request, "explore", EXPLORE_RATE_LIMIT_PER_HOUR))) {
    return { status: 429, body: { error: "Too many requests. Please try again later." } };
  }

  const budget = { requests: 0, bytes: 0, hosts: new Set(), seen: new Set(), truncated: false, start: Date.now() };
  const probes = { answered: 0, refused: 0 }; // failed-fetch tally for the outcome label
  const out = [];

  // Attributed MCP Registry federation — ISSUED FIRST (so it grabs an early
  // subrequest slot before exact-host/delegated fetches can exhaust Cloudflare's
  // per-invocation cap), run CONCURRENTLY with the rest (no added latency), and
  // awaited at the end. Short-timeout + best-effort, so a slow namespace never
  // stalls /explore.
  const namespace = domainToNamespace(domain);
  const registryPromise = namespace ? fetchMcpRegistry(namespace) : Promise.resolve("");

  // Bounded, SSRF-safe fetch of a single delegated URL (cross-host allowed because
  // the publisher named it; self is dispatched in-process). Returns
  // { text, finalUrl, chain } — `chain` is the full ordered list of URLs fetched
  // (original → …redirects… → final), so provenance can preserve the whole path —
  // or null. Counts requests, and — via exploreBudgetAllows — every host touched
  // (including redirect hops) and the bytes fetched against the global budgets.
  async function fetchDoc(url, failMeta) {
    let host;
    try { host = new URL(url).hostname.toLowerCase().replace(/\.+$/, ""); } catch { return null; }
    if (budget.seen.has(url)) return null;
    budget.seen.add(url);
    if (Date.now() - budget.start > EXPLORE_LIMITS.deadlineMs) { budget.truncated = true; return null; }
    if (budget.truncated || budget.requests >= EXPLORE_LIMITS.maxRequests) { budget.truncated = true; return null; }
    if (!budget.hosts.has(host) && budget.hosts.size >= EXPLORE_LIMITS.maxHosts) { budget.truncated = true; return null; }
    budget.requests++;
    try {
      if (domain === SELF_DOMAIN && host === SELF_DOMAIN) {
        const u = new URL(url);
        const text = await selfProbe(u.pathname + u.search, env, ctx);
        exploreBudgetAllows(budget, { hosts: [host], bytes: text.length }, EXPLORE_LIMITS);
        budget.seen.add(u.toString());
        return { text, finalUrl: u.toString(), chain: [u.toString()] };
      }
      const meta = await safeFetch(url, domain, MAX_JSON_BYTES, false, EXPLORE_UA, true, true);
      exploreBudgetAllows(budget, meta, EXPLORE_LIMITS); // counts redirect hosts + bytes
      budget.seen.add(meta.finalUrl); // the resolved URL is now accounted for
      return { text: meta.text, finalUrl: meta.finalUrl, chain: meta.redirectChain };
    } catch (e) {
      const msg = String(e && e.message);
      probes[probeFailureKind(msg)]++; // outcome-label tally (answered vs refused)
      // Optional failure classification for callers that must distinguish "the
      // host answered with an HTTP status" from "nothing answered at all"
      // (org mode's blocked-vs-absent honesty). 0 = network-level failure;
      // -2 = the host has no public DNS record (it does not publicly exist —
      // nothing is published there, which is an ANSWER, not a block).
      if (failMeta) {
        const m = /returned HTTP (\d+)/.exec(msg);
        failMeta.status = m ? Number(m[1]) : /does not resolve/.test(msg) ? -2 : 0;
      }
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
  // null = the registry could not be checked (timeout/error) — disclosed as
  // federatedUnavailable so absence-of-results is never mistaken for
  // checked-and-empty.
  const regText = await registryPromise;
  const registryUnavailable = namespace ? regText === null : false;
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
      for (const rec of verifyCandidateRecords(doc.finalUrl, doc.text, doc.chain)) out.push(rec);
    }
  }

  // Phase 5 — Organization Discovery (opt-in via ?org=1). Probe a bounded set of
  // plausible same-organization hosts: subdomains the homepage itself links to
  // (publisher evidence) plus a small fixed conventional shortlist. Only verified
  // machine-readable resources are reported (evidence "same-domain-host"); a host
  // that serves nothing recognized is simply absent. Shares the global budget.
  // Homepage is used by both the org phase (same-domain link extraction) and the
  // related phase (cross-domain redirect detection) — fetch it once.
  let homeDoc = null;
  if (org || related) homeDoc = await fetchDoc(`https://${domain}/`);

  let orgChecked = null;
  let orgBlocked = null;
  // Observation, org mode only: the domain's own homepage redirect to a
  // different registrable domain (fetchDoc already followed it; the target's
  // HTML never yields same-domain hosts, so the shell would otherwise read as
  // a bare empty). See homepageRedirectInfo.
  let homepageRedirect = null;
  if (org && homeDoc) homepageRedirect = homepageRedirectInfo(homeDoc.finalUrl, domain);
  if (org) {
    let homepageHosts = [];
    if (homeDoc) homepageHosts = parseSameOrgHosts(homeDoc.text, domain);
    const orgHosts = selectOrgHosts(homepageHosts, domain);
    orgChecked = [];
    orgBlocked = [];
    for (const { h, via } of orgHosts) {
      if (budget.truncated) break;
      orgChecked.push(h);
      const statuses = [];
      for (const p of ORG_PROBE_PATHS) {
        const failMeta = { status: -1 }; // -1 = probe skipped (budget), neither reached nor refused
        const doc = await fetchDoc(`https://${h}${p}`, failMeta);
        if (doc) {
          statuses.push(200);
          for (const rec of orgRecordsFromDoc(doc.finalUrl, doc.text, via)) out.push(rec);
          continue;
        }
        statuses.push(failMeta.status);
      }
      // Every probe refused or blackholed → the host blocked the look; absence
      // there is unknown, never implied.
      if (!orgHostResponded(statuses) && statuses.some((s) => s === 0 || s === 401 || s === 403 || s === 405 || s === 429 || s >= 500)) orgBlocked.push(h);
    }
  }

  // Phase 6 — Related Discovery (opt-in via ?related=1): cross-registrable-domain
  // relationships under the strict evidence model of docs/related-discovery-rules.md.
  // Strong classes only restate a declaration served by the queried domain or an
  // attributed registry record; NS containment is recorded as a corroborating
  // signal and never promotes. Bounded: <= RELATED_MAX_HOSTS hosts, 2 declaration
  // fetches + per-host (1 reciprocity fetch + 2 probes + 1 DoH NS lookup).
  let relatedOut = null;
  if (related) {
    relatedOut = [];
    const declared = []; // { host, role, declType, declUrl }
    const rwsUrl = `https://${domain}${RWS_PATH}`;
    const rwsDoc = await fetchDoc(rwsUrl);
    if (rwsDoc) {
      const rws = parseRwsDeclaration(rwsDoc.text, domain);
      if (rws && Array.isArray(rws.sites)) {
        for (const s of rws.sites) {
          if (isCrossRegistrable(s.host, domain)) declared.push({ host: s.host, role: s.role, declType: "related-website-set (legacy)", declUrl: rwsDoc.finalUrl });
        }
      }
    }
    const alUrl = `https://${domain}/.well-known/assetlinks.json`;
    const alDoc = await fetchDoc(alUrl);
    if (alDoc) {
      for (const h of parseAssetLinksWeb(alDoc.text)) {
        if (isCrossRegistrable(h, domain) && !declared.some((d) => d.host === h)) {
          declared.push({ host: h, role: "web-statement", declType: "digital-asset-links", declUrl: alDoc.finalUrl });
        }
      }
    }
    for (const d of declared.slice(0, RELATED_MAX_HOSTS)) {
      if (budget.truncated) break;
      const entry = {
        host: d.host,
        class: "publisher-declared-related",
        declaration: { type: d.declType, role: d.role, url: d.declUrl },
        signals: [],
        resources: [],
      };
      // Mutuality: does the declared site serve a reciprocal declaration?
      const recip = await fetchDoc(`https://${d.host}${RWS_PATH}`);
      entry.declaration.mutual = !!(recip && rwsReciprocal(recip.text, domain));
      // Corroborating signal (never promotes): NS containment.
      const ns = nsContained(await dohNs(d.host), domain);
      if (ns.length) entry.signals.push({ type: "ns-containment", ns, note: "corroborating only; never implies ownership" });
      // Verified machine-readable resources on the related host.
      for (const p of ORG_PROBE_PATHS) {
        const doc = await fetchDoc(`https://${d.host}${p}`);
        if (!doc) continue;
        for (const rec of docRecords(doc.finalUrl, doc.text, "publisher-declared-related", [d.declUrl, d.host, doc.finalUrl])) entry.resources.push(rec);
      }
      relatedOut.push(entry);
    }
    // Publisher-redirect candidate (general rule): the apex homepage redirecting
    // to a DIFFERENT registrable domain is the publisher's own configuration,
    // but it is recorded ONLY as a provenance-carrying candidate — never as the
    // same authoritative host — and only when verified resources exist there.
    if (homeDoc && homeDoc.finalUrl) {
      let redirHost = null;
      try { redirHost = new URL(homeDoc.finalUrl).hostname.toLowerCase().replace(/^www\./, ""); } catch {}
      if (redirHost && isCrossRegistrable(redirHost, domain) && !relatedOut.some((e) => e.host === redirHost)) {
        const entry = {
          host: redirHost,
          class: "publisher-redirect-candidate",
          redirect: { from: `https://${domain}/`, to: homeDoc.finalUrl },
          signals: [],
          resources: [],
        };
        for (const p of ORG_PROBE_PATHS) {
          const doc = await fetchDoc(`https://${redirHost}${p}`);
          if (!doc) continue;
          for (const rec of docRecords(doc.finalUrl, doc.text, "publisher-redirect-candidate", ["redirect:homepage", homeDoc.finalUrl, doc.finalUrl])) entry.resources.push(rec);
        }
        if (entry.resources.length) relatedOut.push(entry);
      }
    }

    // Registry-verified: MCP Registry entries whose remote lives on a
    // cross-registrable-domain host (attributed to the registry).
    for (const r of out) {
      if (r.source !== "mcp-registry" || !r.url) continue;
      let h;
      try { h = new URL(r.url).hostname.toLowerCase().replace(/^www\./, ""); } catch { continue; }
      if (!isCrossRegistrable(h, domain)) continue;
      if (relatedOut.some((e) => e.host === h)) continue;
      relatedOut.push({
        host: h,
        class: "registry-verified-related",
        attribution: r.attribution,
        signals: [],
        resources: [{ ...r }],
      });
    }
    // Caller-supplied cross-domain candidates with verified resources: NS signal
    // may corroborate, producing infrastructure-correlated-candidate; without a
    // signal they stay as plain candidates in resources[] only.
    if (hasCandidates) {
      const candHosts = [];
      for (const r of out) {
        if (r.evidence !== "candidate" || !r.url) continue;
        let h;
        try { h = new URL(r.url).hostname.toLowerCase().replace(/^www\./, ""); } catch { continue; }
        if (!isCrossRegistrable(h, domain) || candHosts.includes(h) || relatedOut.some((e) => e.host === h)) continue;
        candHosts.push(h);
      }
      for (const h of candHosts.slice(0, RELATED_MAX_HOSTS)) {
        const ns = nsContained(await dohNs(h), domain);
        if (!ns.length) continue;
        relatedOut.push({
          host: h,
          class: "infrastructure-correlated-candidate",
          signals: [{ type: "ns-containment", ns, note: "corroborating only; never implies ownership" }],
          resources: out.filter((r) => r.evidence === "candidate" && r.url && r.url.includes("//" + h)).map((r) => ({ ...r })),
        });
      }
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

  // Opt-in connection-readiness (?readiness=1): assess how ready each connectable
  // resource is to connect to and attach a `readiness` field. Bounded + read-only;
  // runs only under the flag, so default /explore output is unchanged.
  if (readiness) {
    const pool = resources.concat(relatedOut ? relatedOut.flatMap((g) => (g && Array.isArray(g.resources) ? g.resources : [])) : []);
    try { await attachReadiness(pool); } catch { /* readiness must never break discovery */ }
    // Anonymous aggregate usage signal: ONE categorical label (the best readiness
    // outcome across connectable resources), no domain / payload / IP — emitted via
    // the single metrics site (recordDiscovery), preserving the privacy invariant.
    const ro = pool.map((r) => r.readiness && r.readiness.outcome);
    recordDiscovery(env, "readiness:" + (ro.includes("ready") ? "ready" : ro.includes("credentials-required") ? "credentials-required" : ro.includes("incomplete") ? "incomplete" : ro.includes("broken") ? "broken" : "none-connectable"));
  }

  const body = {
    domain,
    note: org ? EXPLORE_NOTE + " " + ORG_NOTE : EXPLORE_NOTE,
    ...(readiness
      ? { readinessNote: "readiness[] per connectable resource: ready | credentials-required | incomplete | broken (with missing[]). Read-only, from the service's own published metadata; credentials stay with the caller. No scores." }
      : {}),
    // Outcome label; /explore adds "incomplete" — budgets/deadline cut the walk
    // before it finished, so an empty result may just be an unfinished one.
    outcome: resources.length > 0 ? "found" : budget.truncated ? "incomplete" : resolutionOutcome(0, probes),
    ...(probes.refused ? { blockedProbes: probes.refused } : {}),
    checked: ADAPTERS.map((a) => a.id),
    ...(orgChecked ? { orgChecked } : {}),
    ...(orgBlocked && orgBlocked.length ? { orgBlocked } : {}),
    ...(homepageRedirect ? { homepageRedirect } : {}),
    resources,
    ...(relatedOut
      ? {
          related: relatedOut,
          relatedNote:
            "Cross-registrable-domain entries, separate from exact-host results. Strong classes only restate a " +
            "declaration the queried domain serves (publisher-declared-related) or an attributed registry record " +
            "(registry-verified-related). Technical signals in signals[] are corroborating only and never imply " +
            "ownership. See /spec and docs/related-discovery-rules.md.",
        }
      : {}),
    federated: ["mcp-registry"],
    ...(registryUnavailable
      ? { federatedUnavailable: ["mcp-registry"], federatedNote: "The MCP Registry could not be checked on this request (timeout or error) — registry-backed results may be missing. This is disclosed so it is never mistaken for checked-and-empty." }
      : {}),
    stats: {
      publisherHosted: resources.filter((r) => r.evidence === "publisher-hosted").length,
      publisherDeclared: resources.filter((r) => r.evidence === "publisher-declared").length,
      namespaceVerified: resources.filter((r) => r.evidence === "namespace-verified").length,
      candidate: resources.filter((r) => r.evidence === "candidate").length,
      ...(org ? { sameDomainHost: resources.filter((r) => r.evidence === "same-domain-host").length } : {}),
      ...(relatedOut ? { related: relatedOut.length } : {}),
      requests: budget.requests,
      hosts: budget.hosts.size,
      bytes: budget.bytes,
      truncated: budget.truncated,
    },
    limits:
      org || related
        ? { ...EXPLORE_LIMITS, ...(org ? { orgMaxHosts: ORG_MAX_HOSTS } : {}), ...(related ? { relatedMaxHosts: RELATED_MAX_HOSTS } : {}) }
        : EXPLORE_LIMITS,
  };
  const res = new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${DISCOVER_CACHE_SECONDS}` },
  });
  if (ctx && !hasCandidates) ctx.waitUntil(cache.put(key, res));
  return { status: 200, body };
}

/* ============ Connection-readiness checker (opt-in, additive) ============
   The five pure assessors below are kept BYTE-IDENTICAL to public/resolver.mjs
   (parity-tested in scripts/test.mjs). They read a discovered resource's OWN
   published metadata and return one honest outcome — ready / credentials-required
   / incomplete — with `missing[]` naming any gap. No scores; nothing guessed;
   credentials never touch NessGate. The IO helpers that fetch the metadata are
   worker-specific (they reuse the worker's SSRF guards) and run only under
   /explore?readiness=1, so default /explore output is unchanged. */

// Pure: the negotiated MCP protocolVersion from an initialize response, whether it
// came back as plain JSON or one/more SSE `data:` frames (Streamable HTTP).
export function extractProtocolVersion(text) {
  const tryParse = (s) => { try { return JSON.parse(s); } catch { return null; } };
  const pv = (j) => (j && j.result && typeof j.result.protocolVersion === "string" ? j.result.protocolVersion : null);
  let v = pv(tryParse(text));
  if (v) return v;
  for (const m of String(text || "").matchAll(/^data:\s*(.+)$/gm)) { v = pv(tryParse(m[1])); if (v) return v; }
  return null;
}

// Pure: which connectable protocol a discovered resource represents, or null for a
// pointer/catalog surface (llms.txt, api-catalog, host-meta, …). Reuses each
// source's OWN labels — invents no taxonomy.
export function readinessProtocol(r) {
  if (!r || typeof r !== "object") return null;
  const src = String(r.source || "").toLowerCase();
  const type = String(r.type || "").toLowerCase();
  let path = "", host = "";
  try { const u = new URL(r.url); path = u.pathname.toLowerCase(); host = u.hostname.toLowerCase(); } catch {}
  // OAuth/OpenID metadata documents are NOT connectable endpoints — the MCP
  // readiness resolver fetches them itself; never handshake one as an endpoint.
  if (/\/\.well-known\/(oauth-protected-resource|oauth-authorization-server|openid-configuration)/.test(path)) return null;
  // A documentation/marketing page (…/mcp.md, …/openapi-guide.html) is never an
  // endpoint even when its URL contains a protocol word. Explicit adapter/type
  // labels are still trusted; only the fuzzy path/host heuristics are gated by this,
  // and each requires the word as a bounded path SEGMENT — so /mcp and /openapi.json
  // match, but /mcp-guide and /openapi-tips do not.
  const isDoc = /\.(md|mdx|html?|txt|pdf|rst)($|\?)/.test(path);
  // A documentation-section path is a page ABOUT a protocol, not an endpoint —
  // the fuzzy path heuristics below never fire on one. Explicit adapter/type
  // labels are unaffected.
  const isDocSection = /\/(docs?|documentation|blog|guides?|reference|help|learn|tutorials?)(\/|$)/.test(path);
  if (src === "aid" && r.raw && typeof r.raw === "object" && typeof r.raw.proto === "string") { const p = r.raw.proto.toLowerCase(); return p === "mcp" ? "mcp" : p || null; }
  if (src === "openapi" || type.includes("openapi") || (!isDoc && !isDocSection && /\/(openapi|swagger)(\.(json|ya?ml))?(\/|\?|$)/.test(path))) return "openapi";
  if (src === "mcp" || type === "mcp" || type === "mcp-server" || type === "application/mcp-server-card+json" || (!isDoc && (host.startsWith("mcp.") || (!isDocSection && /\/mcp(\/|\?|$)/.test(path))))) return "mcp";
  if (src === "a2a-agent-card" || type.includes("agent-card") || (!isDoc && !isDocSection && /\/agent(-card)?\.json(\?|$)/.test(path))) return "a2a-agent-card";
  return null;
}

// Pure: OpenAPI readiness from a parsed spec (servers[] + securitySchemes).
export function assessOpenApiReadiness(spec) {
  const out = { protocol: "openapi", transport: "https", version: null, missing: [] };
  if (!spec || typeof spec !== "object") return { ...out, outcome: "incomplete", missing: ["a parseable OpenAPI document"] };
  out.version = typeof spec.openapi === "string" ? spec.openapi : typeof spec.swagger === "string" ? spec.swagger : null;
  const servers = Array.isArray(spec.servers) ? spec.servers.map((s) => s && s.url).filter(Boolean) : [];
  const schemes = (spec.components && typeof spec.components === "object" && spec.components.securitySchemes) || spec.securityDefinitions || null;
  const hasSchemes = !!(schemes && Object.keys(schemes).length);
  // OpenAPI's OWN way to declare "no auth required": an explicit empty top-level
  // security array. Absent securitySchemes WITHOUT that declaration stays
  // incomplete — "didn't say" is not "none needed".
  const explicitlyOpen = Array.isArray(spec.security) && spec.security.length === 0;
  const missing = [];
  if (!servers.length) missing.push("servers[] (no base URL is declared)");
  if (!hasSchemes && !explicitlyOpen) missing.push("securitySchemes (no auth method is declared; an api without auth should declare top-level security: [])");
  if (!out.version) missing.push("openapi/swagger version string");
  if (servers[0]) out.endpoint = servers[0];
  if (missing.length) return { ...out, outcome: "incomplete", missing };
  if (explicitlyOpen) return { ...out, outcome: "ready", auth: { required: false } };
  const first = Object.values(schemes)[0] || {};
  const auth = { required: true, type: first.type };
  if (first.type === "http" && first.scheme) auth.type = "http:" + String(first.scheme).toLowerCase();
  if (first.type === "oauth2" && first.flows && typeof first.flows === "object") {
    const f = first.flows.authorizationCode || first.flows.clientCredentials || first.flows.password || first.flows.implicit || {};
    if (f.authorizationUrl) auth.authorizationEndpoint = f.authorizationUrl;
    if (f.tokenUrl) auth.tokenEndpoint = f.tokenUrl;
    if (f.scopes && typeof f.scopes === "object") auth.scopes = Object.keys(f.scopes);
  }
  return { ...out, outcome: "credentials-required", auth };
}

// Pure: A2A readiness from a parsed agent card (modern + legacy schema).
export function assessA2aReadiness(card) {
  const out = { protocol: "a2a-agent-card", missing: [] };
  if (!card || typeof card !== "object") return { ...out, outcome: "incomplete", missing: ["a parseable A2A agent card"] };
  const ifaces = [
    ...(Array.isArray(card.additionalInterfaces) ? card.additionalInterfaces : []),
    ...(Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : []),
  ].filter((i) => i && typeof i === "object");
  let transport = null, endpoint = typeof card.url === "string" ? card.url : undefined;
  if (typeof card.preferredTransport === "string") transport = card.preferredTransport.toLowerCase();
  else if (ifaces.length && ifaces[0].transport) { transport = String(ifaces[0].transport).toLowerCase(); endpoint = ifaces[0].url || endpoint; }
  else if (typeof card.url === "string" && !/\.json(\?|$)/i.test(card.url)) transport = "jsonrpc";
  out.transport = transport; if (endpoint) out.endpoint = endpoint;
  out.version = typeof card.protocolVersion === "string" ? card.protocolVersion : typeof card.version === "string" ? card.version : null;
  const schemes = card.securitySchemes && typeof card.securitySchemes === "object" ? card.securitySchemes : null;
  const requiredList = Array.isArray(card.security) && card.security.length ? card.security : null;
  const missing = [];
  if (!out.transport) missing.push("a transport (no preferredTransport, interfaces, or usable url)");
  if (!out.version) missing.push("protocolVersion (no version is declared)");
  if (missing.length) return { ...out, outcome: "incomplete", missing };
  if (!schemes && !requiredList) return { ...out, outcome: "ready", auth: { required: false } };
  const first = schemes ? Object.values(schemes)[0] || {} : {};
  return { ...out, outcome: "credentials-required", auth: { required: true, type: first.type || "declared" } };
}

// Pure: classify a FAILED metadata fetch into broken vs incomplete. "broken" is
// claimed ONLY on positive evidence — the service ANSWERED and the answer
// contradicts its own declaration (404/410/5xx at a declared location, or 200 with
// an unparseable document). Denials (401/403 — authorization OR a bot-wall) and
// network failures (vantage, not service) never read as broken: measured in the
// stability experiment, those are frequently not the service's fault.
export function assessFetchFailure(protocol, status, what) {
  if (status === 404 || status === 410 || status >= 500) return { protocol, outcome: "broken", missing: [`a working ${what} — the declared location answered HTTP ${status}`] };
  if (status === 200) return { protocol, outcome: "broken", missing: [`a valid ${what} — the declared location answers but the document is not parseable`] };
  if (status === 401 || status === 403) return { protocol, outcome: "incomplete", missing: [`a readable ${what} (HTTP ${status}: requires authorization or is walled — unverifiable from this vantage)`] };
  return { protocol, outcome: "incomplete", missing: [`a reachable ${what} (fetch failed from this vantage)`] };
}

// Pure: MCP readiness from an initialize result plus an OPTIONAL OAuth metadata
// chain (RFC 9728 protected-resource metadata → RFC 8414 authorization-server
// metadata). A bare 403 is undetermined (auth OR bot/WAF), never a false OAuth wall.
export function assessMcpReadiness({ init, prm, as }) {
  const transport = init && init.status === 405 ? "sse-legacy" : "streamable-http";
  const version = (init && init.protocolVersion) || null;
  const base = { protocol: "mcp", transport, version };
  // ready requires PROTOCOL-level evidence, not transport success: a documentation
  // page answers HTTP 200 to a POST too. Only a parseable JSON-RPC initialize
  // result (its REQUIRED protocolVersion) proves an MCP endpoint.
  if (init && init.ok && init.protocolVersion) return { ...base, outcome: "ready", auth: { required: false }, verified: "ok", missing: [] };
  if (init && init.ok) return { ...base, outcome: "incomplete", verified: "http-200-not-mcp", missing: ["a valid MCP initialize response — the endpoint answered HTTP 200 but not with a JSON-RPC initialize result (a documentation page can do that); protocol-level evidence is required for ready"] };
  const authWall = init && (init.status === 401 || (init.status === 403 && init.wwwAuthenticate));
  if (authWall) {
    if (as && as.authorization_endpoint && as.token_endpoint) {
      const auth = { required: true, type: "oauth2", authorizationEndpoint: as.authorization_endpoint, tokenEndpoint: as.token_endpoint };
      if (Array.isArray(as.scopes_supported)) auth.scopes = as.scopes_supported;
      if (Array.isArray(as.grant_types_supported)) auth.grantTypes = as.grant_types_supported;
      if (as.registration_endpoint) { auth.dynamicClientRegistration = true; auth.registrationEndpoint = as.registration_endpoint; }
      return { ...base, outcome: "credentials-required", auth, verified: "auth-required", missing: [] };
    }
    const missing = !prm
      ? ["OAuth 2.0 Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource"]
      : ["Authorization Server Metadata (RFC 8414) — the protected-resource doc names no reachable authorization server"];
    return { ...base, outcome: "incomplete", auth: { required: true, type: "oauth2" }, verified: "auth-required", missing };
  }
  if (init && init.status === 403) return { ...base, outcome: "incomplete", verified: "denied:403", missing: ["undetermined: endpoint returned 403 with no auth challenge (authorization OR bot/WAF protection — a safe probe cannot distinguish them)"] };
  // Positive evidence the declaration is wrong: the endpoint ANSWERED with
  // gone/not-found/server-error → broken, not merely incomplete.
  if (init && (init.status === 404 || init.status === 410 || init.status >= 500)) return { ...base, outcome: "broken", verified: "error:" + init.status, missing: [`a working MCP endpoint — the declared endpoint answered HTTP ${init.status}`] };
  return { ...base, outcome: "incomplete", verified: init && init.status ? "error:" + init.status : "unreachable", missing: ["a reachable MCP endpoint (initialize handshake did not succeed)"] };
}

// Connection-PLAN client matcher — byte-identical to public/resolver.mjs (parity-tested).
const CLIENT_PROTOCOL_ALIASES = { a2a: "a2a-agent-card", "agent-card": "a2a-agent-card", rest: "openapi", "gbz-185.4": "gbz-185-4" };
export function canonClientProtocol(p) { p = String(p || "").toLowerCase(); return CLIENT_PROTOCOL_ALIASES[p] || p; }

// Pure: can a client entry { protocol, versions?, transports?, auth? } use a
// resolved connection (a readiness record)? Tri-state per dimension — true (both
// declared & intersect), "any" (client unconstrained), "unknown" (service did not
// declare it), false (both declared & CONFLICT → the only hard incompatibility).
export function matchClient(readiness, entry) {
  const dim = (clientList, serviceVal) => {
    if (!Array.isArray(clientList) || !clientList.length) return "any";
    if (serviceVal == null) return "unknown";
    return clientList.map((x) => String(x).toLowerCase()).includes(String(serviceVal).toLowerCase()) ? true : false;
  };
  const version = dim(entry.versions, readiness.version);
  const transport = dim(entry.transports, readiness.transport);
  let auth;
  const a = readiness.auth;
  if (!Array.isArray(entry.auth) || !entry.auth.length) auth = "any";
  else if (!a) auth = "unknown";
  else if (a.required === false) auth = true;
  else {
    const client = entry.auth.map((x) => String(x).toLowerCase());
    const types = [];
    if (typeof a.type === "string") types.push(a.type.toLowerCase());
    if (Array.isArray(a.methods)) for (const m of a.methods) if (m && m.label) types.push(String(m.label).toLowerCase());
    auth = !types.length ? "unknown" : types.some((t) => client.includes(t)) ? true : false;
  }
  const hardFail = version === false ? "version" : transport === false ? "transport" : auth === false ? "auth" : null;
  return { compatible: !hardFail, reason: hardFail ? `client and service both declare ${hardFail} and they do not intersect` : undefined, matchedOn: { protocol: true, version, transport, auth } };
}

const READINESS_MAX = 4; // cap connectable resources assessed per /explore call
const READINESS_BYTES = 262144;
const READINESS_FETCH_TIMEOUT_MS = 5000; // per readiness hop (tighter than the discovery fetch timeout)
const READINESS_DEADLINE_MS = 12000; // total wall-clock budget for the whole readiness pass — a slow
// or hostile endpoint can never run the synchronous /explore handler past this (each hop is also
// individually timed, and no new hop starts once the deadline is reached).

// Bounded body read (literal cap), mirroring the verify-probe reader.
async function readinessReadBounded(res, max) {
  try {
    if (!res.body || typeof res.body.getReader !== "function") return await res.text();
    const reader = res.body.getReader();
    const chunks = []; let size = 0;
    while (size < max) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = max - size;
      chunks.push(value.length > room ? value.subarray(0, room) : value);
      size += Math.min(value.length, room);
      if (value.length > room) break;
    }
    try { await reader.cancel(); } catch {}
    const buf = new Uint8Array(size); let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
    return new TextDecoder().decode(buf);
  } catch { return ""; }
}
// Read-only JSON GET with the worker's SSRF guards. Redirects are NOT followed
// (manual) — a metadata endpoint that redirects reads as unavailable, which is safe.
// Returns { status, json } — status is kept so failures can be honestly classified
// (assessFetchFailure): an answered 404 is evidence, a network failure is not.
async function readinessFetchJson(url, deadline) {
  if (deadline && Date.now() > deadline) return { status: 0, json: null };
  let u; try { u = new URL(url); } catch { return { status: 0, json: null }; }
  if (u.protocol !== "https:") return { status: 0, json: null };
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (isForbiddenHost(host)) return { status: 0, json: null };
  try { await assertPublicDns(host); } catch { return { status: 0, json: null }; }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), READINESS_FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(u.toString(), { method: "GET", redirect: "manual", signal: controller.signal, headers: { "User-Agent": "NessGate-Readiness/1.0 (+https://nessgate.com)", Accept: "application/json" }, cf: { cacheTtl: 0 } });
    if (res.status !== 200) { try { await res.body?.cancel(); } catch {} return { status: res.status || 0, json: null }; }
    try { return { status: 200, json: JSON.parse(await readinessReadBounded(res, READINESS_BYTES)) }; } catch { return { status: 200, json: null }; }
  } catch { return { status: 0, json: null }; } finally { clearTimeout(timer); }
}
// Read-only MCP initialize (no tools/call, no credentials). Returns status even on
// 401/403 (the auth signal), plus the RFC 9728 pointer and negotiated version.
async function readinessMcpInit(url, deadline) {
  if (deadline && Date.now() > deadline) return { ok: false, status: 0 };
  let u; try { u = new URL(url); } catch { return { ok: false, status: 0 }; }
  if (u.protocol !== "https:") return { ok: false, status: 0 };
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (isForbiddenHost(host)) return { ok: false, status: 0 };
  try { await assertPublicDns(host); } catch { return { ok: false, status: 0 }; }
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "NessGate-Readiness", version: "1.0" } } });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), READINESS_FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(u.toString(), { method: "POST", redirect: "manual", signal: controller.signal, headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "User-Agent": "NessGate-Readiness/1.0 (+https://nessgate.com)" }, cf: { cacheTtl: 0 }, body });
    const text = await readinessReadBounded(res, 65536);
    return { ok: res.status === 200, status: res.status, wwwAuthenticate: res.headers.get("www-authenticate") || null, protocolVersion: extractProtocolVersion(text) };
  } catch { return { ok: false, status: 0 }; } finally { clearTimeout(timer); }
}
async function readinessFillMcp(endpoint, deadline) {
  if (/\.json(\?|$)/i.test(endpoint) || /server-card|agent-card/i.test(endpoint)) {
    const card = (await readinessFetchJson(endpoint, deadline)).json;
    const inner = card && (card.url || card.endpoint || card.serverUrl || card.mcpUrl || (card.server && card.server.url));
    if (typeof inner === "string" && /^https:\/\//i.test(inner)) endpoint = inner;
  }
  const init = await readinessMcpInit(endpoint, deadline);
  let prm = null, as = null;
  if (init.status === 401 || init.status === 403) {
    let prmUrl = null;
    const m = init.wwwAuthenticate && init.wwwAuthenticate.match(/resource_metadata="?([^",\s]+)"?/i);
    if (m) prmUrl = m[1];
    else { try { prmUrl = new URL("/.well-known/oauth-protected-resource", endpoint).toString(); } catch {} }
    if (prmUrl) prm = (await readinessFetchJson(prmUrl, deadline)).json;
    const asBase = prm && Array.isArray(prm.authorization_servers) && prm.authorization_servers[0];
    if (asBase) {
      for (const path of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
        let asUrl; try { asUrl = new URL(path, asBase).toString(); } catch { continue; }
        const doc = (await readinessFetchJson(asUrl, deadline)).json;
        if (doc && doc.token_endpoint) { as = doc; break; }
      }
    }
  }
  return { ...assessMcpReadiness({ init, prm, as }), endpoint };
}
// IO: assess one connectable resource (worker vantage). Read-only, no credentials.
async function readinessForResource(resource, deadline) {
  const proto = readinessProtocol(resource);
  if (!proto) return null;
  const stamp = (a) => ({ ...a, endpoint: a.endpoint || resource.url });
  if (proto === "openapi") {
    const r = await readinessFetchJson(resource.url, deadline);
    return stamp(r.json ? assessOpenApiReadiness(r.json) : { ...assessFetchFailure("openapi", r.status, "OpenAPI document"), transport: "https" });
  }
  if (proto === "a2a-agent-card") {
    const r = await readinessFetchJson(resource.sourceUrl || resource.url, deadline);
    return stamp(r.json ? assessA2aReadiness(r.json) : assessFetchFailure("a2a-agent-card", r.status, "A2A agent card"));
  }
  if (proto === "mcp") return stamp(await readinessFillMcp(resource.url, deadline));
  return stamp({ protocol: proto, outcome: "incomplete", missing: [`no readiness resolver implemented for "${proto}" yet`] });
}
// Attach `readiness` to each connectable resource (bounded by BOTH a count budget
// and a total wall-clock deadline). Assesses each UNIQUE endpoint URL once (so a URL
// /explore surfaces from several channels does not spend the budget twice) and shares
// the result with every occurrence. Mutates in place.
async function attachReadiness(resources) {
  const byUrl = new Map();
  const deadline = Date.now() + READINESS_DEADLINE_MS;
  let budget = READINESS_MAX;
  for (const r of resources) {
    const proto = readinessProtocol(r);
    if (!proto) continue;
    if (!byUrl.has(r.url)) {
      if (budget <= 0 || Date.now() > deadline) continue; // out of budget/time — leave later resources unassessed
      budget--;
      try { byUrl.set(r.url, await readinessForResource(r, deadline)); }
      catch { byUrl.set(r.url, { protocol: proto, outcome: "incomplete", missing: ["readiness check failed"] }); }
    }
    if (byUrl.has(r.url)) r.readiness = byUrl.get(r.url);
  }
}

async function apiExplore(raw, env, ctx, request, candidates = [], org = false, related = false, readiness = false) {
  const { status, body } = await exploreData(raw, env, ctx, request, candidates, org, related, readiness);
  const hasCand = Array.isArray(candidates) && candidates.length > 0;
  const extra =
    status === 200
      ? { ...cors(), "Cache-Control": hasCand ? "no-store" : `public, max-age=${DISCOVER_CACHE_SECONDS}` }
      : cors();
  return json(body, status, extra);
}

/* -------------------- Connection PLAN — POST /connect/{domain} -------------------- */
// "How can THIS client connect to this domain?" Discovers the domain (via the
// /explore path — delegation + federation, reusing its cache and rate limit),
// matches each connectable resource against the CLIENT's declared capabilities
// (deterministic intersection — a fact, not a score), assesses readiness of the
// matches, and returns ONE outcome (ready | credentials-required | incomplete |
// no-compatible-method) with a connection plan. Read-only; credentials stay with
// the caller and never touch NessGate. Client-specific → never cached.
async function connectData(raw, env, ctx, request, clientCaps) {
  const domain = normalizeDomain(raw, true);
  if (!domain) { recordDiscovery(env, "connect:invalid"); return { status: 400, body: { error: "Invalid domain" } }; }
  const disc = await exploreData(raw, env, ctx, request, [], false, false, false);
  if (disc.status !== 200) { recordDiscovery(env, "connect:" + (disc.status === 429 ? "rate-limited" : "error")); return disc; } // 429 / 400 bubble up unchanged
  const resources = [
    ...(disc.body.resources || []),
    ...((disc.body.related || []).flatMap((g) => (g && Array.isArray(g.resources) ? g.resources : []))),
  ];
  const caps = clientCaps && typeof clientCaps === "object" ? clientCaps.client || clientCaps : {};
  const supportsList = Array.isArray(caps.supports) ? caps.supports : [];
  const supports = new Map();
  for (const s of supportsList) if (s && s.protocol) supports.set(canonClientProtocol(s.protocol), s);
  const prefer = (Array.isArray(caps.prefer) ? caps.prefer : []).map(canonClientProtocol);
  // A caller that declares NO capabilities must not read as "nothing is compatible"
  // (that would be a false negative on every connectable domain). Assume a broad
  // default client instead — and LABEL the assumption so the answer stays honest.
  let clientAssumed = false;
  if (supports.size === 0) {
    clientAssumed = true;
    for (const p of ["mcp", "openapi", "a2a-agent-card"]) supports.set(p, { protocol: p });
  }

  const deadline = Date.now() + READINESS_DEADLINE_MS;
  const seen = new Set(), plans = [], rejected = [], serviceProtocols = new Set();
  let budget = READINESS_MAX;
  for (const r of resources) {
    const proto = readinessProtocol(r);
    if (!proto) continue;
    serviceProtocols.add(proto);
    if (seen.has(r.url)) continue;
    seen.add(r.url);
    const entry = supports.get(canonClientProtocol(proto));
    if (!entry) { rejected.push({ protocol: proto, endpoint: r.url, reason: "client does not support protocol" }); continue; }
    if (budget <= 0 || Date.now() > deadline) continue;
    budget--;
    let readiness;
    try { readiness = await readinessForResource(r, deadline); } catch { continue; }
    if (!readiness) continue;
    const m = matchClient(readiness, entry);
    if (!m.compatible) { rejected.push({ protocol: proto, endpoint: r.url, reason: m.reason }); continue; }
    plans.push({ ...readiness, matchedOn: m.matchedOn });
  }

  const RANK = { ready: 0, "credentials-required": 1, incomplete: 2, broken: 3 };
  const pidx = (p) => { const i = prefer.indexOf(canonClientProtocol(p)); return i < 0 ? prefer.length : i; };
  plans.sort((a, b) => pidx(a.protocol) - pidx(b.protocol) || (RANK[a.outcome] ?? 4) - (RANK[b.outcome] ?? 4) || String(a.protocol).localeCompare(String(b.protocol)));
  const has = (o) => plans.some((p) => p.outcome === o);
  const outcome = has("ready") ? "ready" : has("credentials-required") ? "credentials-required" : has("incomplete") ? "incomplete" : plans.length ? "broken" : serviceProtocols.size ? "no-compatible-method" : "incomplete";
  const clientOnly = [];
  for (const s of supportsList) { const p = canonClientProtocol(s.protocol); if (p && !serviceProtocols.has(p)) clientOnly.push({ protocol: p, reason: `service publishes no ${p} surface` }); }
  const seenRej = new Set();
  const serviceOffered = rejected.filter((x) => { const k = x.protocol + "|" + x.reason; if (seenRej.has(k)) return false; seenRej.add(k); return true; });

  // Anonymous aggregate usage signal: ONE categorical outcome label, no domain /
  // client payload / IP — emitted via the single metrics site (recordDiscovery).
  recordDiscovery(env, "connect:" + outcome);

  return {
    status: 200,
    body: {
      domain,
      outcome,
      ...(clientAssumed ? { clientAssumed: true } : {}),
      note:
        "Connection plan: how this client can connect. Read-only, from the service's own published metadata; credentials stay with the caller. No scores." +
        (clientAssumed ? " No client capabilities were declared, so a broad default client (mcp, openapi, a2a) was ASSUMED — pass client.supports for a real match." : ""),
      connection: plans[0] || null,
      alternatives: plans.slice(1),
      selectedByClientPreference: prefer.length && plans.length ? { protocol: plans[0].protocol, endpoint: plans[0].endpoint, reason: "client preference order" } : null,
      compatibility: { clientMethods: supports.size, serviceMethods: serviceProtocols.size, compatibleMethods: plans.length },
      unmatched: { serviceOffered, clientOnly },
    },
  };
}

async function apiConnect(raw, env, ctx, request, clientCaps) {
  const { status, body } = await connectData(raw, env, ctx, request, clientCaps);
  return json(body, status, status === 200 ? { ...cors(), "Cache-Control": "no-store" } : cors());
}

/* ----------------------- MCP server (read-only tool) ----------------------- */
// POST /mcp — Model Context Protocol over Streamable HTTP, stateless JSON
// responses. Exposes the resolver as a tool so AI agents can call it directly
// instead of scraping it. Same rate limits and caches as the REST endpoint
// (the tool dispatches to the same handler).

const MCP_SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26"];
const MCP_SERVER_INFO = { name: "nessgate", title: "NessGate — the neutral resolver for the agentic web", version: "1.18.0" };
const MCP_INSTRUCTIONS =
  "Three read-only tools. discover_domain: what a domain publishes (the raw normalized list). " +
  "connect_domain: given a domain AND your client's capabilities, HOW to connect — one outcome " +
  "(ready | credentials-required | incomplete | broken | no-compatible-method) with a connection plan, or the " +
  "exact missing field. check_readiness: per-endpoint readiness for a domain, client-agnostic. All read " +
  "the domain live, store nothing, make no ownership/safety claim; credentials stay with the caller.";

const MCP_DOMAIN_INPUT = {
  type: "object",
  properties: { domain: { type: "string", description: "Registrable domain, e.g. example.com" } },
  required: ["domain"],
};

// connect_domain also takes the CALLER's capabilities (input only — never stored).
const MCP_CONNECT_INPUT = {
  type: "object",
  properties: {
    domain: { type: "string", description: "Registrable domain, e.g. example.com" },
    client: {
      type: "object",
      description:
        "The calling client's capabilities. Omit a dimension to accept any. If client/supports is omitted " +
        "entirely, a broad default (mcp, openapi, a2a) is assumed and the response carries clientAssumed:true.",
      properties: {
        supports: {
          type: "array",
          description: "Protocols the client speaks, each optionally narrowing versions/transports/auth.",
          items: {
            type: "object",
            properties: {
              protocol: { type: "string", description: "e.g. mcp, openapi, a2a" },
              versions: { type: "array", items: { type: "string" } },
              transports: { type: "array", items: { type: "string" } },
              auth: { type: "array", items: { type: "string" } },
            },
            required: ["protocol"],
          },
        },
        prefer: { type: "array", description: "Optional cross-protocol tie-break order.", items: { type: "string" } },
      },
    },
  },
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
  {
    name: "connect_domain",
    title: "Get a connection plan for this client",
    description:
      "Given a domain AND the calling client's capabilities, return HOW the client can connect: one " +
      "outcome (ready | credentials-required | incomplete | broken | no-compatible-method) with a connection plan " +
      "(protocol, endpoint, transport, version, and the auth metadata the service published — e.g. the " +
      "OAuth authorize/token endpoints and scopes), or the exact missing field when the service " +
      "under-publishes. Deterministic matching, no scores. Read-only; credentials stay with the caller " +
      "and are never sent to NessGate.",
    inputSchema: MCP_CONNECT_INPUT,
  },
  {
    name: "check_readiness",
    title: "Check how ready a domain's endpoints are to connect to",
    description:
      "Given a domain, return each connectable resource it publishes with a readiness assessment " +
      "(ready | credentials-required | incomplete | broken, with the exact missing field) read from the service's " +
      "own metadata. Client-agnostic; read-only. Use connect_domain when you know the client's capabilities.",
    inputSchema: MCP_DOMAIN_INPUT,
  },
];

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

// --- Anonymous categorical operational events (Charter Promise 6) ---
// Pure classification of a discovery call's outcome from what the resolver
// already returned. Exported so it can be unit-tested directly.
export function discoveryOutcome(status, body) {
  if (status === 429 || status >= 500) return "error";
  const n = body && Array.isArray(body.resources) ? body.resources.length : 0;
  return n > 0 ? "resources" : "empty";
}
// Emits ONE event per discovery call: a single outcome label and a timestamp,
// nothing else — no domain, request body, IP, or identity, and no client
// classification (it takes no `request`, so it has no access to the caller). It
// is downstream-only: it reads a finished outcome and never influences
// discovery, classification, or authority. Swallowed so it can never affect a
// response. Enforced by scripts/test-metrics-isolation.mjs.
function recordDiscovery(env, outcome) {
  try { if (env && env.METRICS) env.METRICS.writeDataPoint({ indexes: [outcome], blobs: [outcome] }); }
  catch { /* measurement must never affect the request path */ }
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
    const args = (msg.params && msg.params.arguments) || {};
    const handler = name === "discover_domain" ? mcpToolResult : name === "connect_domain" ? mcpConnectResult : name === "check_readiness" ? mcpReadinessResult : null;
    if (!handler) {
      return json(rpcError(msg.id, -32602, `Unknown tool: ${String(name)}`), 200, headers);
    }
    let result;
    try {
      result = await handler(args, env, ctx, request);
    } catch {
      recordDiscovery(env, "error");
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
    recordDiscovery(env, "invalid");
    return {
      content: [{ type: "text", text: "Invalid domain. Provide a bare registrable domain like example.com." }],
      isError: true,
    };
  }
  const { status, body } = await discoverData(domain, env, ctx, request);
  recordDiscovery(env, discoveryOutcome(status, body));
  const text = JSON.stringify(body, null, 2);
  const out = { content: [{ type: "text", text }], isError: status === 429 || status >= 500 };
  if (body && typeof body === "object" && !Array.isArray(body)) out.structuredContent = body;
  return out;
}

// connect_domain over MCP — same behavior as POST /connect/{domain}, one tool, two
// transports. The client's capabilities ride in args.client (input only, never stored).
async function mcpConnectResult(args, env, ctx, request) {
  const domain = normalizeDomain(args.domain, true);
  if (!domain) {
    recordDiscovery(env, "connect:invalid");
    return { content: [{ type: "text", text: "Invalid domain. Provide a bare registrable domain like example.com." }], isError: true };
  }
  const client = args && typeof args.client === "object" && args.client ? args.client : {};
  const { status, body } = await connectData(domain, env, ctx, request, client); // records connect:<outcome>
  const out = { content: [{ type: "text", text: JSON.stringify(body, null, 2) }], isError: status === 429 || status >= 500 };
  if (body && typeof body === "object" && !Array.isArray(body)) out.structuredContent = body;
  return out;
}

// check_readiness over MCP — same behavior as GET /explore/{domain}?readiness=1.
async function mcpReadinessResult(args, env, ctx, request) {
  const domain = normalizeDomain(args.domain, true);
  if (!domain) {
    recordDiscovery(env, "readiness:invalid");
    return { content: [{ type: "text", text: "Invalid domain. Provide a bare registrable domain like example.com." }], isError: true };
  }
  const { status, body } = await exploreData(domain, env, ctx, request, [], false, false, true); // readiness=1; records readiness:<agg>
  const out = { content: [{ type: "text", text: JSON.stringify(body, null, 2) }], isError: status === 429 || status >= 500 };
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
          `<div class="panel"><p class="status no">No supported resources could be confirmed on this exact host</p>` +
          `<p class="meta">NessGate checked the standard discovery locations on ${safeDomain} itself ` +
          `(ARD, A2A, llms.txt, API catalogs, OpenAPI and more) and could not confirm any. This is an exact-host ` +
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
async function safeFetch(url, allowedDomain, maxBytes, strictHosts = false, userAgent = "NessGate-Discover/1.0 (+https://nessgate.com)", allowCrossHost = false, returnMeta = false, truncateAtCap = false) {
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
    let truncated = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (truncateAtCap) {
        // OpenAPI prefix read: retain ONLY up to the cap (trim the final chunk),
        // then cancel. `truncated` true only when more bytes existed beyond the cap.
        const remaining = maxBytes - size;
        if (value.length >= remaining) {
          chunks.push(value.subarray(0, remaining));
          size += remaining;
          if (value.length > remaining) truncated = true;
          else { const nxt = await reader.read(); if (!nxt.done) truncated = true; }
          try { await reader.cancel(); } catch {}
          break;
        }
        chunks.push(value);
        size += value.length;
      } else {
        size += value.length;
        if (size > maxBytes) { await reader.cancel(); throw new Error("the response is too large"); }
        chunks.push(value);
      }
    }
    const buf = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.length;
    }
    const text = new TextDecoder().decode(buf);
    if (truncateAtCap) {
      // Surface the server's OWN declared size so callers can decide whether a
      // larger bounded read could ever complete (skip hopeless re-reads).
      const clRaw = res.headers && typeof res.headers.get === "function" ? res.headers.get("content-length") : null;
      const contentLength = clRaw != null && /^\d+$/.test(String(clRaw).trim()) ? Number(clRaw) : undefined;
      return { text, truncated, contentLength };
    }
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
const DNS_CHECK_CACHE = new Map(); // host -> { promise: Promise<{ok, err}>, expires }
const DNS_CHECK_TTL_MS = 60_000;

async function assertPublicDns(host) {
  const now = Date.now();
  let entry = DNS_CHECK_CACHE.get(host);
  // Cache the IN-FLIGHT promise, not just the settled result: the adapters run
  // in parallel and all check the same host at once, so a result-only cache let
  // every one of them fire its own duplicate DoH pair before the first finished
  // (subrequest waste on cold isolates).
  if (!entry || entry.expires <= now) {
    if (DNS_CHECK_CACHE.size > 500) DNS_CHECK_CACHE.delete(DNS_CHECK_CACHE.keys().next().value);
    entry = { promise: checkPublicDns(host), expires: now + DNS_CHECK_TTL_MS };
    DNS_CHECK_CACHE.set(host, entry);
  }
  const r = await entry.promise;
  if (!r.ok) throw new Error(r.err);
}

// Never rejects — always settles to { ok, err } so a shared cached promise can
// be awaited by any number of callers.
async function checkPublicDns(host) {
  const ips = [];
  for (const type of ["A", "AAAA"]) {
    const data = await dohQuery(host, type);
    for (const a of (data && data.Answer) || []) {
      if (a.type === 1 || a.type === 28) ips.push(a.data);
    }
  }
  if (ips.length === 0) return { ok: false, err: "the domain does not resolve to a public address" };
  if (ips.some((ip) => isPrivateIp(ip))) return { ok: false, err: "the domain resolves to a non-public address" };
  return { ok: true, err: "" };
}

function isPrivateIp(ip) {
  const s = String(ip).toLowerCase().trim();
  if (s.includes(":")) {
    // IPv6: loopback, unspecified, discard, link-local, unique-local, multicast,
    // v4-mapped, NAT64 and 6to4 (both embed IPv4, possibly private), doc range
    return (
      s === "::1" ||
      s === "::" ||
      s.startsWith("100:") ||
      s.startsWith("fc") ||
      s.startsWith("fd") ||
      s.startsWith("fe8") ||
      s.startsWith("fe9") ||
      s.startsWith("fea") ||
      s.startsWith("feb") ||
      s.startsWith("ff") ||
      s.startsWith("::ffff:") ||
      s.startsWith("64:ff9b") ||
      s.startsWith("2002:") ||
      s.startsWith("2001:db8")
    );
  }
  const p = s.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = p;
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
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
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
function exploreLimits() { return EXPLORE_LIMITS; }
export { normalizeDomain, escapeHtml, validateProbeContent, probeShapeOk, parseLinkRel, parseAgentmap, parseAidRecord, isPrivateIp, assertPublicDns, hostAllowedForDomain, isForbiddenHost, normalizeResources, classifyResource, isAcs, parseLlmsLinks, looksMachineReadable, isLlmsPath, classifyJson, exploreBudgetAllows, domainToNamespace, mcpRegistryRecords, verifyCandidateRecords, parseSameOrgHosts, selectOrgHosts, orgHostResponded, homepageRedirectInfo, probeFailureKind, resolutionOutcome, orgRecordsFromDoc, docRecords, isCrossRegistrable, sameRegCanonicalHost, probeShapeOkObj, parseRwsDeclaration, rwsReciprocal, parseAssetLinksWeb, nsContained, selfDomain, apiCatalog, mcpTools, adapters, exploreLimits };
