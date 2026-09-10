// NessGate — the open, neutral compatibility resolver for the agentic web.
// Given a domain, it reads whatever that domain already publishes across the
// standard machine-discovery locations (ARD, A2A, llms.txt, API catalogs,
// OpenAPI, host-meta and more) and returns ONE normalized answer, with a link
// back to each source so an agent can always verify against the domain itself.
//
// - NessGate defines nothing and stores nothing: it reads the standards a
//   domain already publishes and normalizes them. A new standard is just a new
//   adapter (DISCOVER_PROBES entry), never a competing format.
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
const DISCOVER_PROBES = [
  { type: "llms.txt", paths: ["/llms.txt"], kind: "text" },
  { type: "ard-catalog", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"], kind: "json" }, // Agentic Resource Discovery
  { type: "a2a-agent-card", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"], kind: "json" }, // A2A (both known locations)
  { type: "api-catalog", paths: ["/.well-known/api-catalog"], kind: "json" }, // RFC 9727
  { type: "ai-info.json", paths: ["/ai-info.json"], kind: "json" },
  { type: "openapi", paths: ["/openapi.json"], kind: "json" },
  { type: "ord", paths: ["/.well-known/open-resource-discovery"], kind: "json" }, // Open Resource Discovery (SAP / Linux Foundation)
  { type: "awp", paths: ["/.well-known/awp.json"], kind: "json" }, // Agent Web Protocol
  { type: "host-meta", paths: ["/.well-known/host-meta.json"], kind: "json" }, // RFC 6415
];
const DISCOVER_CACHE_SECONDS = 600;
const DISCOVER_RATE_LIMIT_PER_HOUR = 120;
const DISCOVER_UA = "NessGate-Discover/1.0 (+https://nessgate.com)";
const MAX_DISCOVER_RESOURCES = 200; // cap on the normalized resource list
const MAX_PER_SOURCE = 50; // cap per source document (defends against huge files)
const DISCOVER_NOTE =
  "These locations are published by the domain itself at standard, well-known paths. " +
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
      case "a2a-agent-card": {
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
  const settled = await Promise.allSettled(
    DISCOVER_PROBES.map(async (p) => {
      // Try each candidate location; first valid one wins. strictHosts=false:
      // apex→www redirects are legitimate for description. SSRF protections
      // inherited from safeFetch.
      for (const path of p.paths) {
        const url = `https://${domain}${path}`;
        let text;
        try {
          text = domain === SELF_DOMAIN
            ? await selfProbe(path, env, ctx)
            : await safeFetch(url, domain, MAX_JSON_BYTES, false, DISCOVER_UA);
        } catch {
          continue; // this location missing/unreachable — try the next
        }
        if (validateProbeContent(p.kind, text) && probeShapeOk(p.type, p.kind, text)) return { type: p.type, url, kind: p.kind, text };
      }
      return null;
    })
  );
  const hits = settled.filter((r) => r.status === "fulfilled" && r.value).map((r) => r.value);
  // discovered = the routing map (which standards this domain publishes, where).
  const discovered = hits.map((h) => ({ type: h.type, url: h.url }));
  // resources = the normalized union of what those documents actually contain,
  // flattened into one list. Each record keeps the source standard, the native
  // source URL, and (where useful) the raw record.
  const resources = hits
    .flatMap((h) => normalizeResources(h.type, h.kind, h.text, h.url))
    .slice(0, MAX_DISCOVER_RESOURCES);
  const body = {
    domain,
    provenance: "self-published",
    note: DISCOVER_NOTE,
    discovered,
    resources,
    checked: DISCOVER_PROBES.map((p) => p.type),
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

/* ----------------------- MCP server (read-only tool) ----------------------- */
// POST /mcp — Model Context Protocol over Streamable HTTP, stateless JSON
// responses. Exposes the resolver as a tool so AI agents can call it directly
// instead of scraping it. Same rate limits and caches as the REST endpoint
// (the tool dispatches to the same handler).

const MCP_SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26"];
const MCP_SERVER_INFO = { name: "nessgate", title: "NessGate — the neutral resolver for the agentic web", version: "1.1.0" };
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
        description: `NessGate found no standard machine-readable discovery files published by ${safeDomain}.`,
        body:
          `<h1>${safeDomain}</h1>` +
          `<div class="panel"><p class="status no">No machine-readable discovery files found</p>` +
          `<p class="meta">NessGate checked the standard well-known locations (ARD, A2A, llms.txt, ` +
          `API catalogs, OpenAPI and more) and this domain does not publish any of them yet.</p></div>` +
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
async function safeFetch(url, allowedDomain, maxBytes, strictHosts = false, userAgent = "NessGate-Discover/1.0 (+https://nessgate.com)") {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const u = new URL(current);
    if (u.protocol !== "https:") throw new Error("only HTTPS is allowed");
    const host = u.hostname.toLowerCase().replace(/\.+$/, "");
    const hostOk = strictHosts
      ? host === allowedDomain
      : hostAllowedForDomain(host, allowedDomain);
    if (isForbiddenHost(host) || !hostOk) {
      throw new Error("request left the target domain");
    }
    await assertPublicDns(host);

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
    return new TextDecoder().decode(buf);
  }
  throw new Error("too many redirects");
}

async function assertPublicDns(host) {
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
  if (ips.length === 0) throw new Error("the domain does not resolve to a public address");
  for (const ip of ips) {
    if (isPrivateIp(ip)) throw new Error("the domain resolves to a non-public address");
  }
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
function discoverProbes() { return DISCOVER_PROBES; }
export { normalizeDomain, escapeHtml, validateProbeContent, probeShapeOk, isPrivateIp, hostAllowedForDomain, isForbiddenHost, normalizeResources, selfDomain, apiCatalog, mcpTools, discoverProbes };
