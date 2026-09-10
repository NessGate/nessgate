// Regression tests for NessGate's security-critical pure logic.
// Run with `npm test`. No network required.
import {
  normalizeDomain,
  escapeHtml,
  validateProbeContent,
  probeShapeOk,
  isPrivateIp,
  hostAllowedForDomain,
  isForbiddenHost,
  apiCatalog,
  mcpTools,
  normalizeResources,
  discoverProbes,
} from "../src/worker.js";

const API_CATALOG = apiCatalog();
const MCP_TOOLS = mcpTools();

let failed = 0;
function is(actual, expected, name) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) console.log(`  ok  ${name}`);
  else {
    failed++;
    console.error(`FAIL  ${name}: got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}`);
  }
}

console.log("--- domain normalization");
is(normalizeDomain(" Example.COM "), "example.com", "trims, lowercases");
is(normalizeDomain("https://www.foo-bar.com/path?q=1"), "foo-bar.com", "strips scheme/path/www");
is(normalizeDomain("shop.example.co.uk"), "shop.example.co.uk", "keeps real subdomains");
is(normalizeDomain("example.com:8443"), "example.com", "strips port");
is(normalizeDomain("localhost"), null, "rejects localhost");
is(normalizeDomain("127.0.0.1"), null, "rejects IPv4 literal");
is(normalizeDomain("foo.internal"), null, "rejects .internal");
is(normalizeDomain("foo.localhost"), null, "rejects .localhost");
is(normalizeDomain("nessgate.com"), null, "rejects self by default (network-fetch guard)");
is(normalizeDomain("a"), null, "rejects too short");
is(normalizeDomain("münchen.de"), null, "rejects non-ASCII (punycode required)");

console.log("--- self domain on the resolver read path (allowSelf)");
is(normalizeDomain("nessgate.com", true), "nessgate.com", "resolver accepts the apex self domain");
is(normalizeDomain("www.nessgate.com", true), "nessgate.com", "www self normalizes to apex");
is(normalizeDomain("api.nessgate.com", true), null, "self SUBDOMAINS stay rejected even with allowSelf");
is(normalizeDomain("localhost", true), null, "allowSelf does not weaken other forbidden hosts");
is(normalizeDomain("evilnessgate.com", true), "evilnessgate.com", "suffix-lookalike treated as a normal domain");

console.log("--- IDN / punycode TLD acceptance");
is(normalizeDomain("example.xn--p1ai"), "example.xn--p1ai", "accepts punycode TLD (.рф)");
is(normalizeDomain("sub.example.xn--p1ai"), "sub.example.xn--p1ai", "accepts subdomain under punycode TLD");
is(normalizeDomain("xn--e1afmapc.xn--p1ai"), "xn--e1afmapc.xn--p1ai", "accepts punycode label + punycode TLD");
is(normalizeDomain("example.xn--"), null, "rejects bare xn-- with no suffix content");

console.log("--- private/reserved IP detection (SSRF)");
is(isPrivateIp("10.1.2.3"), true, "10/8");
is(isPrivateIp("172.16.0.1"), true, "172.16/12");
is(isPrivateIp("192.168.1.1"), true, "192.168/16");
is(isPrivateIp("169.254.169.254"), true, "link-local/metadata");
is(isPrivateIp("127.0.0.1"), true, "loopback");
is(isPrivateIp("100.64.0.1"), true, "CGNAT");
is(isPrivateIp("8.8.8.8"), false, "public v4 ok");
is(isPrivateIp("::1"), true, "v6 loopback");
is(isPrivateIp("fd12::1"), true, "v6 unique-local");
is(isPrivateIp("fe80::1"), true, "v6 link-local");
is(isPrivateIp("2606:4700::1111"), false, "public v6 ok");

console.log("--- host allowances");
is(hostAllowedForDomain("example.com", "example.com"), true, "apex allowed");
is(hostAllowedForDomain("api.example.com", "example.com"), true, "subdomain allowed");
is(hostAllowedForDomain("evilexample.com", "example.com"), false, "suffix-confusion rejected");
is(isForbiddenHost("metadata.google.internal"), true, "internal suffix forbidden");
is(isForbiddenHost("nessgate.com"), true, "self forbidden (never fetch ourselves over the network)");

console.log("--- discovery probe content validation (/discover)");
is(validateProbeContent("json", '{"name":"Acme Agent"}'), true, "json object accepted");
is(validateProbeContent("json", "[1,2,3]"), true, "json array accepted");
is(validateProbeContent("json", "<!doctype html><html>spa shell</html>"), false, "SPA catch-all HTML rejected for json probe");
is(validateProbeContent("json", "not json at all"), false, "non-JSON rejected");
is(validateProbeContent("json", '"just a string"'), false, "bare JSON string rejected (not an object)");
is(validateProbeContent("json", ""), false, "empty body rejected");
is(validateProbeContent("text", "# Acme\n> AI guidance"), true, "plain text/markdown accepted");
is(validateProbeContent("text", "  <!DOCTYPE html><html>"), false, "catch-all HTML rejected for text probe");
is(validateProbeContent("text", "<html lang=\"en\">"), false, "html tag rejected for text probe");
is(validateProbeContent("text", "   \n  "), false, "whitespace-only rejected");

console.log("--- per-type probe shape validation (no JSON catch-all false positives)");
is(probeShapeOk("ard-catalog", "json", '{"entries":[]}'), true, "ARD with entries[] accepted");
is(probeShapeOk("ard-catalog", "json", "{}"), false, "empty {} at an ARD path rejected (catch-all guard)");
is(probeShapeOk("a2a-agent-card", "json", '{"name":"Ag"}'), true, "A2A card with name accepted");
is(probeShapeOk("a2a-agent-card", "json", '{"supportedInterfaces":[{"url":"https://x/a"}]}'), true, "A2A v1.0 card with supportedInterfaces accepted");
is(probeShapeOk("a2a-agent-card", "json", "{}"), false, "empty {} at an A2A path rejected");
is(probeShapeOk("api-catalog", "json", '{"linkset":[]}'), true, "api-catalog with linkset accepted");
is(probeShapeOk("api-catalog", "json", "{}"), false, "empty {} at api-catalog rejected");
is(probeShapeOk("openapi", "json", '{"openapi":"3.0.0"}'), true, "openapi with version accepted");
is(probeShapeOk("openapi", "json", "{}"), false, "empty {} at /openapi.json rejected");
is(probeShapeOk("host-meta", "json", '{"links":[]}'), true, "host-meta with links accepted");
is(probeShapeOk("ai-info.json", "json", "{}"), true, "ai-info.json (informal) accepts any object");
is(probeShapeOk("llms.txt", "text", "# anything"), true, "text probes always pass shape check");

console.log("--- discovery probe set (the adapter list)");
{
  const probes = discoverProbes();
  is(probes.length, 9, "nine standards probed");
  is(probes.every((p) => p.type && Array.isArray(p.paths) && p.paths.length >= 1 && (p.kind === "json" || p.kind === "text")), true, "every probe has a type, at least one path, and a valid kind");
  is(probes.find((p) => p.type === "ard-catalog").paths.includes("/.well-known/ard.json"), true, "ARD probe checks /.well-known/ard.json");
  is(probes.find((p) => p.type === "a2a-agent-card").paths.length, 2, "A2A probe checks both known agent-card locations");
}

console.log("--- resolver normalization (thin, source-labelled, never invents semantics)");
{
  const N = (t, k, x, u) => normalizeResources(t, k, typeof x === "string" ? x : JSON.stringify(x), u);
  // ARD entries flatten, keeping the source media type and identifier + raw.
  const ard = N("ard-catalog", "json", { entries: [
    { identifier: "urn:air:x.com:n:r-1", displayName: "Data", type: "application/json", url: "https://x.com/a.json" },
    { displayName: "no url" },
  ] }, "https://x.com/.well-known/ard.json");
  is(ard.length, 1, "ARD: only entries with a url are emitted");
  is(ard[0].source, "ard-catalog", "ARD: source recorded");
  is(ard[0].sourceUrl, "https://x.com/.well-known/ard.json", "ARD: native source URL preserved");
  is(ard[0].type, "application/json", "ARD: source's own media type reused, not reinterpreted");
  is(ard[0].url, "https://x.com/a.json", "ARD: resource url");
  is(ard[0].id, "urn:air:x.com:n:r-1", "ARD: identifier preserved");
  is(!!ard[0].raw, true, "ARD: raw record preserved");
  // host-meta links → rel/type reused.
  const hm = N("host-meta", "json", { links: [{ rel: "hub", type: "application/json", href: "https://x.com/h" }, { rel: "noHref" }] }, "https://x.com/.well-known/host-meta.json");
  is(hm.length, 1, "host-meta: only links with href emitted");
  is(hm[0].type, "application/json", "host-meta: link type reused");
  is(hm[0].rel, "hub", "host-meta: rel preserved");
  // linkset (api-catalog) → iterate rel arrays, skip scalar anchor.
  const lc = N("api-catalog", "json", { linkset: [{ anchor: "https://x.com/api", "service-desc": [{ href: "https://x.com/openapi.json", type: "application/openapi+json" }] }] }, "https://x.com/.well-known/api-catalog");
  is(lc.length, 1, "linkset: one link extracted, anchor scalar skipped");
  is(lc[0].url, "https://x.com/openapi.json", "linkset: href extracted");
  is(lc[0].rel, "service-desc", "linkset: rel key preserved");
  // AWP protocols block (object map form).
  const awp = N("awp", "json", { protocols: { mcp: { url: "https://mcp.x.com" }, a2a: "https://x.com/.well-known/agent.json" } }, "https://x.com/.well-known/awp.json");
  is(awp.length, 2, "AWP: both protocol entries extracted (object + string forms)");
  is(awp.find((r) => r.type === "mcp").url, "https://mcp.x.com", "AWP: object-form url");
  is(awp.find((r) => r.type === "a2a").url, "https://x.com/.well-known/agent.json", "AWP: string-form url");
  // A2A v1.0: endpoint lives in supportedInterfaces[], not a top-level url.
  const a2a10 = N("a2a-agent-card", "json", { name: "Ag", supportedInterfaces: [{ url: "https://x.com/a2a", transport: "JSONRPC" }] }, "https://x.com/.well-known/agent-card.json");
  is(a2a10[0].url, "https://x.com/a2a", "A2A v1.0: url taken from supportedInterfaces[0]");
  is(a2a10[0].raw.supportedInterfaces.length, 1, "A2A v1.0: supportedInterfaces preserved in raw");
  const a2aLegacy = N("a2a-agent-card", "json", { name: "Ag", url: "https://x.com/legacy" }, "https://x.com/.well-known/agent-card.json");
  is(a2aLegacy[0].url, "https://x.com/legacy", "A2A: explicit top-level url still preferred");
  // ARD entries may carry inline data instead of a url.
  const ardData = N("ard-catalog", "json", { entries: [{ identifier: "urn:x:1", displayName: "Inline", type: "application/json", data: { a: 1 } }] }, "https://x.com/.well-known/ard.json");
  is(ardData.length, 1, "ARD: inline-data entry is kept (not dropped)");
  is(ardData[0].url, "https://x.com/.well-known/ard.json", "ARD: inline-data entry points back to the catalog");
  is(ardData[0].inline, true, "ARD: inline-data entry flagged");
  // Pointer standards: point to the file, do not parse.
  is(N("llms.txt", "text", "# Acme\n> stuff", "https://x.com/llms.txt")[0].url, "https://x.com/llms.txt", "llms.txt: points to the file, prose not parsed");
  is(N("ord", "json", { openResourceDiscoveryV1: {} }, "https://x.com/.well-known/open-resource-discovery")[0].type, "ord", "ORD: pointer only (no enterprise-schema interpretation)");
  // Never throws on garbage.
  is(N("ard-catalog", "json", "{not json", "https://x.com/a").length, 0, "malformed JSON → empty, never throws");
  is(N("host-meta", "json", { links: "not-an-array" }, "https://x.com/h").length, 0, "unexpected shape → empty");

  // Parity: the embeddable library (public/resolver.mjs) must normalize
  // IDENTICALLY to the reference worker, or the standard forks silently.
  const lib = await import("../public/resolver.mjs");
  const samples = [
    ["ard-catalog", "json", JSON.stringify({ entries: [{ identifier: "urn:air:x.com:n:r-1", displayName: "D", type: "application/json", url: "https://x.com/a.json" }, { type: "x", url: "https://x.com/b" }] }), "https://x.com/.well-known/ard.json"],
    ["host-meta", "json", JSON.stringify({ links: [{ rel: "hub", type: "application/json", href: "https://x.com/h" }] }), "https://x.com/.well-known/host-meta.json"],
    ["api-catalog", "json", JSON.stringify({ linkset: [{ anchor: "https://x.com/api", "service-desc": [{ href: "https://x.com/o.json", type: "application/openapi+json" }] }] }), "https://x.com/.well-known/api-catalog"],
    ["awp", "json", JSON.stringify({ protocols: { mcp: { url: "https://mcp.x.com" }, a2a: "https://x.com/.well-known/agent.json" } }), "https://x.com/.well-known/awp.json"],
    ["a2a-agent-card", "json", JSON.stringify({ name: "Ag", url: "https://x.com/agent", version: "1" }), "https://x.com/.well-known/agent-card.json"],
    ["openapi", "json", JSON.stringify({ openapi: "3.0.0", info: { title: "API" } }), "https://x.com/openapi.json"],
    ["llms.txt", "text", "# X", "https://x.com/llms.txt"],
    ["ord", "json", JSON.stringify({ openResourceDiscoveryV1: {} }), "https://x.com/.well-known/open-resource-discovery"],
    ["a2a-agent-card", "json", JSON.stringify({ name: "Ag", supportedInterfaces: [{ url: "https://x.com/a2a", transport: "JSONRPC" }] }), "https://x.com/.well-known/agent-card.json"],
    ["ard-catalog", "json", JSON.stringify({ entries: [{ identifier: "urn:x:1", displayName: "Inline", type: "application/json", data: { a: 1 } }] }), "https://x.com/.well-known/ard.json"],
  ];
  for (const [t, k, x, u] of samples) {
    is(
      JSON.stringify(lib.normalizeResources(t, k, x, u)),
      JSON.stringify(normalizeResources(t, k, x, u)),
      `library/worker normalization parity for ${t}`
    );
  }
  // Probe lists must match too (same standards, same paths, same order).
  is(JSON.stringify(lib.PROBES), JSON.stringify(discoverProbes()), "library probe list matches worker");
  // probeShapeOk must match the worker too (false-positive guard can't fork).
  const shapeSamples = [
    ["ard-catalog", "json", "{}"], ["ard-catalog", "json", '{"entries":[]}'],
    ["a2a-agent-card", "json", "{}"], ["a2a-agent-card", "json", '{"supportedInterfaces":[]}'],
    ["api-catalog", "json", "{}"], ["openapi", "json", "{}"], ["openapi", "json", '{"openapi":"3.0.0"}'],
    ["ai-info.json", "json", "{}"], ["llms.txt", "text", "# x"],
  ];
  for (const [t, k, x] of shapeSamples) {
    is(lib.probeShapeOk(t, k, x), probeShapeOk(t, k, x), `library/worker probeShapeOk parity for ${t} ${k}`);
  }
}

console.log("--- npm package parity (packages/resolver)");
{
  const { readFileSync } = await import("node:fs");
  const served = readFileSync(new URL("../public/resolver.mjs", import.meta.url), "utf8");
  const pkg = readFileSync(new URL("../packages/resolver/index.mjs", import.meta.url), "utf8");
  is(served === pkg, true, "packages/resolver/index.mjs is byte-identical to public/resolver.mjs");
}

console.log("--- RFC 9727 api-catalog + MCP tool shapes");
is(Array.isArray(API_CATALOG.linkset) && API_CATALOG.linkset.length === 1, true, "api-catalog is a linkset with one API");
is(!!API_CATALOG.linkset[0].anchor, true, "linkset context has an anchor");
is(API_CATALOG.linkset[0]["service-desc"][0].href, "https://nessgate.com/openapi.json", "service-desc links the OpenAPI description");
is(MCP_TOOLS.map((t) => t.name), ["discover_domain"], "MCP exposes exactly the one resolver tool");
is(
  MCP_TOOLS.every((t) => t.description && t.inputSchema && t.inputSchema.required.includes("domain")),
  true,
  "the MCP tool has a description and requires a domain argument"
);

console.log("--- HTML escaping (resource labels are attacker-controlled display text)");
is(
  escapeHtml(`<script>alert("x")</script>' &`),
  "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&#39; &amp;",
  "all HTML-special characters escaped"
);

console.log(failed ? `\n${failed} FAILURES` : "\nAll regression tests passed.");
process.exit(failed ? 1 : 0);
