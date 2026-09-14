// Regression tests for NessGate's security-critical pure logic.
// Run with `npm test`. No network required.
import {
  normalizeDomain,
  escapeHtml,
  validateProbeContent,
  probeShapeOk,
  parseLinkRel,
  parseAgentmap,
  parseAidRecord,
  isPrivateIp,
  hostAllowedForDomain,
  isForbiddenHost,
  apiCatalog,
  mcpTools,
  normalizeResources,
  isAcs,
  parseLlmsLinks,
  looksMachineReadable,
  isLlmsPath,
  classifyJson,
  exploreBudgetAllows,
  domainToNamespace,
  mcpRegistryRecords,
  verifyCandidateRecords,
  parseSameOrgHosts,
  orgRecordsFromDoc,
  adapters,
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
is(probeShapeOk("anp", "json", '{"items":[]}'), true, "ANP with items[] accepted");
is(probeShapeOk("anp", "json", '{"@type":"CollectionPage"}'), true, "ANP CollectionPage accepted");
is(probeShapeOk("anp", "json", "{}"), false, "empty {} at ANP path rejected");
is(probeShapeOk("ucp", "json", '{"ucp_version":"2026-01"}'), true, "UCP with ucp_version accepted");
is(probeShapeOk("ucp", "json", '{"capabilities":[]}'), true, "UCP with capabilities[] accepted");
is(probeShapeOk("ucp", "json", "{}"), false, "empty {} at UCP path rejected");
is(probeShapeOk("gbz-185-4", "json", '{"aic":"","name":"Svc"}'), true, "GB/Z 185.4 ACS (aic marker) accepted");
is(probeShapeOk("gbz-185-4", "json", '{"name":"Svc","certificate":{"requestedValidity":365}}'), true, "GB/Z 185.4 ACS (certificate marker) accepted");
is(probeShapeOk("gbz-185-4", "json", '{"name":"Plain A2A card"}'), false, "plain A2A card is NOT a GB/Z ACS");
is(probeShapeOk("gbz-185-4", "json", "{}"), false, "empty {} is not an ACS");

console.log("--- adapter set (universal-resolver channels)");
{
  const A = adapters();
  const CHANNELS = new Set(["well-known", "link-rel", "robots", "dns"]);
  is(A.length, 14, "fourteen active adapters");
  is(A.every((a) => a.id && CHANNELS.has(a.channel)), true, "every adapter has an id and a known channel");
  is(A.find((a) => a.id === "ard-catalog").paths.includes("/.well-known/ard.json"), true, "ARD well-known path present");
  is(A.find((a) => a.id === "ard-link").channel, "link-rel", "ARD <link rel> is a link-rel adapter");
  is(A.find((a) => a.id === "ard-agentmap").channel, "robots", "ARD Agentmap is a robots adapter");
  is(A.find((a) => a.id === "anp").paths[0], "/.well-known/agent-descriptions", "ANP well-known path");
  is(A.find((a) => a.id === "ucp").paths.includes("/.well-known/ucp"), true, "UCP well-known path");
  is(A.find((a) => a.id === "aid").channel, "dns", "AID is a dns adapter");
  is(A.find((a) => a.id === "aid").node, "_agent", "AID queries the _agent TXT node (v=aid1) — distinct from the IETF DNS-AID SVCB draft");
  is(A.some((a) => a.id === "dns-aid"), false, "the old mislabel 'dns-aid' is gone (AID != IETF DNS-AID)");
  is(A.some((a) => a.id === "gbz-185" || a.id === "gbz-185-4" || a.id === "gbz-185-5"), false, "GB/Z has NO discovery adapter (185.4 is content-recognised; 185.5 is library opt-in) — no guessed path");
}

console.log("--- new-channel parsers (ARD link-rel / robots Agentmap / DNS-AID)");
is(parseLinkRel('<link rel="ard" href="/c.json"><link rel=stylesheet href=x.css><link rel="ai-catalog" href="https://x.com/d.json">', ["ard", "ai-catalog"]), ["/c.json", "https://x.com/d.json"], "link-rel: extracts ard + ai-catalog, skips stylesheet");
is(parseLinkRel("<p>no links</p>", ["ard"]), [], "link-rel: none when absent");
is(parseAgentmap("User-agent: *\nAgentmap: https://x.com/entries.json\nAllow: /", "agentmap"), ["https://x.com/entries.json"], "Agentmap: URL extracted (case-insensitive)");
is(parseAgentmap("Sitemap: https://x.com/sitemap.xml", "agentmap"), [], "Agentmap: none when only a Sitemap present");
{
  const aid = parseAidRecord("v=aid1;u=https://api.example.com/mcp;p=mcp;a=pat;s=Example Tools");
  is(aid.version, "aid1", "AID: version");
  is(aid.uri, "https://api.example.com/mcp", "AID: uri");
  is(aid.proto, "mcp", "AID: proto");
  is(parseAidRecord("version=aid1;uri=https://x/y;proto=a2a").uri, "https://x/y", "AID: long-form keys accepted");
  is(parseAidRecord("just some text"), null, "AID: garbage → null");
  is(parseAidRecord("p=mcp;a=pat"), null, "AID: missing version+uri → null");
}

console.log("--- Explore v2 helpers: llms.txt link-following, machine-readable filter, JSON classify");
is(
  parseLlmsLinks("# Docs\n- [API](https://x.com/api/llms.txt)\n- [Guide](https://x.com/guide.html)\nSee https://x.com/ai-info.json for more."),
  ["https://x.com/api/llms.txt", "https://x.com/guide.html", "https://x.com/ai-info.json"],
  "parseLlmsLinks: markdown links + bare URLs extracted"
);
is(looksMachineReadable("https://x.com/api/llms.txt"), true, "looksMachineReadable: llms.txt");
is(looksMachineReadable("https://x.com/.well-known/ard.json"), true, "looksMachineReadable: json / well-known");
is(looksMachineReadable("https://x.com/guide.html"), false, "looksMachineReadable: html page skipped (not followed)");
is(looksMachineReadable("https://x.com/security.txt"), false, "looksMachineReadable: generic .txt NOT followed (only llms.txt)");
is(looksMachineReadable("https://x.com/.well-known/security.txt"), true, "looksMachineReadable: well-known path allowed");
is(looksMachineReadable("not a url"), false, "looksMachineReadable: garbage → false");
is(isLlmsPath("https://x.com/llms.txt"), true, "isLlmsPath: /llms.txt");
is(isLlmsPath("https://x.com/docs/llms-full.txt"), true, "isLlmsPath: llms-full.txt");
is(isLlmsPath("https://x.com/security.txt"), false, "isLlmsPath: other .txt is NOT llms.txt (no false llms label)");
is(classifyJson('{"entries":[]}'), "ard-catalog", "classifyJson: ARD catalog");
is(classifyJson('{"openapi":"3.0.0"}'), "openapi", "classifyJson: OpenAPI");
is(classifyJson('{"aic":"x","name":"A","certificate":{"requestedValidity":1}}'), "gbz-185-4", "classifyJson: GB/Z ACS recognized");
is(classifyJson('{"name":"Card","supportedInterfaces":[{"url":"https://x/a"}]}'), "a2a-agent-card", "classifyJson: A2A needs A2A-specific structure");
is(classifyJson('{"name":"NessReady","url":"https://x"}'), null, "classifyJson: bare name/url (ai-info-like) NOT mislabelled as A2A");
is(classifyJson('{"random":true}'), null, "classifyJson: unknown JSON → null");
is(classifyJson("not json"), null, "classifyJson: non-JSON → null");

console.log("--- Explore v2 budgets: global bytes + redirect-host accounting");
{
  const L = { maxHosts: 8, maxTotalBytes: 6_000_000 };
  const b1 = { hosts: new Set(), bytes: 0, truncated: false };
  exploreBudgetAllows(b1, { hosts: ["a.com", "b.com"], bytes: 100 }, L); // A→B redirect
  is(b1.hosts.size, 2, "redirect hosts BOTH counted against the host budget");
  is(b1.bytes, 100, "bytes accumulated into the global byte budget");
  const b2 = { hosts: new Set(), bytes: 0, truncated: false };
  exploreBudgetAllows(b2, { hosts: ["x.com"], bytes: 5_000_000 }, L);
  is(b2.truncated, false, "under the global byte budget: not truncated");
  is(exploreBudgetAllows(b2, { hosts: ["y.com"], bytes: 2_000_000 }, L), false, "exceeding the global byte budget returns false");
  is(b2.truncated, true, "global byte budget trips truncation");
  const b3 = { hosts: new Set(), bytes: 0, truncated: false };
  exploreBudgetAllows(b3, { hosts: ["1", "2", "3", "4", "5", "6", "7", "8", "9"], bytes: 1 }, L);
  is(b3.truncated, true, "exceeding the host budget trips truncation");
}

console.log("--- Explore v2 registry federation (attributed, namespace-verified)");
is(domainToNamespace("example.com"), "com.example", "domainToNamespace: example.com → com.example");
is(domainToNamespace("nessgate.com"), "com.nessgate", "domainToNamespace: nessgate.com → com.nessgate");
is(domainToNamespace("sub.example.co.uk"), "uk.co.example.sub", "domainToNamespace: exact reverse, no PSL guessing");
is(domainToNamespace("notadomain"), null, "domainToNamespace: no dot → null");
{
  const reg = JSON.stringify({ servers: [
    { server: { name: "com.example/tools", version: "1.0.0", remotes: [{ type: "streamable-http", url: "https://mcp.example.com/mcp" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active" } } },
    { server: { name: "com.example/old", remotes: [{ url: "https://x" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "deleted" } } },
    { server: { name: "io.github.example/other", remotes: [{ url: "https://y" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active" } } },
    { server: { name: "com.examples/lookalike", remotes: [{ url: "https://z" }] } },
  ] });
  const recs = mcpRegistryRecords(reg, "com.example", "example.com");
  is(recs.length, 1, "registry: only the active, exact-namespace com.example/* server is kept");
  is(recs[0].name, "com.example/tools", "registry: correct server matched (not io.github.*, not com.examples lookalike, not deleted)");
  is(recs[0].evidence, "namespace-verified", "registry: evidence class namespace-verified");
  is(recs[0].url, "https://mcp.example.com/mcp", "registry: remote url extracted");
  is(/verified control of the namespace .* NessGate did not verify this itself/.test(recs[0].attribution), true, "registry: attributed to the registry, not re-claimed by NessGate");
  is(mcpRegistryRecords("not json", "com.example", "example.com").length, 0, "registry: garbage → empty");
}

console.log("--- Explore v2 candidate verification (opt-in; AI suggests, NessGate verifies)");
{
  const llms = verifyCandidateRecords("https://x.com/api/llms.txt", "# Docs\n- [a](https://x.com/a)");
  is(llms.length, 1, "candidate: an llms.txt is verified");
  is(llms[0].evidence, "candidate", "candidate: labelled evidence:candidate");
  is(JSON.stringify(llms[0].provenance), JSON.stringify(["ai-candidate", "https://x.com/api/llms.txt"]), "candidate: provenance marks it AI-suggested");
  const ard = verifyCandidateRecords("https://x.com/c.json", JSON.stringify({ entries: [{ type: "application/json", url: "https://x.com/a.json" }] }));
  is(ard.length, 1, "candidate: a classifiable JSON (ARD) is verified");
  is(ard[0].evidence, "candidate", "candidate: JSON resource labelled candidate");
  is(verifyCandidateRecords("https://x.com/page.json", '{"random":true}').length, 0, "candidate: unrecognized JSON is NOT accepted (relationship never invented)");
  is(verifyCandidateRecords("https://x.com/notes.txt", "just text").length, 0, "candidate: a non-llms .txt is not accepted as a resource");
  // Redirect provenance: the original suggested URL AND the final URL are both kept.
  const redir = verifyCandidateRecords(
    "https://b.com/final/llms.txt",
    "# x",
    ["https://a.com/suggested/llms.txt", "https://b.com/final/llms.txt"]
  );
  is(
    JSON.stringify(redir[0].provenance),
    JSON.stringify(["ai-candidate", "https://a.com/suggested/llms.txt", "https://b.com/final/llms.txt"]),
    "candidate: full original→final redirect chain preserved in provenance"
  );
  is(redir[0].url, "https://b.com/final/llms.txt", "candidate: record points to the FINAL url (where the content is)");
}

console.log("--- Explore v2 Organization Discovery (opt-in, bounded, verified-only)");
{
  const html = '<a href="https://developers.example.com/docs">Docs</a> <a href="https://twitter.com/example">X</a> <img src="https://cdn.example.com/logo.png"> <a href="https://www.example.com/about">About</a> <a href="https://developers.example.com/api">API</a>';
  is(
    parseSameOrgHosts(html, "example.com"),
    ["developers.example.com", "cdn.example.com"],
    "parseSameOrgHosts: same-domain subdomains only, unique, cross-domain + www/apex excluded"
  );
  is(parseSameOrgHosts("no links here", "example.com"), [], "parseSameOrgHosts: none → empty");
  is(parseSameOrgHosts(html, "other.org"), [], "parseSameOrgHosts: wrong domain → empty");
  const orgLlms = orgRecordsFromDoc("https://developers.example.com/llms.txt", "# Dev docs\n- [API](https://developers.example.com/api.md)", "conventional");
  is(orgLlms.length, 1, "org: a real llms.txt on a related host is reported");
  is(orgLlms[0].evidence, "same-domain-host", "org: labelled same-domain-host");
  is(JSON.stringify(orgLlms[0].provenance), JSON.stringify(["org:conventional", "https://developers.example.com/llms.txt"]), "org: provenance records how the host was found");
  is(orgRecordsFromDoc("https://docs.example.com/llms.txt", "<!doctype html><html>SPA shell</html>", "conventional").length, 0, "org: an SPA catch-all shell is NOT reported (wildcard-DNS guard)");
  const orgArd = orgRecordsFromDoc("https://developers.example.com/.well-known/ard.json", JSON.stringify({ entries: [{ type: "application/json", url: "https://developers.example.com/a.json" }] }), "homepage-link");
  is(orgArd.length, 1, "org: an ARD catalog on a related host is normalized");
  is(orgArd[0].evidence, "same-domain-host", "org: ARD entries labelled same-domain-host");
  is(orgRecordsFromDoc("https://api.example.com/page.json", '{"random":true}', "conventional").length, 0, "org: unrecognized JSON is not reported");
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
  // ANP: CollectionPage items[] → one record per agent description.
  const anp = N("anp", "json", { "@type": "CollectionPage", items: [{ "@type": "ad:AgentDescription", name: "Bot", "@id": "https://x.com/agents/bot.json" }, { name: "no id" }] }, "https://x.com/.well-known/agent-descriptions");
  is(anp.length, 1, "ANP: only items with @id emitted");
  is(anp[0].url, "https://x.com/agents/bot.json", "ANP: @id becomes the url");
  is(anp[0].type, "agent-description", "ANP: labelled agent-description");
  is(anp[0].name, "Bot", "ANP: name preserved");
  // UCP: capabilities[] with transport bindings.
  const ucp = N("ucp", "json", { ucp_version: "2026-01", capabilities: [{ name: "checkout", transports: [{ type: "mcp", url: "https://x.com/mcp" }, { type: "rest", endpoint: "https://x.com/api" }] }] }, "https://x.com/.well-known/ucp");
  is(ucp.length, 2, "UCP: one record per transport binding");
  is(ucp[0].url, "https://x.com/mcp", "UCP: transport url");
  is(ucp.find((r) => r.type === "rest").url, "https://x.com/api", "UCP: transport endpoint alias");
  is(N("ucp", "json", { ucp_version: "2026-01", capabilities: [] }, "https://x.com/.well-known/ucp")[0].url, "https://x.com/.well-known/ucp", "UCP: no endpoints → points to the profile");

  // GB/Z 185.4 ACS recognition + normalization (China 智能体互联).
  is(isAcs({ aic: "", name: "X" }), true, "isAcs: aic marker + name");
  is(isAcs({ name: "X", certificate: { requestedValidity: 1825 } }), true, "isAcs: certificate.requestedValidity marker");
  is(isAcs({ name: "A2A card", url: "https://x/a" }), false, "isAcs: plain A2A card rejected");
  is(isAcs({ aic: "id" }), false, "isAcs: marker without agent-desc shape rejected");
  const acs = { aic: "urn:acps:001", protocolVersion: "02.02", name: "registry-service", description: "d", version: "2.2.0", provider: { organization: "ACPs Working Group", url: "https://ioa.pub" }, securitySchemes: { mtls: { type: "mutualTLS" } }, certificate: { requestedValidity: 1825 }, capabilities: { streaming: false, messageQueue: [] }, endPoints: [{ url: "https://x.com/agent" }], skills: [] };
  const acsRec = N("a2a-agent-card", "json", acs, "https://x.com/.well-known/agent-card.json");
  is(acsRec.length, 1, "ACS at the agent-card location → one record");
  is(acsRec[0].source, "gbz-185-4", "ACS labelled gbz-185-4 (not plain A2A) at the agent-description location");
  is(acsRec[0].type, "gbz-185-4-acs", "ACS: record type");
  is(acsRec[0].url, "https://x.com/agent", "ACS: url taken from endPoints");
  is(acsRec[0].raw.aic, "urn:acps:001", "ACS: agent identity code (aic) preserved");
  is(!!acsRec[0].raw.securitySchemes.mtls, true, "ACS: mTLS security scheme preserved");
  is(acsRec[0].sourceUrl, "https://x.com/.well-known/agent-card.json", "ACS: provenance (sourceUrl) preserved");
  is(N("gbz-185-4", "json", acs, "https://gw.example/acps-adp-v2/discover")[0].source, "gbz-185-4", "direct gbz-185-4 normalization (used by the 185.5 gateway path)");
  is(N("a2a-agent-card", "json", { name: "Ag", url: "https://x.com/a" }, "https://x.com/.well-known/agent-card.json")[0].source, "a2a-agent-card", "a plain A2A card at the same location is still A2A, not GB/Z");

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
    ["anp", "json", JSON.stringify({ "@type": "CollectionPage", items: [{ "@id": "https://x.com/a.json", name: "B" }] }), "https://x.com/.well-known/agent-descriptions"],
    ["ucp", "json", JSON.stringify({ ucp_version: "2026-01", capabilities: [{ name: "c", transports: [{ type: "mcp", url: "https://x.com/mcp" }] }] }), "https://x.com/.well-known/ucp"],
    ["a2a-agent-card", "json", JSON.stringify({ aic: "id-1", name: "Svc", protocolVersion: "02.02", securitySchemes: { mtls: { type: "mutualTLS" } }, certificate: { requestedValidity: 1825 }, capabilities: { messageQueue: [] }, endPoints: [{ url: "https://x.com/a" }] }), "https://x.com/.well-known/agent-card.json"],
    ["gbz-185-4", "json", JSON.stringify({ aic: "id-2", name: "Svc2", provider: { organization: "O" } }), "https://gw.example/acps-adp-v2/discover"],
  ];
  for (const [t, k, x, u] of samples) {
    is(
      JSON.stringify(lib.normalizeResources(t, k, x, u)),
      JSON.stringify(normalizeResources(t, k, x, u)),
      `library/worker normalization parity for ${t}`
    );
  }
  // The adapter table must match (same ids, channels, paths, order).
  is(JSON.stringify(lib.ADAPTERS), JSON.stringify(adapters()), "library adapter table matches worker");
  // The new-channel parsers must match too.
  is(JSON.stringify(lib.parseLinkRel('<link rel="ard" href="/c.json">', ["ard"])), JSON.stringify(parseLinkRel('<link rel="ard" href="/c.json">', ["ard"])), "parseLinkRel parity");
  is(JSON.stringify(lib.parseAgentmap("Agentmap: https://x/e.json", "agentmap")), JSON.stringify(parseAgentmap("Agentmap: https://x/e.json", "agentmap")), "parseAgentmap parity");
  is(JSON.stringify(lib.parseAidRecord("v=aid1;u=https://x/mcp;p=mcp")), JSON.stringify(parseAidRecord("v=aid1;u=https://x/mcp;p=mcp")), "parseAidRecord parity");
  // probeShapeOk must match the worker too (false-positive guard can't fork).
  const shapeSamples = [
    ["ard-catalog", "json", "{}"], ["ard-catalog", "json", '{"entries":[]}'],
    ["a2a-agent-card", "json", "{}"], ["a2a-agent-card", "json", '{"supportedInterfaces":[]}'],
    ["api-catalog", "json", "{}"], ["openapi", "json", "{}"], ["openapi", "json", '{"openapi":"3.0.0"}'],
    ["ai-info.json", "json", "{}"], ["llms.txt", "text", "# x"],
    ["anp", "json", "{}"], ["anp", "json", '{"items":[]}'], ["ucp", "json", "{}"], ["ucp", "json", '{"ucp_version":"2026-01"}'],
    ["gbz-185-4", "json", '{"aic":"","name":"S"}'], ["gbz-185-4", "json", "{}"], ["gbz-185-4", "json", '{"name":"plain a2a"}'],
  ];
  // isAcs parity (worker vs library)
  is(lib.isAcs({ aic: "", name: "X" }), isAcs({ aic: "", name: "X" }), "isAcs parity: ACS");
  is(lib.isAcs({ name: "plain a2a" }), isAcs({ name: "plain a2a" }), "isAcs parity: non-ACS");
  for (const [t, k, x] of shapeSamples) {
    is(lib.probeShapeOk(t, k, x), probeShapeOk(t, k, x), `library/worker probeShapeOk parity for ${t} ${k}`);
  }

  // GB/Z 185.5 optional discovery gateway — library only, OFF unless configured.
  const acsEntry = { aic: "id-9", name: "Gateway Agent", certificate: { requestedValidity: 365 }, capabilities: {} };
  const gwOut = lib.normalizeAcsGatewayResponse(JSON.stringify({ results: [acsEntry, { name: "not an acs" }] }), "https://gw/acps-adp-v2/discover");
  is(gwOut.length, 1, "gateway: only ACS entries extracted from the response");
  is(gwOut[0].source, "gbz-185-4", "gateway: ACS normalized with the shared 185.4 normalizer");
  is(gwOut[0].provenance, "gbz-185-5-gateway", "gateway: records tagged gbz-185-5-gateway provenance (not self-published)");
  is(lib.normalizeAcsGatewayResponse("not json", "https://gw/x").length, 0, "gateway: non-JSON → empty, never throws");
  const emptyFetch = async () => ({ ok: false, status: 404, text: async () => "" });
  const noGbz = await lib.resolve("example.com", { fetch: emptyFetch });
  is(noGbz.checked.includes("gbz-185-5"), false, "resolve() WITHOUT opts.gbz never queries a gateway");
  let calledUrl = null, calledMethod = null;
  const gwFetch = async (url, init) => { calledUrl = url; calledMethod = init && init.method; return { ok: true, status: 200, text: async () => JSON.stringify({ results: [acsEntry] }) }; };
  const withGbz = await lib.resolve("example.com", { fetch: emptyFetch, gbz: { gatewayUrl: "https://gw.example/", fetch: gwFetch, query: { description: "need x" } } });
  is(calledUrl, "https://gw.example/acps-adp-v2/discover", "gateway: POSTs the real /acps-adp-v2/discover endpoint (configured base URL, not guessed)");
  is(calledMethod, "POST", "gateway: uses POST");
  is(withGbz.checked.includes("gbz-185-5"), true, "resolve() WITH opts.gbz records gbz-185-5 in checked");
  is(withGbz.resources.some((r) => r.source === "gbz-185-4" && r.provenance === "gbz-185-5-gateway"), true, "gateway ACS records merged into resources with gateway provenance");
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
