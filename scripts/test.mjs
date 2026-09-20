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
  assertPublicDns,
  discoveryOutcome,
  hostAllowedForDomain,
  isForbiddenHost,
  apiCatalog,
  mcpTools,
  normalizeResources,
  classifyResource,
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
  selectOrgHosts,
  orgRecordsFromDoc,
  docRecords,
  isCrossRegistrable,
  sameRegCanonicalHost,
  probeShapeOkObj,
  parseRwsDeclaration,
  rwsReciprocal,
  parseAssetLinksWeb,
  nsContained,
  adapters,
  extractOpenApiCapabilities,
  parseMcpMessages,
  mcpToolCapabilities,
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
is(isPrivateIp("198.51.100.7"), true, "TEST-NET-2");
is(isPrivateIp("203.0.113.9"), true, "TEST-NET-3");
is(isPrivateIp("::1"), true, "v6 loopback");
is(isPrivateIp("fd12::1"), true, "v6 unique-local");
is(isPrivateIp("fe80::1"), true, "v6 link-local");
is(isPrivateIp("ff02::1"), true, "v6 multicast");
is(isPrivateIp("100::1"), true, "v6 discard prefix");
is(isPrivateIp("64:ff9b::a00:1"), true, "NAT64 (embeds IPv4, possibly private)");
is(isPrivateIp("2002:7f00::1"), true, "6to4 (embeds IPv4, possibly private)");
is(isPrivateIp("2606:4700::1111"), false, "public v6 ok");
// Alternative IP spellings must never pass domain validation (SSRF encodings).
is(normalizeDomain("127.1"), null, "rejects short-form IP");
is(normalizeDomain("2130706433"), null, "rejects decimal IP");
is(normalizeDomain("0x7f000001"), null, "rejects hex IP");
is(normalizeDomain("017700000001"), null, "rejects octal IP");

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
is(validateProbeContent("text", "  <!-- Copyright Microsoft --> <!DOCTYPE html><html>"), false, "HTML behind a leading comment rejected (login-shell false-positive guard)");
is(validateProbeContent("text", "<!-- File: llms.txt Domain: x -->\n# Real llms\n- [a](https://x/a)"), true, "genuine text with a comment header still accepted");
is(validateProbeContent("text", "<!-- unterminated"), false, "unterminated comment rejected");
is(validateProbeContent("text", "<HTML><body>"), false, "bare <tag> head rejected");

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
  // selectOrgHosts: the bounded probe slots must go to plausible PUBLISHING
  // hosts, not whatever same-domain URL happens to appear first in the HTML.
  // Real-world failure this guards: microsoft.com's homepage yields
  // cdn-dynmedia-1./web.vortex.data./wcpstatic./fpt. first, which consumed all
  // 4 slots and starved docs./developers./the conventional shortlist.
  const junkFirst = ["cdn-dynmedia-1.big.com", "web.vortex.data.big.com", "wcpstatic.big.com", "fpt.big.com", "docs.big.com"];
  const selJunk = selectOrgHosts(junkFirst, "big.com");
  is(selJunk.length, 4, "selectOrgHosts: capped at ORG_MAX_HOSTS");
  is(selJunk[0].h, "docs.big.com", "selectOrgHosts: dev-facing homepage host outranks CDN junk");
  is(selJunk[0].via, "homepage-link", "selectOrgHosts: homepage evidence label kept");
  is(selJunk[1].h, "developers.big.com", "selectOrgHosts: conventional shortlist fills before junk");
  is(selJunk.some((x) => x.h === "cdn-dynmedia-1.big.com"), false, "selectOrgHosts: CDN junk never wins a slot while better candidates exist");
  // openai-shaped case: community.* (Discourse serves llms.txt) must stay eligible.
  const oai = selectOrgHosts(["deploymentsafety.openai.com", "platform.openai.com", "developers.openai.com", "community.openai.com"], "openai.com");
  is(oai.map((x) => x.h).includes("community.openai.com"), true, "selectOrgHosts: community.* homepage link keeps its slot (real llms publisher pattern)");
  is(oai.map((x) => x.h).includes("deploymentsafety.openai.com"), false, "selectOrgHosts: non-dev-facing homepage host yields to conventional candidates");
  // No homepage hosts → pure conventional shortlist, docs first.
  const conv = selectOrgHosts([], "plain.com");
  is(conv[0].h, "docs.plain.com", "selectOrgHosts: conventional fallback starts at docs.");
  is(conv.every((x) => x.via === "conventional"), true, "selectOrgHosts: conventional entries labeled");
  // Dedupe: homepage-linked docs. must not appear twice via the shortlist.
  const dd = selectOrgHosts(["docs.dup.com"], "dup.com");
  is(dd.filter((x) => x.h === "docs.dup.com").length, 1, "selectOrgHosts: homepage + conventional dedupe");
  const orgArd = orgRecordsFromDoc("https://developers.example.com/.well-known/ard.json", JSON.stringify({ entries: [{ type: "application/json", url: "https://developers.example.com/a.json" }] }), "homepage-link");
  is(orgArd.length, 1, "org: an ARD catalog on a related host is normalized");
  is(orgArd[0].evidence, "same-domain-host", "org: ARD entries labelled same-domain-host");
  is(orgRecordsFromDoc("https://api.example.com/page.json", '{"random":true}', "conventional").length, 0, "org: unrecognized JSON is not reported");
}

console.log("--- canonical-host fallback + single-parse shape checks (benchmark rules)");
is(sameRegCanonicalHost("https://www.capgemini.com/", "capgemini.com"), "www.capgemini.com", "canonical: apex→www accepted");
is(sameRegCanonicalHost("https://m365.cloud.microsoft/x", "cloud.microsoft"), "m365.cloud.microsoft", "canonical: apex→subdomain accepted");
is(sameRegCanonicalHost("https://azure.microsoft.com/", "azure.com"), null, "canonical: cross-registrable-domain redirect → null (never authoritative)");
is(sameRegCanonicalHost("https://capgemini.com/", "capgemini.com"), null, "canonical: no redirect → null");
is(sameRegCanonicalHost("not a url", "x.com"), null, "canonical: garbage → null");
is(probeShapeOkObj("ard-catalog", { entries: [] }), true, "probeShapeOkObj: same semantics as text variant (ARD)");
is(probeShapeOkObj("openapi", {}), false, "probeShapeOkObj: rejects like text variant");
{
  // The object and text variants must agree (single-parse optimization safety).
  const cases = [["ard-catalog", '{"entries":[]}'], ["ucp", '{"capabilities":[]}'], ["anp", "{}"], ["openapi", '{"swagger":"2.0"}'], ["gbz-185-4", '{"aic":"","name":"S"}']];
  for (const [t, x] of cases) is(probeShapeOkObj(t, JSON.parse(x)), probeShapeOk(t, "json", x), `obj/text shape agreement: ${t}`);
}

console.log("--- canonical fallback engine path (library resolve() with mocked fetch)");
{
  const lib = await import("../public/resolver.mjs");
  const mock = async (url) => {
    const u = String(url);
    if (u === "https://flipcase.com/") return { ok: true, status: 200, url: "https://www.flipcase.com/", text: async () => "<html>home</html>" };
    if (u === "https://www.flipcase.com/llms.txt") return { ok: true, status: 200, url: u, text: async () => "# Flipcase\n- [docs](https://www.flipcase.com/docs)" };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  const r = await lib.resolve("flipcase.com", { fetch: mock });
  is(r.discovered.length, 1, "fallback: canonical www llms.txt discovered when apex is empty");
  is(r.discovered[0].url, "https://www.flipcase.com/llms.txt", "fallback: discovered url is on the canonical host");
  const crossMock = async (url) => {
    const u = String(url);
    if (u === "https://flipcase.com/") return { ok: true, status: 200, url: "https://other-domain.com/", text: async () => "<html>x</html>" };
    if (u === "https://other-domain.com/llms.txt") return { ok: true, status: 200, url: u, text: async () => "# Other" };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  const r2 = await lib.resolve("flipcase.com", { fetch: crossMock });
  is(r2.discovered.length, 0, "fallback: cross-registrable-domain redirect is NEVER followed");
}

console.log("--- library records the FINAL (post-redirect) URL and labels rebrands honestly");
{
  const lib = await import("../public/resolver.mjs");
  // Wholesale rebrand: oldbrand.com/llms.txt redirects to newbrand.com/llms.txt.
  // fetch (redirect:"follow") lands there; res.url carries the final URL. The
  // record must attribute the bytes to their real origin and drop the
  // "publisher" label — the hosted-vs-library divergence the real-world
  // benchmark audit flagged (neon.tech→neon.com).
  const rebrand = async (url) => {
    const u = String(url);
    if (u === "https://oldbrand.com/llms.txt") return { ok: true, status: 200, url: "https://newbrand.com/llms.txt", text: async () => "# NewBrand\n- [docs](https://newbrand.com/docs)" };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  const r = await lib.resolve("oldbrand.com", { fetch: rebrand });
  is(r.resources.length >= 1, true, "rebrand: resource still found (the library follows the hop)");
  is(r.resources[0].sourceUrl, "https://newbrand.com/llms.txt", "rebrand: sourceUrl is the FINAL post-redirect URL, not the requested one");
  is(r.resources[0].class, "verified-external-location", "rebrand: labeled verified-external-location, NOT verified-publisher-location");
  is(r.discovered[0].url, "https://newbrand.com/llms.txt", "rebrand: discovered map records the final URL");
  // Same-registrable redirect (apex → www) records the final URL but keeps the
  // publisher label — the content never left the domain's own registrable domain.
  const www = async (url) => {
    const u = String(url);
    if (u === "https://samebrand.com/llms.txt") return { ok: true, status: 200, url: "https://www.samebrand.com/llms.txt", text: async () => "# SameBrand" };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  const r2 = await lib.resolve("samebrand.com", { fetch: www });
  is(r2.resources[0].sourceUrl, "https://www.samebrand.com/llms.txt", "www redirect: final URL recorded");
  is(r2.resources[0].class, "verified-publisher-location", "www redirect: same registrable domain stays verified-publisher-location");
  // A fetch implementation that does not expose res.url falls back to the
  // requested URL (bring-your-own-fetch stays supported).
  const noUrl = async (url) => {
    const u = String(url);
    if (u === "https://plain.com/llms.txt") return { ok: true, status: 200, text: async () => "# Plain" };
    return { ok: false, status: 404, text: async () => "" };
  };
  const r3 = await lib.resolve("plain.com", { fetch: noUrl });
  is(r3.resources[0].sourceUrl, "https://plain.com/llms.txt", "no res.url: falls back to the requested URL");
  is(r3.resources[0].class, "verified-publisher-location", "no res.url: classification unchanged");
}

console.log("--- declared capabilities: verbatim publisher data only, never inferred");
{
  const lib = await import("../public/resolver.mjs");
  // OpenAPI: operations + security schemes 1:1 from the document.
  const spec = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "Pet API" },
    paths: {
      "/pets": { get: { operationId: "listPets", summary: "List all pets" }, post: { operationId: "createPet" } },
      "/pets/{id}": { get: { summary: "Get one pet" }, "x-vendor": { ignored: true } },
    },
    components: { securitySchemes: { bearer: { type: "http", scheme: "bearer" }, key: { type: "apiKey", in: "header" } } },
  });
  const decl = extractOpenApiCapabilities(spec);
  is(decl.capabilities.length, 3, "openapi: one capability per declared operation (vendor extensions ignored)");
  is(decl.capabilities[0].method, "GET", "openapi: method verbatim");
  is(decl.capabilities[0].path, "/pets", "openapi: path verbatim");
  is(decl.capabilities[0].operationId, "listPets", "openapi: operationId verbatim");
  is(decl.capabilities[0].summary, "List all pets", "openapi: summary verbatim");
  is(decl.security.length, 2, "openapi: declared security schemes surfaced");
  is(decl.security[0].name, "bearer", "openapi: scheme name is the publisher's own key");
  is(decl.security[0].type, "http", "openapi: scheme type verbatim");
  is(extractOpenApiCapabilities("{not json"), null, "openapi: malformed → null (never guessed)");
  is(extractOpenApiCapabilities('{"openapi":"3.0.0"}'), null, "openapi: no declarations → null (absence, not invention)");
  // Swagger 2 securityDefinitions are the same publisher declaration.
  is(extractOpenApiCapabilities(JSON.stringify({ swagger: "2.0", securityDefinitions: { basic: { type: "basic" } } })).security[0].name, "basic", "openapi: swagger-2 securityDefinitions surfaced");
  // Cap: more declared operations than the limit → labeled truncation, never silent.
  const big = { openapi: "3.0.0", paths: {} };
  for (let i = 0; i < 45; i++) big.paths["/p" + i] = { get: { operationId: "op" + i } };
  const bigDecl = extractOpenApiCapabilities(JSON.stringify(big));
  is(bigDecl.capabilities.length, 40, "openapi: capability list capped");
  is(bigDecl.capabilitiesTruncated, true, "openapi: cap is labeled, never silent");
  // Security schemes obey the same no-silent-caps rule.
  const manySchemes = {};
  for (let i = 0; i < 45; i++) manySchemes["s" + i] = { type: "apiKey" };
  const secDecl = extractOpenApiCapabilities(JSON.stringify({ openapi: "3.0.0", components: { securitySchemes: manySchemes } }));
  is(secDecl.security.length, 40, "openapi: security list capped");
  is(secDecl.securityTruncated, true, "openapi: security cap is labeled, never silent");
  is(JSON.stringify(lib.extractOpenApiCapabilities(spec)), JSON.stringify(extractOpenApiCapabilities(spec)), "extractOpenApiCapabilities worker/library parity");
  // A2A: declared skills verbatim on the normalized record.
  const card = JSON.stringify({ name: "Support Agent", url: "https://acme.com/a2a", capabilities: { streaming: true }, skills: [{ id: "faq", name: "Answer FAQs", description: "Answers product questions", tags: ["support"] }, "junk", { name: "Book demo" }] });
  const a2a = normalizeResources("a2a-agent-card", "json", card, "https://acme.com/.well-known/agent-card.json");
  is(a2a[0].capabilities.length, 2, "a2a: declared skills → capabilities (non-object entries dropped)");
  is(a2a[0].capabilities[0].name, "Answer FAQs", "a2a: skill name verbatim");
  is(a2a[0].capabilities[0].description, "Answers product questions", "a2a: skill description verbatim");
  is(a2a[0].capabilities[0].tags[0], "support", "a2a: tags verbatim");
  is(a2a[0].raw.capabilities.streaming, true, "a2a: card-level capabilities object preserved in raw");
  const plainCard = normalizeResources("a2a-agent-card", "json", JSON.stringify({ name: "NoSkills", url: "https://acme.com/a2a" }), "https://acme.com/.well-known/agent-card.json");
  is(plainCard[0].capabilities, undefined, "a2a: no declared skills → NO capabilities field (absence, not invention)");
  // Skills that declare none of id/name/description surface nothing — no {} noise.
  const emptySkills = normalizeResources("a2a-agent-card", "json", JSON.stringify({ name: "E", url: "https://acme.com/a2a", skills: [{}, { foo: 1 }] }), "https://acme.com/.well-known/agent-card.json");
  is(emptySkills[0].capabilities, undefined, "a2a: skills declaring nothing usable → no capabilities field");
  is(JSON.stringify(lib.normalizeResources("a2a-agent-card", "json", card, "https://acme.com/.well-known/agent-card.json")), JSON.stringify(a2a), "a2a skills normalization worker/library parity");
  // End-to-end through the library adapter: a spec that fits the prefix carries
  // its declared operations on the discovered resource.
  const mockFetch = async (url) => {
    const u = String(url);
    if (u === "https://capdemo.com/openapi.json") return { ok: true, status: 200, url: u, text: async () => spec };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  const r = await lib.resolve("capdemo.com", { fetch: mockFetch });
  const oa = r.resources.find((x) => x.source === "openapi");
  is(oa.capabilities.length, 3, "resolve(): openapi resource carries declared operations");
  is(oa.security.length, 2, "resolve(): openapi resource carries declared security schemes");
  is(oa.class, "verified-publisher-location", "resolve(): capability-bearing resource keeps its class");
  // A spec larger than the 64 KB prefix triggers ONE bounded full read; if that
  // read ALSO truncates (doc bigger than the byte cap), the spec stays
  // detected-but-not-enumerated — never a partial extraction. The head marker
  // sits inside the prefix, so detection holds either way.
  const bigSpec = '{"openapi":"3.0.0","info":{"title":"Big"},"pad":"' + "x".repeat(70000) + '","paths":{"/a":{"get":{"operationId":"a"}}}}';
  const bigMock = async (url) => {
    const u = String(url);
    if (u === "https://bigcap.com/openapi.json") return { ok: true, status: 200, url: u, text: async () => bigSpec };
    return { ok: false, status: 404, url: u, text: async () => "" };
  };
  // Cap below the doc size → full read truncates → detected, no capabilities.
  const rBig = await lib.resolve("bigcap.com", { fetch: bigMock, maxBytes: 66000 });
  const oaBig = rBig.resources.find((x) => x.source === "openapi");
  is(!!oaBig, true, "oversized spec: still detected from the bounded prefix");
  is(oaBig.capabilities, undefined, "oversized spec: NO capabilities from a truncated document (partial extraction forbidden)");
  // Default cap (1 MB) fits the whole doc → the second bounded read enumerates it.
  const rBig2 = await lib.resolve("bigcap.com", { fetch: bigMock });
  const oaBig2 = rBig2.resources.find((x) => x.source === "openapi");
  is(oaBig2.capabilities.length, 1, "large-but-under-cap spec: second bounded read enumerates declared operations");
  is(oaBig2.capabilities[0].operationId, "a", "large spec: operationId verbatim");
}

console.log("--- MCP introspection: read-only, opt-in, verbatim server declarations");
{
  const lib = await import("../public/resolver.mjs");
  // Pure parsers: plain JSON and SSE framing, worker/library parity.
  const sse = 'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":2,"result":{"tools":[]}}\n\n';
  is(JSON.stringify(parseMcpMessages(sse, "text/event-stream; charset=utf-8")), JSON.stringify([{ jsonrpc: "2.0", id: 2, result: { tools: [] } }]), "SSE framing parsed (multi-line data accumulated per event)");
  is(parseMcpMessages("{not json", "application/json").length, 0, "malformed body → no messages, never guessed");
  is(JSON.stringify(lib.parseMcpMessages(sse, "text/event-stream")), JSON.stringify(parseMcpMessages(sse, "text/event-stream")), "parseMcpMessages worker/library parity");
  const toolsResult = { tools: [{ name: "search", description: "Search things", inputSchema: { type: "object" } }, { name: "bare" }, { description: "no name — unusable" }, "junk"] };
  const caps = mcpToolCapabilities(toolsResult);
  is(caps.capabilities.length, 2, "tools without a name (spec-required) are skipped; junk dropped");
  is(caps.capabilities[0].name, "search", "tool name verbatim");
  is(caps.capabilities[0].description, "Search things", "tool description verbatim");
  is(caps.capabilities[0].inputSchema.type, "object", "inputSchema verbatim");
  is(JSON.stringify(lib.mcpToolCapabilities(toolsResult)), JSON.stringify(mcpToolCapabilities(toolsResult)), "mcpToolCapabilities worker/library parity");

  // Behavioral: full library flow against a mock MCP server. Records EVERY
  // JSON-RPC method sent — the read-only allowlist is proven, not assumed.
  const sent = [];
  const postsTo = [];
  const mkMcpFetch = (mcpUrl, awpHost) => async (url, opts) => {
    const u = String(url);
    if (opts && opts.method === "POST") {
      postsTo.push(u);
      const frame = JSON.parse(opts.body);
      sent.push(frame.method);
      const H = (extra) => ({ get: (h) => { const k = h.toLowerCase(); if (k === "content-type") return extra.ct; if (k === "mcp-session-id") return extra.sess || null; return null; } });
      if (frame.method === "initialize") return { ok: true, status: 200, url: u, headers: H({ ct: "application/json", sess: "sess-1" }), text: async () => JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18", serverInfo: { name: "CapMCP", version: "2.0" }, capabilities: {} } }) };
      if (frame.method === "notifications/initialized") return { ok: true, status: 202, url: u, headers: H({ ct: "" }), text: async () => "" };
      if (frame.method === "tools/list") {
        // Session must be echoed (spec) — refuse otherwise so the test catches it.
        if (!opts.headers || opts.headers["Mcp-Session-Id"] !== "sess-1") return { ok: false, status: 400, url: u, headers: H({ ct: "application/json" }), text: async () => JSON.stringify({ error: "missing session" }) };
        return { ok: true, status: 200, url: u, headers: H({ ct: "text/event-stream" }), text: async () => 'data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"Search things","inputSchema":{"type":"object"}},{"name":"bare"}]}}\n\n' };
      }
      return { ok: false, status: 400, url: u, headers: H({ ct: "" }), text: async () => "" };
    }
    if (u === "https://" + awpHost + "/.well-known/awp.json") return { ok: true, status: 200, url: u, headers: { get: () => "application/json" }, text: async () => JSON.stringify({ protocols: { mcp: mcpUrl } }) };
    return { ok: false, status: 404, url: u, headers: { get: () => "" }, text: async () => "" };
  };

  const r = await lib.resolve("capmcp.com", { fetch: mkMcpFetch("https://capmcp.com/mcp", "capmcp.com"), mcp: true });
  is(JSON.stringify(r.introspected), JSON.stringify(["mcp"]), "introspection is labeled top-level");
  const mcpRes = r.resources.find((x) => String(x.type).toLowerCase() === "mcp");
  is(mcpRes.introspection.ok, true, "introspection succeeded");
  is(mcpRes.introspection.serverInfo.name, "CapMCP", "serverInfo verbatim");
  is(mcpRes.introspection.protocolVersion, "2025-06-18", "negotiated protocol version recorded");
  is(mcpRes.capabilities.length, 2, "declared tools land in the capabilities envelope");
  is(mcpRes.capabilities[0].name, "search", "tool surfaced verbatim via SSE response");
  is(JSON.stringify(sent), JSON.stringify(["initialize", "notifications/initialized", "tools/list"]), "EXACTLY the read-only method set was sent — nothing else, ever");
  is(sent.includes("tools/call"), false, "tools/call is never sent (structural allowlist, behaviorally proven)");

  // OFF by default: no POST leaves the resolver without opts.mcp.
  sent.length = 0; postsTo.length = 0;
  const rOff = await lib.resolve("capmcp.com", { fetch: mkMcpFetch("https://capmcp.com/mcp", "capmcp.com") });
  is(sent.length, 0, "opt-in: no introspection POSTs without opts.mcp");
  is(rOff.introspected, undefined, "opt-in: no introspected label by default");
  is(rOff.resources.find((x) => String(x.type).toLowerCase() === "mcp").introspection, undefined, "opt-in: no introspection field by default");

  // Declared EXTERNAL endpoints are never introspected.
  sent.length = 0; postsTo.length = 0;
  const rExt = await lib.resolve("capmcp.com", { fetch: mkMcpFetch("https://other-registrable.com/mcp", "capmcp.com"), mcp: true });
  is(sent.length, 0, "cross-registrable declared MCP endpoint: not introspected");
  is(rExt.resources.find((x) => String(x.type).toLowerCase() === "mcp").introspection, undefined, "external endpoint carries no introspection result");

  // Auth wall = honest observation, not an error and never retried.
  const authFetch = async (url, opts) => {
    const u = String(url);
    if (opts && opts.method === "POST") return { ok: false, status: 401, url: u, headers: { get: () => "" }, text: async () => "" };
    if (u === "https://authmcp.com/.well-known/awp.json") return { ok: true, status: 200, url: u, headers: { get: () => "application/json" }, text: async () => JSON.stringify({ protocols: { mcp: "https://authmcp.com/mcp" } }) };
    return { ok: false, status: 404, url: u, headers: { get: () => "" }, text: async () => "" };
  };
  const rAuth = await lib.resolve("authmcp.com", { fetch: authFetch, mcp: true });
  const authRes = rAuth.resources.find((x) => String(x.type).toLowerCase() === "mcp");
  is(authRes.introspection.ok, false, "auth-walled endpoint: introspection not ok");
  is(authRes.introspection.status, "auth-required", "auth wall labeled auth-required (no credentials, no retry)");
  is(authRes.capabilities, undefined, "auth-walled endpoint: no capabilities invented");
}

console.log("--- Related Discovery (cross-domain; strict evidence model)");
{
  is(isCrossRegistrable("googleapis.com", "google.com"), true, "cross: different registrable domain");
  is(isCrossRegistrable("developers.google.com", "google.com"), false, "cross: subdomain is NOT cross-domain");
  is(isCrossRegistrable("google.com", "google.com"), false, "cross: apex is not cross-domain");
  // RWS primary file (queried domain declares its set)
  const rws = parseRwsDeclaration(
    JSON.stringify({ primary: "https://google.com", associatedSites: ["https://youtube.com", "https://android.com"], serviceSites: ["https://googleusercontent.com"] }),
    "google.com"
  );
  is(rws.primary, "google.com", "RWS: primary parsed");
  is(rws.sites.length, 3, "RWS: associated + service sites extracted");
  is(rws.sites.find((s) => s.host === "youtube.com").role, "associated", "RWS: role preserved");
  is(rws.sites.find((s) => s.host === "googleusercontent.com").role, "service", "RWS: service role preserved");
  // Member file (reciprocity)
  const member = parseRwsDeclaration(JSON.stringify({ primary: "https://google.com" }), "youtube.com");
  is(member.memberOf, "google.com", "RWS: member file exposes its primary");
  is(rwsReciprocal(JSON.stringify({ primary: "https://google.com" }), "google.com"), true, "RWS: reciprocity check passes");
  is(rwsReciprocal(JSON.stringify({ primary: "https://evil.com" }), "google.com"), false, "RWS: non-matching primary is not reciprocal");
  is(parseRwsDeclaration("not json", "google.com"), null, "RWS: garbage → null");
  // Digital Asset Links: web statements only
  const al = parseAssetLinksWeb(JSON.stringify([
    { relation: ["delegate_permission/common.handle_all_urls"], target: { namespace: "android_app", package_name: "x" } },
    { relation: ["delegate_permission/common.query_webapk"], target: { namespace: "web", site: "https://related.example" } },
  ]));
  is(al, ["related.example"], "assetlinks: web statements extracted, app statements ignored");
  is(parseAssetLinksWeb("{}").length, 0, "assetlinks: non-array → empty");
  // NS containment (corroborating only)
  is(nsContained(["ns1.google.com.", "ns2.google.com."], "google.com"), ["ns1.google.com", "ns2.google.com"], "ns: containment detected (trailing dots normalized)");
  is(nsContained(["dns1.p08.nsone.net."], "microsoft.com").length, 0, "ns: third-party NS → no containment");
  // docRecords: evidence class passthrough (used by the related layer)
  const dr = docRecords("https://youtube.com/llms.txt", "# yt", "publisher-declared-related", ["https://google.com/.well-known/related-website-set.json", "youtube.com"]);
  is(dr[0].evidence, "publisher-declared-related", "docRecords: related evidence class applied");
  is(dr[0].provenance[0], "https://google.com/.well-known/related-website-set.json", "docRecords: declaration cited in provenance");
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

console.log("--- resource result taxonomy (class field) — DX self-explaining results");
{
  const D = "acme.com";
  // The surface NessGate fetched + validated (resource IS the document).
  is(classifyResource({ url: "https://acme.com/llms.txt", sourceUrl: "https://acme.com/llms.txt" }, D), "verified-publisher-location", "class: fetched surface → verified-publisher-location");
  // Declared inside a catalog, target on the apex (not itself fetched).
  is(classifyResource({ url: "https://acme.com/mcp", sourceUrl: "https://acme.com/.well-known/ard.json" }, D), "publisher-declared", "class: on-domain declared pointer → publisher-declared");
  // Declared, target on the publisher's own SUBDOMAIN (still same registrable domain).
  is(classifyResource({ url: "https://mcp.acme.com/mcp", sourceUrl: "https://acme.com/.well-known/ard.json" }, D), "publisher-declared", "class: subdomain declared pointer → publisher-declared");
  // Declared, target on a DIFFERENT registrable domain → unverified external.
  is(classifyResource({ url: "https://github.com/acme/x", sourceUrl: "https://acme.com/.well-known/ard.json" }, D), "declared-external-pointer", "class: cross-registrable pointer → declared-external-pointer");
  // A look-alike suffix domain must NOT count as same-registrable.
  is(classifyResource({ url: "https://notacme.com/x", sourceUrl: "https://acme.com/.well-known/ard.json" }, D), "declared-external-pointer", "class: suffix look-alike → declared-external-pointer (not same registrable)");
  // No usable URL.
  is(classifyResource({ url: "::::", sourceUrl: "https://acme.com/.well-known/ard.json" }, D), "unsupported", "class: unparseable url → unsupported");
  // The fetched document itself, but its FINAL URL crossed the registrable-domain
  // boundary (the library followed a rebrand redirect and recorded where the
  // bytes actually came from) → honest external label, never "publisher".
  is(classifyResource({ url: "https://newbrand.com/llms.txt", sourceUrl: "https://newbrand.com/llms.txt" }, D), "verified-external-location", "class: fetched cross-registrable final URL → verified-external-location");
  // Parity: worker and library classify identically.
  const lib = await import("../public/resolver.mjs");
  for (const c of [
    { url: "https://acme.com/llms.txt", sourceUrl: "https://acme.com/llms.txt" },
    { url: "https://mcp.acme.com/mcp", sourceUrl: "https://acme.com/.well-known/ard.json" },
    { url: "https://other.org/x", sourceUrl: "https://acme.com/.well-known/ard.json" },
    { url: "https://newbrand.com/llms.txt", sourceUrl: "https://newbrand.com/llms.txt" },
    { url: "bad", sourceUrl: "https://acme.com/x" },
  ]) is(lib.classifyResource(c, D), classifyResource(c, D), `classifyResource library/worker parity for ${c.url}`);
}

console.log("--- self ARD catalog is served at BOTH canonical names");
{
  // ARD readers in the wild probe /.well-known/ai-catalog.json (the ARD-canonical
  // name); ard.json is the alias. nessgate.com must serve BOTH or it is invisible
  // to standard ARD tooling (DNS-AID et al.). Byte-identical to avoid drift.
  const { readFileSync } = await import("node:fs");
  const ard = readFileSync(new URL("../public/.well-known/ard.json", import.meta.url), "utf8");
  const aic = readFileSync(new URL("../public/.well-known/ai-catalog.json", import.meta.url), "utf8");
  is(aic === ard, true, "public/.well-known/ai-catalog.json is byte-identical to ard.json (ARD-canonical alias)");
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

console.log("--- DoH hardening (a stalled resolver must never hang an invocation)");
{
  const realFetch = globalThis.fetch;
  // A DoH endpoint that never responds on its own — it settles ONLY if the
  // caller aborts. The check must FAIL within its own timeout budget, not hang
  // (untimed DoH awaits were the root cause of production 504s). The watchdog
  // race makes a reintroduced hang a loud test failure instead of a silent
  // unsettled await. Worst case is one timer per record type (A + AAAA).
  globalThis.fetch = (url, opts) =>
    new Promise((_, reject) => {
      if (opts && opts.signal) {
        opts.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }
    });
  const t0 = Date.now();
  let watchdog;
  const outcome = await Promise.race([
    assertPublicDns("stalled-doh.test.example").then(() => "resolved", () => "rejected"),
    new Promise((r) => { watchdog = setTimeout(r, 15_000, "hung"); }),
  ]);
  clearTimeout(watchdog);
  const ms = Date.now() - t0;
  globalThis.fetch = realFetch;
  is(outcome, "rejected", "assertPublicDns fails (not hangs) when DoH stalls");
  is(ms < 12_000, true, `assertPublicDns bounded by its DoH timers (took ${ms}ms)`);

  // Parallel adapters check the same host at once: they must share ONE
  // in-flight lookup (A + AAAA), not stampede a duplicate DoH pair each.
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    return new Response(JSON.stringify({ Answer: [{ type: 1, data: "93.184.216.34" }] }));
  };
  await Promise.all(Array.from({ length: 8 }, () => assertPublicDns("stampede.test.example")));
  globalThis.fetch = realFetch;
  is(calls <= 2, true, `8 concurrent checks share one in-flight DoH pair (${calls} lookups)`);
}

console.log("--- discovery-outcome classification (anonymous metric)");
is(discoveryOutcome(200, { resources: [{ x: 1 }, { y: 2 }] }), "resources", "resources returned");
is(discoveryOutcome(200, { resources: [] }), "empty", "valid but zero resources");
is(discoveryOutcome(200, {}), "empty", "no resources field → empty");
is(discoveryOutcome(500, { resources: [{ x: 1 }] }), "error", "5xx is an error regardless of body");
is(discoveryOutcome(429, {}), "error", "rate-limited is an error");
// The metric never encodes the domain, body, or count — only these four labels
// (plus "invalid" for bad input, set on the pre-resolve path).
is(["resources", "empty", "error"].includes(discoveryOutcome(200, { resources: [1] })), true, "outcome is always one bounded label");

console.log(failed ? `\n${failed} FAILURES` : "\nAll regression tests passed.");
process.exit(failed ? 1 : 0);
