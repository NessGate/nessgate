// Stage 1 v2-alpha conformance + regression tests. No network (mocked fetch).
// Run with `npm run test:v2`. Proves: two-axis classification; verification
// alone never promotes Level 2 → Level 1; provenance on every result;
// determinism / store-independence; and that v1 `resolve()` is unchanged when
// the new options are not used.
import { resolve as resolveV1 } from "../packages/resolver/index.mjs";
import {
  resolveV2, classify, levelFor, LEVEL, V2_ADAPTERS, adapterInfo,
  isSafeHttpsHost, parseCtNames, parseSitemapLocs, parseRobotsSitemaps, hostsFromLocs,
  EXPERIMENTAL,
} from "../packages/resolver/v2.mjs";

let failed = 0;
function is(actual, expected, name) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) console.log(`  ok  ${name}`);
  else { failed++; console.error(`FAIL  ${name}: got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}`); }
}
const throws = (fn, name) => Promise.resolve().then(fn).then(
  () => { failed++; console.error(`FAIL  ${name}: did not throw`); },
  () => console.log(`  ok  ${name}`));

/* ------------------------------- mock fetch ------------------------------- */
function resp(status, body, contentType, url) {
  return {
    ok: status >= 200 && status < 300, status, url: url,
    headers: { get: (h) => (String(h).toLowerCase() === "content-type" ? contentType : null) },
    text: async () => body, json: async () => JSON.parse(body),
  };
}
function makeFetch(routes) {
  return async (url) => {
    const u = String(url);
    if (u.startsWith("https://cloudflare-dns.com/")) return resp(200, JSON.stringify({ Answer: [] }), "application/dns-json", u);
    const r = routes[u];
    if (r) return resp(r.status ?? 200, r.body ?? "", r.contentType ?? "application/json", r.finalUrl ?? u);
    return resp(404, "", "text/plain", u);
  };
}

// Scenario: acme.test publishes llms.txt (L1). CT lists api/docs/dead.acme.test.
// api serves llms.txt (L2 same-registrable). docs is reachable-but-empty (none).
// dead 500s (unreachable). robots→sitemap lists a cross-host partner-cdn.test
// (serves llms.txt → L2 publisher-linked) and api.acme.test (already seen).
const SEED = "acme.test";
const routes = {
  "https://acme.test/llms.txt": { status: 200, contentType: "text/plain", body: "# ACME\nRoot resources." },
  "https://acme.test/robots.txt": { status: 200, contentType: "text/plain", body: "User-agent: *\nSitemap: https://acme.test/sitemap.xml" },
  "https://acme.test/sitemap.xml": { status: 200, contentType: "application/xml",
    body: "<urlset><url><loc>https://partner-cdn.test/a</loc></url><url><loc>https://api.acme.test/b</loc></url></urlset>" },
  "https://crt.sh/?q=%25.acme.test&output=json": { status: 200, contentType: "application/json",
    body: JSON.stringify([
      { name_value: "api.acme.test\n*.acme.test" },
      { name_value: "docs.acme.test" },
      { name_value: "dead.acme.test" },
      { name_value: "www.acme.test" },       // filtered
      { name_value: "evil.other.test" },     // cross-domain, filtered
    ]) },
  "https://api.acme.test/llms.txt": { status: 200, contentType: "text/plain", body: "# ACME API" },
  "https://docs.acme.test/": { status: 200, contentType: "text/html", body: "<html></html>" },   // reachable, empty → none
  "https://dead.acme.test/": { status: 500, contentType: "text/plain", body: "" },               // → unreachable
  "https://partner-cdn.test/llms.txt": { status: 200, contentType: "text/plain", body: "# Partner CDN for ACME" },
};
const fetch = makeFetch(routes);
const opts = { fetch, timeoutMs: 2000, maxBytes: 1_000_000 };

/* ------------------------- two-axis classification ------------------------ */
console.log("--- two-axis classification (level derives ONLY from relationship)");
is(levelFor("publisher-hosted"), 1, "publisher-hosted → Level 1");
is(levelFor("same-registrable-domain"), 2, "same-registrable-domain → Level 2");
is(levelFor("publisher-linked"), 2, "publisher-linked → Level 2");
await throws(() => levelFor("made-up-class"), "unknown evidence class throws");
{
  const it = classify({ url: "https://x.test/llms.txt", source: "llms.txt" }, "same-registrable-domain",
    [{ adapter: "ct-subdomains", host: "x.test" }], "verified");
  is(it.level, 2, "classified item carries level from its class");
  is(it.verification, "verified", "verification recorded on axis 1");
  is(it.relationship, "same-registrable-domain", "relationship recorded on axis 2");
}

console.log("--- INVARIANT: verification alone never promotes Level 2 → Level 1");
for (const v of ["verified", "unreachable", "none"]) {
  const it = classify({ url: "https://api.x.test/llms.txt", source: "llms.txt" }, "same-registrable-domain",
    [{ adapter: "ct-subdomains", host: "api.x.test" }], v);
  is(it.level, 2, `verification="${v}" leaves same-registrable-domain at Level 2`);
}
// Structural proof: no non-authority adapter can even name a Level 1 class.
for (const a of V2_ADAPTERS) {
  if (!a.canEstablishAuthority) is(levelFor(a.evidenceClass), 2, `adapter ${a.id} (canEstablishAuthority=false) emits a Level 2 class`);
}

/* ------------------------------- provenance ------------------------------- */
console.log("--- provenance is required on every result");
await throws(() => classify({ url: "u", source: "s" }, "publisher-hosted", []), "empty provenance throws");
await throws(() => classify({ url: "u", source: "s" }, "publisher-hosted", undefined), "missing provenance throws");

/* --------------------------- adapter architecture ------------------------- */
console.log("--- adapter architecture is self-describing");
for (const a of V2_ADAPTERS) {
  const okShape = typeof a.id === "string" && typeof a.standard === "string" &&
    ["resources", "hosts", "relationships"].includes(a.discovers) &&
    typeof a.evidenceClass === "string" && typeof a.canEstablishAuthority === "boolean" &&
    ["fast", "balanced", "deep"].includes(a.tier) &&
    (a.external === null || typeof a.external === "string") && typeof a.run === "function";
  is(okShape, true, `adapter ${a.id} declares a complete descriptor`);
}
is(adapterInfo().map((a) => a.id), ["exact-host", "ct-subdomains", "sitemap-hosts"], "adapterInfo lists the Stage-1 adapters");
is(adapterInfo().find((a) => a.id === "exact-host").canEstablishAuthority, true, "only exact-host can establish authority");

/* ------------------------------ host helpers ------------------------------ */
console.log("--- host guard + pure parsers (deterministic, SSRF-lite)");
is(isSafeHttpsHost("api.acme.test"), true, "normal host allowed");
is(isSafeHttpsHost("127.0.0.1"), false, "IPv4 literal rejected");
is(isSafeHttpsHost("localhost"), false, "localhost rejected");
is(isSafeHttpsHost("thing.internal"), false, ".internal rejected");
is(isSafeHttpsHost("intranet"), false, "bare hostname rejected");
is(parseCtNames(routes["https://crt.sh/?q=%25.acme.test&output=json"].body, "acme.test"),
  ["api.acme.test", "docs.acme.test", "dead.acme.test"], "CT: apex/www/wildcard/cross-domain filtered, deduped");
is(parseCtNames("not json", "acme.test"), [], "CT: bad JSON → empty");
is(parseSitemapLocs("<urlset><url><loc>https://a.test/x</loc></url><url><loc>https://a.test/x</loc></url></urlset>"),
  ["https://a.test/x"], "sitemap locs deduped");
is(parseRobotsSitemaps("Sitemap: https://a.test/s.xml\nUser-agent: *"), ["https://a.test/s.xml"], "robots Sitemap: parsed");
is(hostsFromLocs(["https://api.a.test/1", "https://a.test/2", "https://10.0.0.1/x", "https://api.a.test/3"], "a.test"),
  ["api.a.test"], "hostsFromLocs: apex + IP excluded, deduped");

/* ------------------------------- tier: fast ------------------------------- */
console.log("--- tier: fast (exact-host only) mirrors v1 exactly");
const v1 = await resolveV1(SEED, opts);
is(Object.keys(v1).sort(), ["checked", "discovered", "domain", "provenance", "resources"], "v1 output shape unchanged");
const fast = await resolveV2(SEED, { ...opts, tier: "fast" });
is(fast.checked, ["exact-host"], "fast runs only exact-host");
is(fast.level2.length, 0, "fast yields no Level 2");
const key = (r) => r.url + "|" + r.source;
is(fast.level1.map((i) => key(i.resource)).sort(), (v1.resources || []).map(key).sort(),
  "fast Level-1 resources == v1 resources (v1 behavior preserved)");
is(fast.level1.every((i) => i.level === 1 && i.relationship === "publisher-hosted" && i.verification === "verified"), true,
  "fast items are publisher-hosted / Level 1 / verified");
is(fast.level1.every((i) => i.provenance.length > 0), true, "every fast item has provenance");

/* ----------------------------- tier: balanced ----------------------------- */
console.log("--- tier: balanced (adds CT + sitemap, all Level 2, provenance intact)");
const bal = await resolveV2(SEED, { ...opts, tier: "balanced" });
is(bal.checked, ["exact-host", "ct-subdomains", "sitemap-hosts"], "balanced runs all three adapters");
const host = (it) => (it.provenance.find((p) => p.host) || {}).host;
const apiItem = bal.items.find((i) => host(i) === "api.acme.test");
is(!!apiItem && apiItem.level === 2 && apiItem.relationship === "same-registrable-domain" && apiItem.verification === "verified", true,
  "CT-discovered api.acme.test is verified BUT stays Level 2 (same-registrable-domain)");
const partner = bal.items.find((i) => host(i) === "partner-cdn.test");
is(!!partner && partner.level === 2 && partner.relationship === "publisher-linked", true,
  "sitemap cross-host partner-cdn.test is Level 2 publisher-linked");
is(bal.items.every((i) => Array.isArray(i.provenance) && i.provenance.length >= 1), true,
  "every balanced item carries provenance");
is(apiItem.provenance.some((p) => p.source === "ct-log") && apiItem.provenance.some((p) => p.adapter === "exact-host"), true,
  "CT item provenance records the CT query AND the verifying resolve");
is(bal.stats.unreachable >= 1, true, "dead.acme.test counted as unreachable");
is(bal.stats.reachableEmpty >= 1, true, "docs.acme.test counted as reachable-but-empty (none), not a result");
is(bal.items.some((i) => host(i) === "docs.acme.test"), false, "reachable-empty host produces no item");
// The seed's own llms.txt is still there, still Level 1.
is(bal.level1.some((i) => i.relationship === "publisher-hosted"), true, "seed publisher-hosted resource still Level 1 in balanced");

console.log("--- grouping & deterministic order (grouped by class, not ranked)");
is(bal.items.every((i, n) => n === 0 || bal.items[n - 1].level <= i.level), true, "Level 1 items precede Level 2 items");

/* --------------------- determinism / store independence ------------------- */
console.log("--- determinism / store-independence (no persistent state)");
const a = await resolveV2(SEED, { ...opts, tier: "balanced" });
const b = await resolveV2(SEED, { ...opts, tier: "balanced" });
const strip = (r) => ({ ...r, stats: { ...r.stats, ms: 0 } });
is(JSON.stringify(strip(a)) === JSON.stringify(strip(b)), true, "two fresh runs classify identically (no hidden store)");

/* --------------------------------- tiers ---------------------------------- */
console.log("--- tier handling");
await throws(() => resolveV2(SEED, { ...opts, tier: "nonsense" }), "unknown tier throws");
const deep = await resolveV2(SEED, { ...opts, tier: "deep" });
is(deep.truncations.includes("deep tier not implemented in alpha; ran balanced"), true, "deep clamps to balanced and discloses it");
is(EXPERIMENTAL, true, "module is flagged EXPERIMENTAL");
is(/NOT active/.test(bal.charter), true, "result states Charter v2 is not active");

console.log(failed ? `\n${failed} FAILURES` : "\nAll v2-alpha tests passed.");
process.exit(failed ? 1 : 0);
