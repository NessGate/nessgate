// Layer 1 — OFFICIAL conformance. Runs each vendored official/canonical document
// (compat/vendor/**, from the ecosystems' own specs/RFCs, license recorded in
// each SOURCE.md) through the resolver and asserts we detect + normalize it
// correctly. This checks NessGate against the standards' own material, not just
// our synthetic fixtures. Run with `npm run test:conformance`. No network.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validateProbeContent, probeShapeOk, normalizeResources, detectOpenApi } from "../packages/resolver/index.mjs";

let failed = 0;
const is = (a, e, n) => { const ok = JSON.stringify(a) === JSON.stringify(e); console[ok ? "log" : "error"](`${ok ? "  ok " : "FAIL"}  ${n}`); if (!ok) { failed++; console.error(`      got ${JSON.stringify(a)} want ${JSON.stringify(e)}`); } };
const vurl = (rel) => fileURLToPath(new URL("../compat/vendor/" + rel, import.meta.url));
const read = (rel) => readFileSync(vurl(rel), "utf8");

console.log("--- layer 1: official conformance vectors");

// OpenAPI 3.0 — official OAI petstore.
{
  const body = read("openapi/3.0/petstore.json");
  const d = detectOpenApi(body);
  is(d.ok, true, "OAI petstore.json is detected as OpenAPI");
  is(d.title, "Swagger Petstore", "OAI petstore title normalized");
}

// api-catalog — RFC 9727 Appendix A example.
{
  const body = read("api-catalog/rfc9727/example.json");
  is(validateProbeContent("json", body) && probeShapeOk("api-catalog", "json", body), true, "RFC 9727 linkset is accepted");
  const recs = normalizeResources("api-catalog", "json", body, "https://example.com/.well-known/api-catalog");
  is(recs.length > 0, true, "RFC 9727 linkset normalizes to >=1 record");
  is(recs.every((r) => r.source === "api-catalog" && r.url && r.rel), true, "RFC 9727 records carry source/url/rel");
  is(recs.some((r) => r.rel === "service-desc" && /foo_api\/spec$/.test(r.url)), true, "RFC 9727 service-desc link extracted");
}

// host-meta — RFC 6415 JRD example.
{
  const body = read("host-meta/rfc6415/example.json");
  is(validateProbeContent("json", body) && probeShapeOk("host-meta", "json", body), true, "RFC 6415 JRD is accepted");
  const recs = normalizeResources("host-meta", "json", body, "https://example.com/.well-known/host-meta.json");
  // Only links with an href are emitted (a template-only link is correctly skipped).
  is(recs.length, 1, "RFC 6415 JRD: only the href link is emitted (template-only skipped)");
  is(recs[0].rel, "hub", "RFC 6415 JRD: hub link normalized");
}

console.log(failed ? `\n${failed} CONFORMANCE FAILURES` : "\nAll official conformance vectors pass.");
process.exit(failed ? 1 : 0);
