// One-shot SEED generator for the compatibility corpus (M1 backfill). Emits the
// initial fixtures, adapter manifests, and matrix from (a) the existing
// hand-written normalization tests and (b) the live ADAPTERS array. After this,
// NEW fixtures are added BY HAND per the rule in compat/README.md ("every
// compatibility fix adds a permanent regression fixture"). Kept in-repo for
// provenance of the seed set; not part of CI.
//
// Usage: node compat/_generate-seed.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { ADAPTERS } from "../packages/resolver/index.mjs";

const root = new URL("./", import.meta.url);
const w = (rel, obj) => {
  const p = new URL(rel, root); mkdirSync(new URL("./", p), { recursive: true });
  writeFileSync(p, JSON.stringify(obj, null, 2) + "\n");
};

/* -------------------------------- fixtures -------------------------------- */
// Each: parser/normalizer regression at the document level (no network).
// origin: official-example | reference-impl | real-world | synthetic
const F = [];
const fx = (o) => F.push(o);

// -- positive: normalization must produce the expected records --
fx({ id: "ard-catalog/0.91/basic-url-entry", protocol: "ard-catalog", version: "0.91", surface: "/.well-known/ard.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/ard.json", body: JSON.stringify({ entries: [{ identifier: "urn:air:x.com:n:r-1", displayName: "Data", type: "application/json", url: "https://x.com/a.json" }, { displayName: "no url" }] }) },
  expect: { verification: "verified", relationship: "publisher-hosted", level: 1, resources: [{ source: "ard-catalog", type: "application/json", url: "https://x.com/a.json", id: "urn:air:x.com:n:r-1" }] }, notes: "only entries with a url; source media type reused; identifier preserved" });
fx({ id: "ard-catalog/0.91/inline-data-entry", protocol: "ard-catalog", version: "0.91", surface: "/.well-known/ard.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/ard.json", body: JSON.stringify({ entries: [{ identifier: "urn:x:1", displayName: "Inline", type: "application/json", data: { a: 1 } }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "ard-catalog", type: "application/json", url: "https://x.com/.well-known/ard.json", inline: true }] }, notes: "inline-data entry kept, points back to the catalog, flagged inline" });
fx({ id: "host-meta/rfc6415/links", protocol: "host-meta", version: "rfc6415", surface: "/.well-known/host-meta.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/host-meta.json", body: JSON.stringify({ links: [{ rel: "hub", type: "application/json", href: "https://x.com/h" }, { rel: "noHref" }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "host-meta", type: "application/json", rel: "hub", url: "https://x.com/h" }] }, notes: "legacy RFC 6415; only links with href; rel/type reused" });
fx({ id: "api-catalog/rfc9727/linkset-service-desc", protocol: "api-catalog", version: "rfc9727", surface: "/.well-known/api-catalog", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/api-catalog", body: JSON.stringify({ linkset: [{ anchor: "https://x.com/api", "service-desc": [{ href: "https://x.com/openapi.json", type: "application/openapi+json" }] }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "api-catalog", rel: "service-desc", url: "https://x.com/openapi.json" }] }, notes: "iterate rel arrays; scalar anchor skipped" });
fx({ id: "awp/draft/protocols-object-and-string", protocol: "awp", version: "draft", surface: "/.well-known/awp.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/awp.json", body: JSON.stringify({ protocols: { mcp: { url: "https://mcp.x.com" }, a2a: "https://x.com/.well-known/agent.json" } }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "awp", type: "mcp", url: "https://mcp.x.com" }, { source: "awp", type: "a2a", url: "https://x.com/.well-known/agent.json" }] }, notes: "object-form and string-form protocol entries both extracted" });
fx({ id: "a2a-agent-card/1.0/supported-interfaces", protocol: "a2a-agent-card", version: "1.0", surface: "/.well-known/agent-card.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/agent-card.json", body: JSON.stringify({ name: "Ag", supportedInterfaces: [{ url: "https://x.com/a2a", transport: "JSONRPC" }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "a2a-agent-card", url: "https://x.com/a2a" }] }, notes: "A2A v1.0: url from supportedInterfaces[0]" });
fx({ id: "a2a-agent-card/legacy/top-level-url", protocol: "a2a-agent-card", version: "legacy", surface: "/.well-known/agent-card.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/agent-card.json", body: JSON.stringify({ name: "Ag", url: "https://x.com/legacy" }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "a2a-agent-card", url: "https://x.com/legacy" }] }, notes: "legacy: explicit top-level url preferred" });
fx({ id: "anp/draft/collectionpage-items", protocol: "anp", version: "draft", surface: "/.well-known/agent-descriptions", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/agent-descriptions", body: JSON.stringify({ "@type": "CollectionPage", items: [{ "@type": "ad:AgentDescription", name: "Bot", "@id": "https://x.com/agents/bot.json" }, { name: "no id" }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "anp", type: "agent-description", name: "Bot", url: "https://x.com/agents/bot.json" }] }, notes: "only items with @id; @id becomes url" });
fx({ id: "ucp/2026-01/capabilities-transports", protocol: "ucp", version: "2026-01", surface: "/.well-known/ucp", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/ucp", body: JSON.stringify({ ucp_version: "2026-01", capabilities: [{ name: "checkout", transports: [{ type: "mcp", url: "https://x.com/mcp" }, { type: "rest", endpoint: "https://x.com/api" }] }] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "ucp", type: "mcp", url: "https://x.com/mcp" }, { source: "ucp", type: "rest", url: "https://x.com/api" }] }, notes: "one record per transport binding; endpoint alias" });
fx({ id: "ucp/2026-01/no-endpoints-points-to-profile", protocol: "ucp", version: "2026-01", surface: "/.well-known/ucp", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/ucp", body: JSON.stringify({ ucp_version: "2026-01", capabilities: [] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "ucp", url: "https://x.com/.well-known/ucp" }] }, notes: "no endpoints → points to the profile" });
fx({ id: "llms.txt/1.0/pointer", protocol: "llms.txt", version: "1.0", surface: "/llms.txt", kind: "text", origin: "synthetic",
  input: { url: "https://x.com/llms.txt", body: "# Acme\n> stuff" },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "llms.txt", url: "https://x.com/llms.txt" }] }, notes: "pointer standard: points to the file, prose not parsed" });
fx({ id: "ord/1/pointer", protocol: "ord", version: "1", surface: "/.well-known/open-resource-discovery", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/open-resource-discovery", body: JSON.stringify({ openResourceDiscoveryV1: {} }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "ord", type: "ord", url: "https://x.com/.well-known/open-resource-discovery" }] }, notes: "pointer only; no enterprise-schema interpretation" });
fx({ id: "openapi/3.0/basic", protocol: "openapi", version: "3.0", surface: "/openapi.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/openapi.json", body: JSON.stringify({ openapi: "3.0.0", info: { title: "Acme API" }, paths: {} }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "openapi", type: "openapi", name: "Acme API", url: "https://x.com/openapi.json" }] }, notes: "pointer; title surfaced as name" });
fx({ id: "gbz-185-4/2.2/acs-at-agent-card", protocol: "a2a-agent-card", version: "gbz-185-4", surface: "/.well-known/agent-card.json", kind: "json", origin: "synthetic",
  input: { url: "https://x.com/.well-known/agent-card.json", body: JSON.stringify({ aic: "urn:acps:001", protocolVersion: "02.02", name: "registry-service", version: "2.2.0", securitySchemes: { mtls: { type: "mutualTLS" } }, certificate: { requestedValidity: 1825 }, endPoints: [{ url: "https://x.com/agent" }], skills: [] }) },
  expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: "gbz-185-4", type: "gbz-185-4-acs", url: "https://x.com/agent" }] }, notes: "China GB/Z 185.4 ACS recognized by content at the agent-card location; labelled gbz-185-4 not A2A" });

// -- reject: catch-alls / wrong shape / HTML shells MUST be rejected --
const rej = (id, protocol, kind, body, notes, origin = "synthetic") =>
  fx({ id, protocol, kind, origin, input: { url: "https://x.com/probe", body: typeof body === "string" ? body : JSON.stringify(body) }, expect: { reject: true }, notes });
rej("llms.txt/reject/html-shell", "llms.txt", "text", "<!DOCTYPE html><html><head><title>SPA</title></head><body></body></html>", "SPA HTML shell served for every path must not pass as llms.txt");
rej("ard-catalog/reject/catch-all-empty", "ard-catalog", "json", {}, "empty object (JSON 404 catch-all) has no entries[] → rejected");
rej("api-catalog/reject/no-linkset", "api-catalog", "json", { data: [] }, "no linkset[] → rejected");
rej("openapi/reject/no-openapi-field", "openapi", "json", { hello: "world" }, "generic JSON without openapi/swagger → rejected");
rej("ucp/reject/catch-all", "ucp", "json", { message: "not found" }, "real-world: a 200 JSON at /.well-known/ucp without capabilities/ucp_version (observed on ucpchecker.com) → rejected", "real-world");
rej("a2a-agent-card/reject/empty", "a2a-agent-card", "json", { foo: 1 }, "no name/url/supportedInterfaces → rejected");
rej("ard-catalog/reject/malformed-json", "ard-catalog", "json", "{not json", "malformed JSON → rejected, never throws");

for (const f of F) w(`fixtures/${f.id}.json`, f);

/* ---------------------------- adapter manifests --------------------------- */
// Contract fields the corpus needs but the runtime ADAPTERS array doesn't carry.
const CONTRACT = {
  "llms.txt": { authority: "publisher-hosted", kind: "text", versions: ["1.0"] },
  "ard-catalog": { authority: "publisher-hosted", kind: "json", versions: ["0.91"] },
  "a2a-agent-card": { authority: "publisher-hosted", kind: "json", versions: ["1.0", "legacy", "gbz-185-4"] },
  "api-catalog": { authority: "publisher-hosted", kind: "json", versions: ["rfc9727"] },
  "ai-info.json": { authority: "publisher-hosted", kind: "json", versions: ["draft"] },
  "openapi": { authority: "publisher-hosted", kind: "json", versions: ["3.0", "3.1", "2.0"] },
  "ord": { authority: "publisher-hosted", kind: "json", versions: ["1"] },
  "awp": { authority: "publisher-hosted", kind: "json", versions: ["draft"] },
  "host-meta": { authority: "publisher-hosted", kind: "json", versions: ["rfc6415"] },
  "anp": { authority: "publisher-hosted", kind: "json", versions: ["draft"] },
  "ucp": { authority: "publisher-hosted", kind: "json", versions: ["2026-01"] },
  "ard-link": { authority: "publisher-hosted", kind: "html", versions: ["0.91"], normalizeAs: "ard-catalog" },
  "ard-agentmap": { authority: "publisher-hosted", kind: "robots", versions: ["0.91"], normalizeAs: "ard-catalog" },
  "aid": { authority: "publisher-hosted", kind: "dns", versions: ["aid1"] },
};
const fixturesByProto = {};
for (const f of F) { const p = f.protocol; (fixturesByProto[p] ||= []).push(f.id); }
// gbz-185-4 fixtures live under a2a-agent-card protocol but count for gbz too
const gbzFixtures = F.filter((f) => f.id.startsWith("gbz-185-4/")).map((f) => f.id);

const manifests = {};
for (const a of ADAPTERS) {
  const c = CONTRACT[a.id] || { authority: "publisher-hosted", kind: a.kind || "json", versions: ["unknown"] };
  const m = {
    id: a.id,
    channel: a.channel,
    surfaces: a.paths || (a.rels ? [`<link rel=${a.rels.join("|")}>`] : a.directive ? [`robots ${a.directive}:`] : a.node ? [`DNS TXT ${a.node}`] : []),
    versions: c.versions,
    authority: c.authority,          // all current adapters read the domain's own surface → Level 1
    canEstablishAuthority: true,
    normalizeAs: a.normalizeAs || a.id,
    provenanceRequired: true,
    officialSuite: null,             // filled in M2
    deviations: [],
    fixtures: fixturesByProto[a.normalizeAs || a.id] || fixturesByProto[a.id] || [],
  };
  manifests[a.id] = m;
  w(`adapters/${a.id}.json`, m);
}

/* --------------------------------- matrix --------------------------------- */
const matrix = {};
for (const a of ADAPTERS) {
  const m = manifests[a.id];
  const proto = a.normalizeAs || a.id;
  matrix[proto] ||= {};
  for (const v of m.versions) {
    matrix[proto][v] = {
      surfaces: m.surfaces,
      parser: `normalizeResources('${proto}')`,
      authority: `${m.authority} (Level 1) — the domain's own surface`,
      officialSuite: m.officialSuite,
      deviations: proto === "openapi" ? ["specs >1MB exceed the resolver maxBytes cap and are currently missed (see benchmarks/V2-ALPHA-REPORT-... ; fix will add a resolve-level fixture per the corpus rule)"] : [],
      fixtures: (fixturesByProto[proto] || []).concat(proto === "a2a-agent-card" ? [] : []),
    };
  }
}
// gbz-185-4 is a distinct protocol recognized by content at the a2a surface
matrix["gbz-185-4"] = { "2.2": { surfaces: ["/.well-known/agent-card.json (content-recognized)"], parser: "normalizeResources('gbz-185-4') / isAcs", authority: "publisher-hosted (Level 1)", officialSuite: null, deviations: ["recognized by content (aic / certificate.requestedValidity), never a guessed path"], fixtures: gbzFixtures } };
w("matrix.json", matrix);

console.log(`seed generated: ${F.length} fixtures, ${Object.keys(manifests).length} adapter manifests, ${Object.keys(matrix).length} matrix protocols`);
