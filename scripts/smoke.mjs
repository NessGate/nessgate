// Post-deploy smoke test: run `npm run smoke` after every deploy.
import { execSync } from "node:child_process";
const BASE = process.env.SMOKE_BASE || "https://nessgate.com";
let failed = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL  ${name}: ${e.message}`);
  }
}

const get = (p) => fetch(BASE + p, { redirect: "manual" });

await check("homepage 200 and serves CURRENT html (resolver + /check link)", async () => {
  const r = await get("/");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const t = await r.text();
  if (!t.includes("resolver")) throw new Error("unexpected body");
  if (!t.includes('href="/check"')) throw new Error("stale homepage: /check link missing");
});

for (const p of ["/check", "/guide", "/api", "/spec", "/charter", "/changelog", "/about", "/privacy", "/terms", "/contact",
  "/blog", "/blog/state-of-ai-discovery-september-2026", "/blog/what-is-ard-ai-catalog-json", "/blog/feed.xml",
  "/style.css", "/app.js", "/check.js", "/robots.txt", "/sitemap.xml", "/llms.txt", "/ai-info.json",
  "/openapi.json", "/resolver.mjs", "/favicon.svg", "/favicon.ico", "/logo-horizontal.svg", "/site.webmanifest",
  "/safari-pinned-tab.svg", "/og.png", "/.well-known/security.txt"]) {
  await check(`${p} 200`, async () => {
    const r = await get(p);
    if (r.status !== 200) throw new Error(`status ${r.status}`);
  });
}

await check("discover returns the normalized answer shape, labeled self-published", async () => {
  const r = await get("/discover/nessgate.com");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const d = await r.json();
  if (d.provenance !== "self-published") throw new Error("missing provenance label");
  if (typeof d.note !== "string" || d.note.length < 10) throw new Error("missing note");
  if (!Array.isArray(d.checked) || d.checked.length !== 9) throw new Error(`checked list should have 9 standards, got ${d.checked && d.checked.length}`);
  if (!Array.isArray(d.discovered)) throw new Error("discovered not an array");
});

await check("resolver discovers NessGate's OWN first-party files (self-probe path)", async () => {
  const d = await (await get("/discover/nessgate.com")).json();
  const types = (d.discovered || []).map((x) => x.type);
  for (const want of ["ai-info.json", "openapi", "llms.txt", "api-catalog"]) {
    if (!types.includes(want)) throw new Error(`self-discover missing ${want} (got ${types.join(",")})`);
  }
});

await check("resolver NORMALIZES documents into resource records (source + sourceUrl)", async () => {
  const d = await (await get("/discover/nessgate.com")).json();
  if (!Array.isArray(d.resources) || d.resources.length < 4) {
    throw new Error(`resources missing/short (${d.resources && d.resources.length})`);
  }
  for (const res of d.resources) {
    if (!res.source || !res.sourceUrl || !res.type || !res.url) throw new Error("resource record missing source/sourceUrl/type/url");
  }
  // api-catalog (a linkset) must flatten into multiple api-catalog-sourced records.
  const apiCat = d.resources.filter((x) => x.source === "api-catalog");
  if (apiCat.length < 2) throw new Error(`api-catalog linkset not flattened (${apiCat.length})`);
});

await check("discover rejects invalid domain (400) and self-subdomains (400)", async () => {
  const bad = await get("/discover/not_a_domain");
  if (bad.status !== 400) throw new Error(`invalid status ${bad.status}`);
  const sub = await get("/discover/api.nessgate.com");
  if (sub.status !== 400) throw new Error(`self-subdomain status ${sub.status}`);
});

await check("REMOVED registry endpoints are gone (404): /resolve, /registry.json, /export", async () => {
  // Cache-buster query keeps this testing WORKER behavior, not a stale 60s edge
  // cache left over from the pre-removal deploy.
  const cb = `?nocache=${Date.now()}`;
  for (const p of ["/resolve/nessgate.com", "/registry.json", "/export/nessgate.com/ard.json"]) {
    const r = await get(p + cb);
    if (r.status !== 404) throw new Error(`${p} should be 404, got ${r.status}`);
  }
});

await check("human-readable domain page renders (live discovery)", async () => {
  const r = await get("/example.com");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const t = await r.text();
  if (!t.includes("example.com")) throw new Error("domain page missing domain");
});

await check("own /.well-known/api-catalog is an RFC 9727 linkset", async () => {
  const r = await get("/.well-known/api-catalog");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  if (!(r.headers.get("content-type") || "").includes("linkset")) throw new Error("wrong content-type");
  const doc = await r.json();
  if (!Array.isArray(doc.linkset) || !doc.linkset[0]["service-desc"]) throw new Error("not a linkset");
});

await check("openapi.json documents /discover (and not the removed registry paths)", async () => {
  const r = await get("/openapi.json");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const doc = await r.json();
  if (!doc.paths["/discover/{domain}"]) throw new Error("openapi missing /discover");
  for (const gone of ["/resolve/{domain}", "/registry.json", "/export/{domain}/ard.json"]) {
    if (doc.paths[gone]) throw new Error(`openapi still documents removed path ${gone}`);
  }
  const documented =
    doc.paths["/discover/{domain}"].get.responses["200"].content["application/json"].schema.properties.checked.example;
  const live = await (await get("/discover/nessgate.com")).json();
  if (JSON.stringify(documented) !== JSON.stringify(live.checked)) {
    throw new Error(`openapi checked ${JSON.stringify(documented)} != live ${JSON.stringify(live.checked)}`);
  }
});

await check("MCP server: initialize + tools/list (discover_domain only) + a real tool call", async () => {
  const rpc = (body) =>
    fetch(BASE + "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const init = await (await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })).json();
  if (!init.result || !init.result.serverInfo || init.result.serverInfo.name !== "nessgate") throw new Error("bad initialize");
  if (!init.result.capabilities.tools) throw new Error("tools capability missing");
  const list = await (await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" })).json();
  const names = (list.result.tools || []).map((t) => t.name);
  if (JSON.stringify(names) !== JSON.stringify(["discover_domain"])) throw new Error(`tools should be [discover_domain], got ${names}`);
  const call = await (await rpc({
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { name: "discover_domain", arguments: { domain: "nessgate.com" } },
  })).json();
  if (!call.result || call.result.isError) throw new Error("discover tool call errored");
  if (!call.result.structuredContent || call.result.structuredContent.provenance !== "self-published") {
    throw new Error("discover tool did not return the normalized structured content");
  }
});

await check("MCP server: unknown method and unknown tool are handled per JSON-RPC", async () => {
  const rpc = (body) =>
    fetch(BASE + "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const bad = await (await rpc({ jsonrpc: "2.0", id: 9, method: "no/such/method" })).json();
  if (!bad.error || bad.error.code !== -32601) throw new Error("expected method-not-found error");
  const badTool = await (await rpc({
    jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "resolve_domain", arguments: {} },
  })).json();
  if (!badTool.error || badTool.error.code !== -32602) throw new Error("expected invalid-params for the removed resolve_domain tool");
  const getReq = await get("/mcp");
  if (getReq.status !== 405) throw new Error(`GET /mcp should be 405, got ${getReq.status}`);
});

await check("embeddable resolver library is served and exports resolve()", async () => {
  const r = await get("/resolver.mjs");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const ct = (r.headers.get("content-type") || "").toLowerCase();
  if (!ct.includes("javascript") && !ct.includes("ecmascript")) throw new Error(`unexpected content-type ${ct}`);
  const body = await r.text();
  if (!/export\s+async\s+function\s+resolve/.test(body)) throw new Error("resolve() export missing");
  if (!body.includes("normalizeResources")) throw new Error("normalizer missing from library");
});

await check("retired /setup 301-redirects to /guide", async () => {
  const r = await get("/setup");
  if (r.status !== 301) throw new Error(`status ${r.status}`);
  if (!(r.headers.get("location") || "").endsWith("/guide")) throw new Error("bad redirect target");
});

await check("www redirects 301 to apex", async () => {
  const r = await fetch("https://www.nessgate.com/about", { redirect: "manual" });
  if (r.status !== 301) throw new Error(`status ${r.status}`);
  if (!(r.headers.get("location") || "").startsWith("https://nessgate.com/")) throw new Error("bad location");
});

await check("HSTS present on HTML", async () => {
  const r = await get("/spec");
  if (!(r.headers.get("strict-transport-security") || "").includes("max-age")) throw new Error("missing HSTS");
});

await check("sitemap.xml is a urlset of the static pages", async () => {
  const r = await get("/sitemap.xml");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const t = await r.text();
  if (!t.includes("<urlset")) throw new Error("not a urlset");
  if (!t.includes("/spec") || !t.includes("/api")) throw new Error("missing expected page URLs");
});

await check("security headers uniform on non-HTML routes", async () => {
  for (const p of ["/.well-known/security.txt", "/sitemap.xml", "/version"]) {
    const r = await get(p);
    for (const h of ["strict-transport-security", "x-content-type-options", "x-frame-options"]) {
      if (!r.headers.get(h)) throw new Error(`${p} missing ${h}`);
    }
  }
});

await check("deployed build matches local HEAD", async () => {
  const r = await get("/version");
  if (r.status !== 200) throw new Error(`status ${r.status}`);
  const { build } = await r.json();
  if (!r.headers.get("x-nessgate-build")) throw new Error("missing X-NessGate-Build header");
  let head = "";
  try {
    head = execSync("git rev-parse --short HEAD").toString().trim();
  } catch {
    return; // no git available; endpoint check above still ran
  }
  if (build !== head) throw new Error(`deployed "${build}" != local HEAD "${head}" (dirty builds are rejected at deploy time)`);
});

console.log(failed ? `\n${failed} FAILURES` : "\nAll smoke tests passed.");
process.exit(failed ? 1 : 0);
