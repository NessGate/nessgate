// M0.5 — refine ground truth: re-fetch each JSON surface the probe found and
// check it against the SPEC-DEFINED shape (not NessGate's code — these are the
// standards' own required fields), to weed out catch-all/SPA false positives.
// llms.txt (text) hits from the probe are trusted (already non-HTML checked).
// Output: refined per-domain genuine surfaces for hand review before freezing.
//
// Usage: node benchmarks/verify-groundtruth.mjs <probe.jsonl> <outJsonl>
import { readFileSync, writeFileSync } from "node:fs";

const [inFile, outFile] = process.argv.slice(2);
if (!inFile || !outFile) { console.error("usage: node verify-groundtruth.mjs <probe.jsonl> <outJsonl>"); process.exit(1); }

// Spec-defined shape — the document's OWN standard requires these. (Derived from
// each spec, matching what any correct reader would demand; independent ruler.)
function shapeOk(proto, obj) {
  if (!obj || typeof obj !== "object") return false;
  switch (proto) {
    case "ard-catalog": return Array.isArray(obj.entries);
    case "api-catalog": return Array.isArray(obj.linkset);
    case "openapi": return typeof obj.openapi === "string" || typeof obj.swagger === "string";
    case "a2a-agent-card": return typeof obj.name === "string" || typeof obj.url === "string" || Array.isArray(obj.supportedInterfaces);
    case "ucp": return Array.isArray(obj.capabilities) || typeof obj.ucp_version === "string";
    case "awp": return obj.protocols !== undefined;
    case "host-meta": return Array.isArray(obj.links);
    case "anp": return Array.isArray(obj.items) || obj["@type"] === "CollectionPage";
    case "ord": return true; // ORD wrapper varies; pointer-only. Kept as-is; noted.
    case "ai-info.json": return true; // no formal schema; any object accepted (noted)
    default: return true;
  }
}

async function get(url, timeoutMs = 6000) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { redirect: "follow", signal: ctrl.signal, headers: { "User-Agent": "NessGate-GroundTruthProbe/0 (+https://nessgate.com)", Accept: "application/json,text/plain,*/*" } });
    return { status: res.status, body: await res.text() };
  } catch (e) { return { status: 0, error: String((e && e.name) || e) }; }
  finally { clearTimeout(t); }
}

const rows = readFileSync(inFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const out = [];
for (const r of rows) {
  const genuine = [];
  for (const f of r.found || []) {
    if (f.kind === "text" || f.kind === "dns") { genuine.push({ ...f, genuine: true }); continue; }
    // re-fetch and spec-shape-check json surfaces
    const g = await get("https://" + r.domain + f.path);
    let ok = false, keys = [];
    if (g.status === 200) { try { const o = JSON.parse(g.body); keys = Object.keys(o).slice(0, 8); ok = shapeOk(f.proto, o); } catch {} }
    genuine.push({ ...f, genuine: ok, topKeys: keys });
  }
  const genuineProtos = [...new Set(genuine.filter((g) => g.genuine).map((g) => g.proto))];
  const row = { domain: r.domain, reachable: r.reachable, blocked: r.blocked, genuine: genuine.filter((g) => g.genuine), rejected: genuine.filter((g) => !g.genuine), protocols: genuineProtos, nGenuine: genuineProtos.length };
  out.push(row);
  process.stdout.write(`${r.domain}: ${row.blocked ? "BLOCKED " : ""}${genuineProtos.join(",") || (r.reachable ? "(none)" : "unreachable")}${row.rejected.length ? "  [rejected: " + row.rejected.map((x) => x.proto).join(",") + "]" : ""}\n`);
}
writeFileSync(outFile, out.map((r) => JSON.stringify(r)).join("\n") + "\n");
console.log("VERIFY DONE →", outFile);
