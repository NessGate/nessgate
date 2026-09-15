// Paced production verification against hosted nessgate.com from the operator's
// real IP (rate-limit-exempted via RL_BYPASS_IP for the run). Sequential, with a
// pause between domains, capturing cf-cache-status/age so cached responses can
// be reported separately from fresh ones (they measure the edge, not coverage).
import { readFileSync, appendFileSync, writeFileSync } from "node:fs";

const [cohortFile, outFile] = process.argv.slice(2);
const base = "https://nessgate.com";
const domains = readFileSync(cohortFile, "utf8").split("\n").map((s) => s.trim()).filter(Boolean);
const TIMEOUT_MS = 45000;
const PAUSE_MS = 8000;

async function step(url) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    const ms = Date.now() - t0;
    const cache = res.headers.get("cf-cache-status") || "-";
    const age = res.headers.get("age") || "0";
    let body = null;
    try { body = await res.json(); } catch {}
    return { status: res.status, ms, cache, age, body };
  } catch (e) {
    return { status: 0, ms: Date.now() - t0, cache: "-", age: "0", err: String(e && e.name) };
  } finally {
    clearTimeout(timer);
  }
}

writeFileSync(outFile, "");
for (const d of domains) {
  const disc = await step(`${base}/discover/${encodeURIComponent(d)}`);
  const org = await step(`${base}/explore/${encodeURIComponent(d)}?org=1`);
  const rel = await step(`${base}/explore/${encodeURIComponent(d)}?related=1`);
  const row = {
    domain: d,
    discStatus: disc.status, discMs: disc.ms, discCache: disc.cache,
    discResources: disc.status === 200 && disc.body ? (disc.body.resources || []).length : null,
    orgStatus: org.status, orgMs: org.ms, orgCache: org.cache,
    orgIncremental: org.status === 200 && org.body && org.body.stats ? org.body.stats.sameDomainHost || 0 : null,
    relStatus: rel.status, relMs: rel.ms, relCache: rel.cache,
    relIncremental: rel.status === 200 && rel.body ? (rel.body.related || []).length : null,
  };
  row.exactPositive = row.discResources !== null && row.discResources > 0;
  row.orgPositive = row.orgIncremental !== null && row.orgIncremental > 0;
  row.relPositive = row.relIncremental !== null && row.relIncremental > 0;
  row.blockedOrTimeout = disc.status !== 200 || org.status !== 200 || rel.status !== 200;
  row.genuineEmpty = !row.blockedOrTimeout && row.discResources === 0 && row.orgIncremental === 0 && row.relIncremental === 0;
  appendFileSync(outFile, JSON.stringify(row) + "\n");
  console.log(`${d}: disc=${row.discResources ?? "ERR"}(${disc.cache}) org+=${row.orgIncremental ?? "ERR"} rel+=${row.relIncremental ?? "ERR"}`);
  await new Promise((r) => setTimeout(r, PAUSE_MS));
}

const rows = readFileSync(outFile, "utf8").trim().split("\n").map(JSON.parse);
const n = rows.length;
const pct = (k) => ((100 * rows.filter((r) => r[k]).length) / n).toFixed(1) + "%";
console.log(`\n=== PROD summary (${n} domains) ===`);
console.log(`exact positive: ${pct("exactPositive")} | org incremental: ${pct("orgPositive")} | related incremental: ${pct("relPositive")}`);
console.log(`any-layer: ${((100 * rows.filter((r) => r.exactPositive || r.orgPositive || r.relPositive).length) / n).toFixed(1)}% | genuine empty: ${pct("genuineEmpty")} | blocked/timeout: ${pct("blockedOrTimeout")}`);
const cached = rows.filter((r) => r.discCache === "HIT").length;
console.log(`edge-cached /discover responses: ${cached}/${n} (reported separately; fresh runs measure coverage)`);
const lat = rows.filter((r) => !r.blockedOrTimeout).map((r) => r.discMs + r.orgMs + r.relMs).sort((a, b) => a - b);
if (lat.length) console.log(`triplet latency p50/p90: ${lat[Math.floor(lat.length * 0.5)]}ms / ${lat[Math.floor(lat.length * 0.9)]}ms`);
