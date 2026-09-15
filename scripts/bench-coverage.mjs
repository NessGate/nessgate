// Coverage benchmark for the v1.5 resolver engine (run against `wrangler dev --local`).
// For each domain in the two predetermined cohorts, records separately:
//   discover  — GET /discover/{d}            (exact-host)
//   org       — GET /explore/{d}?org=1       (incremental: stats.sameDomainHost)
//   related   — GET /explore/{d}?related=1   (incremental: related[].length)
// plus per-step latency and status. No code changes to the resolver; harness only.
// Usage: node scripts/bench-coverage.mjs <base> <cohortFile> <label> <outJsonl>
import { readFileSync, appendFileSync, writeFileSync } from "node:fs";

const [base, cohortFile, label, outFile] = process.argv.slice(2);
const domains = readFileSync(cohortFile, "utf8").split("\n").map((s) => s.trim()).filter(Boolean);
const TIMEOUT_MS = 35000;
const CONCURRENCY = 3;

// Local-dev only: give each domain its own synthetic client IP so the app's
// per-IP rate limit (60 explore/hr) measures per-client behavior instead of
// tripping on the benchmark's aggregate volume. Header-only; no product change.
let ipCounter = 0;
async function step(url, ip) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "CF-Connecting-IP": ip } });
    const ms = Date.now() - t0;
    let body = null;
    try { body = await res.json(); } catch {}
    return { status: res.status, ms, body };
  } catch (e) {
    return { status: 0, ms: Date.now() - t0, err: String(e && e.name) };
  } finally {
    clearTimeout(timer);
  }
}

async function runDomain(d) {
  const n = ++ipCounter;
  const ip = `10.${Math.floor(n / 250) + 1}.${(n % 250) + 1}.7`;
  const disc = await step(`${base}/discover/${encodeURIComponent(d)}`, ip);
  const org = await step(`${base}/explore/${encodeURIComponent(d)}?org=1`, ip);
  const rel = await step(`${base}/explore/${encodeURIComponent(d)}?related=1`, ip);
  const discRes = disc.status === 200 && disc.body ? (disc.body.resources || []).length : null;
  const orgInc = org.status === 200 && org.body && org.body.stats ? org.body.stats.sameDomainHost || 0 : null;
  const relInc = rel.status === 200 && rel.body ? (rel.body.related || []).length : null;
  const anyFail = disc.status !== 200 || org.status !== 200 || rel.status !== 200;
  const row = {
    cohort: label,
    domain: d,
    discStatus: disc.status, discMs: disc.ms, discResources: discRes,
    orgStatus: org.status, orgMs: org.ms, orgIncremental: orgInc,
    relStatus: rel.status, relMs: rel.ms, relIncremental: relInc,
    exactPositive: discRes !== null && discRes > 0,
    orgPositive: orgInc !== null && orgInc > 0,
    relPositive: relInc !== null && relInc > 0,
    blockedOrTimeout: anyFail,
    genuineEmpty: !anyFail && discRes === 0 && orgInc === 0 && relInc === 0,
  };
  appendFileSync(outFile, JSON.stringify(row) + "\n");
  process.stdout.write(`${label} ${d}: disc=${discRes ?? "ERR"} org+=${orgInc ?? "ERR"} rel+=${relInc ?? "ERR"} (${disc.ms + org.ms + rel.ms}ms)\n`);
  return row;
}

writeFileSync(outFile, "");
const queue = [...domains];
const rows = [];
async function worker() {
  for (;;) {
    const d = queue.shift();
    if (!d) return;
    rows.push(await runDomain(d));
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));

const n = rows.length;
const pct = (k) => ((100 * rows.filter((r) => r[k]).length) / n).toFixed(1) + "%";
console.log(`\n=== ${label} summary (${n} domains) ===`);
console.log(`exact /discover positive: ${pct("exactPositive")}`);
console.log(`org=1 incremental positive: ${pct("orgPositive")}`);
console.log(`related=1 incremental positive: ${pct("relPositive")}`);
console.log(`any-layer positive: ${((100 * rows.filter((r) => r.exactPositive || r.orgPositive || r.relPositive).length) / n).toFixed(1)}%`);
console.log(`genuine empty: ${pct("genuineEmpty")}`);
console.log(`blocked/timeout (any step): ${pct("blockedOrTimeout")}`);
const lat = rows.filter((r) => !r.blockedOrTimeout).map((r) => r.discMs + r.orgMs + r.relMs).sort((a, b) => a - b);
if (lat.length) console.log(`total latency p50/p90: ${lat[Math.floor(lat.length * 0.5)]}ms / ${lat[Math.floor(lat.length * 0.9)]}ms`);
