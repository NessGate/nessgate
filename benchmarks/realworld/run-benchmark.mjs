// Real-world compatibility benchmark: NessGate vs INDEPENDENT ground truth.
//
// Ground truth comes from corpus.json (probe-groundtruth.mjs, which never
// consulted NessGate). Here we run NessGate's reference library resolve() from
// the SAME machine/egress as the ground-truth prober, so a "miss" reflects
// NessGate's discovery LOGIC, not a network/bot-wall difference between the
// hosted worker's egress and the prober's (that is called out separately).
//
// Measures, per domain: correct discoveries, missed, false positives, incorrect
// attribution, latency, and request count. Emits results.jsonl + prints a
// stratified summary. Deterministic given the frozen corpus.
//
//   node benchmarks/realworld/run-benchmark.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(readFileSync(join(HERE, "corpus.json"), "utf8"));
const lib = await import("../../public/resolver.mjs");

async function runNessGate(domain) {
  let n = 0;
  const t0 = Date.now();
  const counting = async (url, opts) => { n++; return fetch(url, opts); };
  try {
    const r = await lib.resolve(domain, { fetch: counting, timeoutMs: 12000 });
    return { ok: true, requests: n, ms: Date.now() - t0, discovered: r.discovered || [], resources: r.resources || [] };
  } catch (e) {
    return { ok: false, requests: n, ms: Date.now() - t0, error: String(e.message).slice(0, 80), discovered: [], resources: [] };
  }
}

const rows = [];
let i = 0;
for (const d of corpus.domains) {
  i++;
  if (d.error) { rows.push({ domain: d.domain, skipped: "gt-error" }); continue; }
  const gtProtocols = new Set(d.groundTruthProtocols || []);
  const ng = await runNessGate(d.domain);
  const ngProtocols = new Set((ng.discovered || []).map((x) => x.type));

  const correct = [...gtProtocols].filter((p) => ngProtocols.has(p));
  const missed = [...gtProtocols].filter((p) => !ngProtocols.has(p));
  const falsePos = [...ngProtocols].filter((p) => !gtProtocols.has(p));

  // Attribution check. Since library 1.7.0, a followed cross-registrable
  // redirect records the FINAL URL and is HONESTLY labeled
  // class:"verified-external-location" (or lands under a record declared by
  // such a document) — that is correct, labeled attribution of a publisher
  // rebrand (neon.tech → neon.com), counted separately as externalLabeled.
  // "Misattributed" now means what it should: an off-domain sourceUrl WITHOUT
  // the honest external label — a record silently claiming the queried
  // domain's authority for another domain's bytes.
  const offDomain = (ng.resources || []).filter((r) => {
    try {
      if (!r.sourceUrl || r.sourceUrl.startsWith("dns:")) return false;
      const h = new URL(r.sourceUrl).hostname.toLowerCase().replace(/\.+$/, "");
      return h !== d.domain && !h.endsWith("." + d.domain);
    } catch { return true; }
  });
  const externalLabeled = offDomain.filter((r) => r.class === "verified-external-location" || r.class === "declared-external-pointer" || r.class === "publisher-declared")
    .map((r) => ({ source: r.source, sourceUrl: r.sourceUrl, class: r.class }));
  const misattributed = offDomain.filter((r) => !externalLabeled.some((e) => e.sourceUrl === r.sourceUrl && e.source === r.source))
    .map((r) => ({ source: r.source, sourceUrl: r.sourceUrl, class: r.class }));

  rows.push({
    domain: d.domain, stratum: d.stratum, category: d.category, blocked: d.blocked,
    groundTruth: [...gtProtocols], nessgate: [...ngProtocols],
    correct, missed, falsePositives: falsePos,
    misattributed,
    externalLabeled,
    resourceCount: (ng.resources || []).length, requests: ng.requests, ms: ng.ms, error: ng.error,
  });
  const flag = missed.length ? " MISS:" + missed.join(",") : "";
  const fp = falsePos.length ? " FP:" + falsePos.join(",") : "";
  console.log(`[${i}/${corpus.domains.length}] ${d.domain.padEnd(26)} ${(d.stratum||"?").padEnd(9)} gt:${gtProtocols.size} ng:${ngProtocols.size} req:${ng.requests}${flag}${fp}`);
}

writeFileSync(join(HERE, "results.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

// ---- stratified summary ----
const scored = rows.filter((r) => !r.skipped);
const positives = scored.filter((r) => r.stratum === "multi" || r.stratum === "single");
const negatives = scored.filter((r) => r.stratum === "negative");
const sum = (a) => a.reduce((x, y) => x + y, 0);
const med = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const p90 = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length * 0.9)]; };

const totalGtPositive = sum(positives.map((r) => r.groundTruth.length));
const totalCorrect = sum(positives.map((r) => r.correct.length));
const totalMissed = sum(positives.map((r) => r.missed.length));
const totalFP = sum(scored.map((r) => r.falsePositives.length));
const misattrCount = sum(scored.map((r) => r.misattributed.length));
const extLabeledCount = sum(scored.map((r) => (r.externalLabeled || []).length));
const negFP = negatives.filter((r) => r.nessgate.length > 0);

console.log("\n==== REAL-WORLD COMPATIBILITY SUMMARY ====");
console.log(`domains scored: ${scored.length} (multi ${scored.filter(r=>r.stratum==="multi").length}, single ${scored.filter(r=>r.stratum==="single").length}, negative ${negatives.length}, blocked ${scored.filter(r=>r.stratum==="blocked").length})`);
console.log(`ground-truth resources on positives: ${totalGtPositive}`);
console.log(`CORRECT discoveries: ${totalCorrect}/${totalGtPositive} (recall ${(100*totalCorrect/(totalGtPositive||1)).toFixed(1)}%)`);
console.log(`MISSED: ${totalMissed}  |  FALSE POSITIVES: ${totalFP}  |  MISATTRIBUTED (silent): ${misattrCount}  |  external, honestly labeled: ${extLabeledCount}`);
console.log(`negative controls with ANY NessGate output: ${negFP.length}/${negatives.length}`);
console.log(`latency ms  p50 ${med(scored.map(r=>r.ms))}  p90 ${p90(scored.map(r=>r.ms))}`);
console.log(`requests    p50 ${med(scored.map(r=>r.requests))}  p90 ${p90(scored.map(r=>r.requests))}`);
console.log("\n--- every MISS (investigate: NessGate logic gap, or GT judgment) ---");
for (const r of positives.filter((x) => x.missed.length)) console.log(`  ${r.domain}: missed ${r.missed.join(",")} (gt ${r.groundTruth.join(",")})`);
console.log("\n--- every FALSE POSITIVE (investigate) ---");
for (const r of scored.filter((x) => x.falsePositives.length)) console.log(`  ${r.domain}: FP ${r.falsePositives.join(",")}`);
console.log("\n--- MISATTRIBUTED (off-domain sourceUrl WITHOUT the honest external label — real defects) ---");
for (const r of scored.filter((x) => x.misattributed.length)) console.log(`  ${r.domain}: ${r.misattributed.map(m=>m.source+"→"+m.sourceUrl+" (class "+m.class+")").join("; ")}`);
console.log("\n--- external, honestly labeled (publisher rebrands followed + labeled; correct behavior) ---");
for (const r of scored.filter((x) => (x.externalLabeled || []).length)) console.log(`  ${r.domain}: ${[...new Set(r.externalLabeled.map(m=>new URL(m.sourceUrl).hostname))].join(", ")} (${r.externalLabeled.length} records)`);
console.log(`\nwrote results.jsonl (${rows.length} rows)`);
