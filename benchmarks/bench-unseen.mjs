// M0.5 — unseen-domain benchmark (the moat metric). Runs the deterministic
// resolver (library exact-host via resolveV2 fast → two-axis, for classification
// + provenance checks) against the FROZEN holdout and reports SEPARATED metrics.
// Never one "accuracy" number: a resolver that returns nothing must not score
// well just because many sites expose nothing.
//
// Ground truth is the independent probe (holdout-unseen.json), NOT the resolver.
// Usage: node benchmarks/bench-unseen.mjs <outJsonl>
import { readFileSync, appendFileSync, writeFileSync, existsSync } from "node:fs";
import { resolveV2 } from "../packages/resolver/v2.mjs";

const [outFile] = process.argv.slice(2);
if (!outFile) { console.error("usage: node bench-unseen.mjs <outJsonl>"); process.exit(1); }

const holdout = JSON.parse(readFileSync("C:/NessGate/benchmarks/holdout-unseen.json", "utf8"));
const done = new Set();
if (existsSync(outFile)) { for (const l of readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean)) { try { done.add(JSON.parse(l).domain); } catch {} } }
else writeFileSync(outFile, "");

function countingFetch(counter) {
  return async (url, init) => { counter.n++; return fetch(url, init); };
}

async function one(entry) {
  const t0 = Date.now();
  const counter = { n: 0 };
  const row = { domain: entry.domain, stratum: entry.stratum, gt: entry.groundTruthProtocols, ms: 0 };
  try {
    const r = await Promise.race([
      resolveV2(entry.domain, { tier: "fast", fetch: countingFetch(counter), timeoutMs: 8000, maxBytes: 1_000_000 }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("hard-timeout")), 60000)),
    ]);
    row.ms = Date.now() - t0;
    row.requests = counter.n;
    const items = r.items || [];
    row.foundProtocols = [...new Set(items.map((i) => i.resource.source))];
    // classification: exact-host items MUST be publisher-hosted / Level 1 / verified
    row.classOk = items.every((i) => i.relationship === "publisher-hosted" && i.level === 1 && i.verification === "verified");
    // provenance: every item must carry a re-derivable sourceUrl on the domain
    row.provOk = items.every((i) => Array.isArray(i.provenance) && i.provenance.some((p) => typeof p.sourceUrl === "string" && p.sourceUrl.startsWith("https://")));
    row.itemCount = items.length;
  } catch (e) {
    row.ms = Date.now() - t0; row.requests = counter.n; row.error = String((e && e.message) || e);
    row.foundProtocols = [];
  }
  // per-domain scoring vs ground truth
  const gt = new Set(entry.groundTruthProtocols);
  const found = new Set(row.foundProtocols || []);
  row.recallHits = [...gt].filter((p) => found.has(p));
  row.missed = [...gt].filter((p) => !found.has(p));
  const fp = [...found].filter((p) => !gt.has(p));
  // Blocked-stratum domains challenge or vary their responses per caller (the
  // freeze notes record gitlab serving llms.txt "once — nondeterministic
  // challenge", and an audit re-run reproduced exactly that). Ground truth
  // there is UNSTABLE, so a finding on a blocked domain is reported separately
  // — it is neither a resolver false positive nor proof the resolver is right.
  if (entry.stratum === "blocked") { row.unstableFindings = fp; row.falsePositives = []; }
  else row.falsePositives = fp;
  appendFileSync(outFile, JSON.stringify(row) + "\n");
  process.stdout.write(`${entry.stratum.padEnd(16)} ${entry.domain}: gt=[${entry.groundTruthProtocols.join(",")}] found=[${(row.foundProtocols||[]).join(",")}] ${row.error ? "ERR:"+row.error : ""} ${Math.round(row.ms/1000)}s\n`);
}

const queue = holdout.domains.filter((d) => !done.has(d.domain));
console.log(`unseen benchmark: ${queue.length} domains (${done.size} done)`);
async function worker() { for (;;) { const e = queue.shift(); if (!e) return; await one(e); } }
await Promise.all([worker(), worker(), worker()]);
console.log("UNSEEN BENCH DONE");
