// Stage 1 benchmark: v1 resolve() vs the EXPERIMENTAL v2 balanced tier, on the
// SAME frozen 200-domain cohorts. Library-only; runs the resolver directly in
// Node against the live web (no hosted-service change). Measures what the
// balanced tier adds over v1, and at what cost — no domain hardcoding, no
// optimizing around individual examples.
//
// Hardened like the P2 bench (this machine's connectivity collapses under
// sustained multi-origin load): detached-friendly, resume-by-domain, cool-downs,
// bounded caps, connectivity guard.
//
// Usage: node benchmarks/bench-v2alpha.mjs <outJsonl>
import { readFileSync, appendFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve as resolveV1 } from "../packages/resolver/index.mjs";
import { resolveV2 } from "../packages/resolver/v2.mjs";

const [outFile] = process.argv.slice(2);
if (!outFile) { console.error("usage: node bench-v2alpha.mjs <outJsonl>"); process.exit(1); }

const cohorts = [
  ["A", "C:/NessGate/benchmarks/cohort-a-tranco100.txt"],
  ["B", "C:/NessGate/benchmarks/cohort-b-publicapis100.txt"],
];
const domains = cohorts.flatMap(([c, f]) =>
  readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((d) => [c, d.trim()]));

const alreadyDone = new Set();
if (existsSync(outFile)) {
  for (const line of readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean)) {
    try { alreadyDone.add(JSON.parse(line).domain); } catch {}
  }
} else writeFileSync(outFile, "");

// Bounded caps so one domain can't run away; balanced verifies at most a few hosts.
const OPTS = { timeoutMs: 6000, ctTimeoutMs: 20000, maxBytes: 1_000_000, ctCap: 8, sitemapCap: 8, hostVerifyCap: 5 };
const hostOf = (it) => (it.provenance.find((p) => p.host) || {}).host || "";

async function online() {
  try { const r = await fetch("https://cloudflare-dns.com/dns-query?name=example.com&type=A", { headers: { Accept: "application/dns-json" } }); return r.ok; }
  catch { return false; }
}

let sinceCooldown = 0;
async function one(cohort, d, idx) {
  let redos = 0;
  for (;;) {
    if (++sinceCooldown >= 15) { sinceCooldown = 0; await new Promise((r) => setTimeout(r, 45000)); }
    const row = await attempt(cohort, d);
    const collapsed = !row.error && row.v2 == null;
    if (collapsed || row.error === "hard-timeout") {
      if (!(await online())) {
        process.stdout.write(`OFFLINE at ${d} — cooling down…\n`);
        while (!(await online())) await new Promise((r) => setTimeout(r, 60000));
      }
      if (++redos <= 2) continue;
    }
    appendFileSync(outFile, JSON.stringify(row) + "\n");
    const a = row.v2 || {};
    process.stdout.write(`${idx + 1}/200 ${cohort} ${d}: v1=${row.v1 ? row.v1.resources : "ERR"} L2+${a.level2 ?? "-"} hosts+${a.newHosts ?? "-"} req=${a.requests ?? "-"} ${Math.round(row.ms / 1000)}s\n`);
    return;
  }
}

async function attempt(cohort, d) {
  const t0 = Date.now();
  const row = { cohort, domain: d, ms: 0, v1: null, v2: null };
  try {
    const guard = new Promise((_, rej) => setTimeout(() => rej(new Error("hard-timeout")), 120000));
    const run = (async () => {
      const v1 = await resolveV1(d, OPTS);
      const bal = await resolveV2(d, { ...OPTS, tier: "discovery" });
      row.v1 = { resources: (v1.resources || []).length, positive: (v1.resources || []).length > 0 };
      const bySource = {};
      for (const it of bal.level2) bySource[it.relationship] = (bySource[it.relationship] || 0) + 1;
      const newHosts = new Set(bal.level2.map(hostOf).filter(Boolean));
      row.v2 = {
        level1: bal.stats.level1, level2: bal.stats.level2, total: bal.stats.total,
        verified: bal.stats.verified, newHosts: newHosts.size,
        unreachable: bal.stats.unreachable, reachableEmpty: bal.stats.reachableEmpty,
        checkedHosts: bal.stats.checkedHosts, requests: bal.stats.requests,
        bySource, skipped: bal.stats.skipped,
        // compact audit trail of the Level-2 associations this domain produced
        l2: bal.level2.map((it) => ({ host: hostOf(it), type: it.resource.type, rel: it.relationship, url: it.resource.url })).slice(0, 40),
      };
    })();
    await Promise.race([run, guard]);
    row.ms = Date.now() - t0;
  } catch (e) {
    row.ms = Date.now() - t0;
    row.error = String((e && e.message) || e);
  }
  return row;
}

const queue = domains.map((x, i) => [x[0], x[1], i]).filter((x) => !alreadyDone.has(x[1]));
console.log(`resuming: ${alreadyDone.size} done, ${queue.length} to go`);
async function workerLoop() {
  for (;;) { const x = queue.shift(); if (!x) return; await one(x[0], x[1], x[2]); }
}
await Promise.all([workerLoop(), workerLoop()]);
console.log("BENCH DONE");
