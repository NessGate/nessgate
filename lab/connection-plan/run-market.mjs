// Market-rate estimate: run the readiness pipeline over a LARGE, unbiased sample
// (Tranco popular domains — NOT the groundtruth-positive set) to estimate the real
// fraction of the web an agent can auto-connect to.
//
//   --file=<path>     domain list (default benchmarks/cohort-a-tranco100.txt)
//   --n=<N>           random subsample size (default: all)
//   --source=local|explore   local resolve()+delegate (default, no rate limit)
//                            or hosted /explore (richer recall, 60/hr cap)
//   --seed=<int>      sample seed (default 1)
//
// Writes market-<source>.json. Progress logged as it goes.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "../../packages/resolver/index.mjs";
import { assessReadiness } from "./readiness.mjs";
import { expandByDelegation } from "./delegate.mjs";
import { fetchExplore } from "./explore.mjs";
import { PROFILES } from "./profiles.mjs";

const arg = (k, d) => { const m = process.argv.find((a) => a.startsWith(`--${k}=`)); return m ? m.split("=").slice(1).join("=") : d; };
const file = arg("file", fileURLToPath(new URL("../../benchmarks/cohort-a-tranco100.txt", import.meta.url)));
const source = arg("source", "local");
const seed = parseInt(arg("seed", "1"), 10);

let domains = readFileSync(file, "utf8").split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
// Deterministic shuffle (LCG) so a subsample is reproducible without Date/Math.random reliance.
let x = seed >>> 0 || 1;
const rnd = () => ((x = (1103515245 * x + 12345) & 0x7fffffff) / 0x7fffffff);
for (let i = domains.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [domains[i], domains[j]] = [domains[j], domains[i]]; }
const n = parseInt(arg("n", String(domains.length)), 10);
domains = domains.slice(0, n);

const client = PROFILES.polyglot;
const rows = [];
console.log(`market sweep: ${domains.length} domains via ${source}\n`);

for (let i = 0; i < domains.length; i++) {
  const domain = domains[i];
  const t0 = Date.now();
  try {
    let discovery;
    if (source === "explore") discovery = await fetchExplore(domain, { timeoutMs: 30000 });
    else {
      discovery = await resolve(domain, { verify: true, mcp: true, org: true, timeoutMs: 6000, deadlineMs: 15000 });
      const ex = await expandByDelegation(discovery, { timeoutMs: 6000 }).catch(() => ({ discovery }));
      discovery = ex.discovery || discovery;
    }
    const report = await assessReadiness(discovery, client, { timeoutMs: 6000, maxAssess: 4 });
    const positive = (discovery.resources || []).length > 0;
    rows.push({ domain, outcome: report.outcome, positive, protocol: report.connection ? report.connection.protocol : null, ms: Date.now() - t0 });
    console.log(`  [${i + 1}/${domains.length}] ${domain.padEnd(24)} ${report.outcome}${positive ? "" : " (no surfaces)"}`);
  } catch (e) {
    rows.push({ domain, error: String(e && e.message || e), ms: Date.now() - t0 });
    console.log(`  [${i + 1}/${domains.length}] ${domain.padEnd(24)} ERROR ${e && e.message}`);
  }
}

const ok = rows.filter((r) => !r.error);
const N = ok.length || 1;
const count = (o) => ok.filter((r) => r.outcome === o).length;
const positives = ok.filter((r) => r.positive).length;
const readyCreds = count("ready") + count("credentials-required");
const scorecard = {
  ranAt: new Date().toISOString(), source, file, sampled: domains.length, evaluated: ok.length, errors: rows.length - ok.length,
  publishesSomething_pct: Math.round((positives / N) * 100),
  outcomes: { ready: count("ready"), "credentials-required": count("credentials-required"), incomplete: count("incomplete"), "no-compatible-method": count("no-compatible-method") },
  readyOrCreds_pct_ofAll: Math.round((readyCreds / N) * 100),
  readyOrCreds_pct_ofPublishers: positives ? Math.round((readyCreds / positives) * 100) : 0,
  rows,
};
const outPath = fileURLToPath(new URL(`./market-${source}.json`, import.meta.url));
writeFileSync(outPath, JSON.stringify(scorecard, null, 2));

console.log(`\n================ MARKET SCORECARD (${source}) ================`);
console.log(`Sampled ${scorecard.sampled}  ·  evaluated ${scorecard.evaluated}  ·  errors ${scorecard.errors}`);
console.log(`Publishes ANY machine surface:     ${scorecard.publishesSomething_pct}%`);
console.log(`ready:                ${scorecard.outcomes.ready}`);
console.log(`credentials-required: ${scorecard.outcomes["credentials-required"]}`);
console.log(`incomplete:           ${scorecard.outcomes.incomplete}`);
console.log(`no-compatible-method: ${scorecard.outcomes["no-compatible-method"]}`);
console.log(`\nReady-or-creds (of ALL sampled):        ${scorecard.readyOrCreds_pct_ofAll}%`);
console.log(`Ready-or-creds (of those publishing):   ${scorecard.readyOrCreds_pct_ofPublishers}%`);
console.log(`\nWrote ${outPath}`);
