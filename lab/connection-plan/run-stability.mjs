// Verdict-STABILITY experiment (lab-only).
//
// The certification question ("NessGate Ready") stands or falls on one property:
// is the readiness VERDICT stable — across repeated runs, and across vantages?
// Determinism of the RULES is already CI-proven (same evidence → same verdict);
// this measures determinism of the OBSERVATIONS (same network → same evidence?).
//
// Design:
//  - Discovery comes from the hosted /explore (10-min edge cache), so N
//    back-to-back runs see IDENTICAL discovery. Any run-to-run variance is
//    therefore the ASSESSMENT layer (MCP handshakes, OAuth metadata chains,
//    spec fetches) — exactly the layer a certification predicate depends on.
//  - N local runs per domain (assessment fresh every time), then ONE production
//    POST /connect per domain: a different vantage (Cloudflare edge) running the
//    same rules — measures vantage variance on the final outcome.
//  - Incomplete verdicts are classified "broken-style" (something was DECLARED
//    but fails: 404s, failed handshakes, denials) vs "under-published" (the
//    protocol-defined metadata simply is not there) — evidence for whether a
//    distinct "broken" outcome is worth adding.
//
// Read-only, bounded, no credentials. Writes last-run-stability.json (gitignored).
// Usage: node run-stability.mjs [runs] [domain ...]

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { fetchExplore } from "./explore.mjs";
import { assessReadiness } from "./readiness.mjs";
import { PROFILES } from "./profiles.mjs";

const RUNS = /^\d+$/.test(process.argv[2] || "") ? parseInt(process.argv[2], 10) : 3;
const extra = process.argv.slice(/^\d+$/.test(process.argv[2] || "") ? 3 : 2);
const SEED = ["supabase.com", "elevenlabs.io", "vercel.com", "stripe.com", "anthropic.com", "huggingface.co", "mintlify.com", "zapier.com", "sentry.io", "linear.app", "notion.so", "cloudflare.com"];
const domains = extra.length ? extra : SEED;
const client = PROFILES.polyglot;

const BROKEN_RE = /reachable|handshake|denied|403|unreachable|parseable/i; // declared, but fails
const fp = (r) => {
  const c = r.connection || {};
  const a = c.auth || {};
  return {
    outcome: r.outcome,
    protocol: c.protocol || null,
    endpoint: c.endpoint || null,
    transport: c.transport || null,
    authType: a.type || null,
    tokenEndpoint: a.tokenEndpoint || null,
    verified: c.verified ? (c.verified.handshake || c.verified) : null,
    missing0: (r.missing && r.missing[0]) || null,
  };
};

const results = {};
for (let run = 1; run <= RUNS; run++) {
  console.log(`\n===== local run ${run}/${RUNS} =====`);
  for (const domain of domains) {
    try {
      const discovery = await fetchExplore(domain, { timeoutMs: 30000 });
      const report = await assessReadiness(discovery, client, { timeoutMs: 8000, maxAssess: 6 });
      (results[domain] ||= []).push(fp(report));
      console.log(`  ${domain.padEnd(20)} ${report.outcome}`);
    } catch (e) {
      (results[domain] ||= []).push({ outcome: "run-error", error: String(e && e.message || e) });
      console.log(`  ${domain.padEnd(20)} RUN-ERROR ${e && e.message}`);
    }
  }
}

// Production vantage: one /connect per domain, same broad client shape.
console.log(`\n===== production vantage (/connect) =====`);
const prod = {};
for (const domain of domains) {
  try {
    const res = await fetch(`https://nessgate.com/connect/${domain}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client: { supports: [{ protocol: "mcp" }, { protocol: "openapi" }, { protocol: "a2a" }] } }),
    });
    const j = await res.json();
    prod[domain] = { outcome: j.outcome, endpoint: (j.connection || {}).endpoint || null };
    console.log(`  ${domain.padEnd(20)} ${j.outcome}`);
  } catch (e) {
    prod[domain] = { outcome: "run-error", error: String(e && e.message || e) };
    console.log(`  ${domain.padEnd(20)} RUN-ERROR`);
  }
}

/* --------------------------------- analysis -------------------------------- */
const rows = [];
for (const domain of domains) {
  const runs = results[domain] || [];
  const outcomes = [...new Set(runs.map((r) => r.outcome))];
  const endpoints = [...new Set(runs.map((r) => r.endpoint))];
  const auths = [...new Set(runs.map((r) => (r.authType || "") + "|" + (r.tokenEndpoint || "")))];
  const stable = outcomes.length === 1;
  const inc = runs.filter((r) => r.outcome === "incomplete");
  const brokenStyle = inc.length && inc.every((r) => r.missing0 && BROKEN_RE.test(r.missing0));
  rows.push({
    domain,
    outcomes,
    outcomeStable: stable,
    endpointStable: endpoints.length === 1,
    authStable: auths.length === 1,
    prodOutcome: (prod[domain] || {}).outcome || null,
    prodAgreesWithMajority: (() => {
      const counts = {}; for (const r of runs) counts[r.outcome] = (counts[r.outcome] || 0) + 1;
      const majority = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
      return (prod[domain] || {}).outcome === majority;
    })(),
    incompleteClass: inc.length ? (brokenStyle ? "broken-style" : "under-published") : null,
    flipDetail: stable ? null : runs.map((r, i) => `run${i + 1}:${r.outcome}(${r.verified || r.missing0 || ""})`),
  });
}

const n = rows.length;
const scorecard = {
  ranAt: new Date().toISOString(), runs: RUNS, domains: n,
  outcomeStable_pct: Math.round((rows.filter((r) => r.outcomeStable).length / n) * 100),
  endpointStable_pct: Math.round((rows.filter((r) => r.endpointStable).length / n) * 100),
  authStable_pct: Math.round((rows.filter((r) => r.authStable).length / n) * 100),
  prodAgrees_pct: Math.round((rows.filter((r) => r.prodAgreesWithMajority).length / n) * 100),
  incompletes: { brokenStyle: rows.filter((r) => r.incompleteClass === "broken-style").length, underPublished: rows.filter((r) => r.incompleteClass === "under-published").length },
  unstable: rows.filter((r) => !r.outcomeStable).map((r) => ({ domain: r.domain, flips: r.flipDetail })),
  prodDisagreements: rows.filter((r) => !r.prodAgreesWithMajority).map((r) => ({ domain: r.domain, local: r.outcomes, prod: r.prodOutcome })),
  rows,
};

writeFileSync(fileURLToPath(new URL("./last-run-stability.json", import.meta.url)), JSON.stringify(scorecard, null, 2));

console.log("\n================ STABILITY SCORECARD ================");
console.log(`${RUNS} local runs × ${n} domains (discovery cache-stable; assessment fresh each run)`);
console.log(`  outcome stable across runs:   ${scorecard.outcomeStable_pct}%`);
console.log(`  endpoint stable:              ${scorecard.endpointStable_pct}%`);
console.log(`  auth metadata stable:         ${scorecard.authStable_pct}%`);
console.log(`  prod vantage agrees:          ${scorecard.prodAgrees_pct}%`);
console.log(`  incompletes: broken-style=${scorecard.incompletes.brokenStyle}  under-published=${scorecard.incompletes.underPublished}`);
if (scorecard.unstable.length) { console.log(`  UNSTABLE:`); for (const u of scorecard.unstable) console.log(`    ${u.domain}: ${u.flips.join("  ")}`); }
if (scorecard.prodDisagreements.length) { console.log(`  PROD DISAGREES:`); for (const d of scorecard.prodDisagreements) console.log(`    ${d.domain}: local=${d.local.join("/")} prod=${d.prod}`); }
console.log(`\nWrote last-run-stability.json`);
