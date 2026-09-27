// Live test of the connection-plan prototype against REAL services.
//
// Calls the real, unmodified resolver (packages/resolver/index.mjs) — reading
// each domain directly, exactly as the published product does — then runs the
// prototype planner on top and scores the result against the four questions the
// experiment set out to answer:
//
//   Q1  Did we find a usable connection PATH? (any compatible plan)
//   Q2  Did we pick the correct protocol & version? (top plan protocol; version
//       confirmed vs unconfirmed — measured, not assumed)
//   Q3  Would the developer STILL have to read the protocols themselves?
//       (proxy: completeness — "complete" = no; otherwise yes)
//   Q4  Did it add value beyond raw /discover? (a plan/verdict discover doesn't give)
//
// Network required (this is a lab tool, off in CI). Writes a JSON scorecard next
// to this file. Usage: node run-live.mjs [domain ...]   (defaults to a seed set)

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "../../packages/resolver/index.mjs";
import { buildConnectionPlan } from "./plan.mjs";
import { PROFILES } from "./profiles.mjs";

// Real domains verified (by the repo's own groundtruth) to publish something.
const SEED = ["supabase.com", "elevenlabs.io", "vercel.com", "stripe.com", "anthropic.com", "huggingface.co", "mintlify.com", "zapier.com"];
const domains = process.argv.slice(2).length ? process.argv.slice(2) : SEED;

// Test each domain with the broad "polyglot" client (max match surface) so the
// score reflects the SERVICE's declaration quality, not a narrow client.
const client = PROFILES.polyglot;

const rows = [];
for (const domain of domains) {
  let discovery;
  const t0 = Date.now();
  try {
    // verify + mcp on: gives the planner reachability + MCP handshake facts,
    // which is where "complete" plans come from. Bounded, read-only.
    discovery = await resolve(domain, { verify: true, mcp: true, timeoutMs: 8000, deadlineMs: 20000 });
  } catch (e) {
    rows.push({ domain, error: String(e && e.message || e) });
    console.log(`\n■ ${domain}  ERROR: ${e && e.message}`);
    continue;
  }
  const ms = Date.now() - t0;
  const plan = buildConnectionPlan(discovery, client);
  const top = plan.connectionPlans[0] || null;

  const row = {
    domain,
    ms,
    discoverResources: discovery.resources.length,
    outcome: plan.match.outcome,
    compatibleMethods: plan.match.compatibleMethods,
    q1_foundPath: plan.connectionPlans.length > 0,
    q2_topProtocol: top ? top.protocol : null,
    q2_versionConfirmed: top ? top.version != null : null,
    q3_devStillReadsSpecs: top ? top.completeness !== "complete" : null,
    q3_completeness: top ? top.completeness : null,
    q4_valueBeyondDiscover: plan.match.outcome !== "none-found", // a verdict/plan discover doesn't emit
    protocols: [...new Set(plan.connectionPlans.map((p) => p.protocol))],
  };
  rows.push(row);

  console.log(`\n■ ${domain}  (${ms}ms, ${discovery.resources.length} discovered resources)`);
  console.log(`   outcome: ${plan.match.outcome} — ${plan.match.summary}`);
  for (const p of plan.connectionPlans.slice(0, 5)) {
    console.log(`   • ${p.protocol}  v=${p.version ?? "?"}  transport=${p.transport ?? "?"}  auth=${p.auth.detail}${p.auth.methods.length ? "(" + p.auth.methods.map((m) => m.label).join(",") + ")" : ""}  [${p.completeness}]  ← ${p.sourceUrl}`);
  }
  if (plan.notes.length) plan.notes.slice(0, 3).forEach((n) => console.log(`   note: ${n}`));
}

// --- scorecard ------------------------------------------------------------
const ok = rows.filter((r) => !r.error);
const n = ok.length || 1;
const pct = (k) => Math.round((ok.filter(k).length / n) * 100);
const scorecard = {
  ranAt: new Date().toISOString(),
  domainsTested: rows.length,
  errors: rows.filter((r) => r.error).length,
  Q1_found_usable_path_pct: pct((r) => r.q1_foundPath),
  Q2_version_confirmed_of_matched_pct: (() => {
    const matched = ok.filter((r) => r.q1_foundPath);
    return matched.length ? Math.round((matched.filter((r) => r.q2_versionConfirmed).length / matched.length) * 100) : 0;
  })(),
  Q3_complete_no_spec_reading_pct: pct((r) => r.q3_completeness === "complete"),
  Q3_protocol_only_needs_spec_reading_pct: pct((r) => r.q1_foundPath && r.q3_completeness !== "complete"),
  Q4_added_a_verdict_pct: pct((r) => r.q4_valueBeyondDiscover),
  outcomeBreakdown: rows.reduce((a, r) => { const k = r.error ? "error" : r.outcome; a[k] = (a[k] || 0) + 1; return a; }, {}),
  rows,
};

const outPath = fileURLToPath(new URL("./last-run.json", import.meta.url));
writeFileSync(outPath, JSON.stringify(scorecard, null, 2));

console.log("\n================ SCORECARD ================");
console.log(`Domains: ${scorecard.domainsTested}  (errors: ${scorecard.errors})`);
console.log(`Q1  found a usable connection path:            ${scorecard.Q1_found_usable_path_pct}%`);
console.log(`Q2  version confirmed (of those matched):      ${scorecard.Q2_version_confirmed_of_matched_pct}%`);
console.log(`Q3  COMPLETE plan (dev need NOT read specs):    ${scorecard.Q3_complete_no_spec_reading_pct}%`);
console.log(`Q3  protocol-only (dev STILL reads specs):      ${scorecard.Q3_protocol_only_needs_spec_reading_pct}%`);
console.log(`Q4  produced a verdict beyond /discover:        ${scorecard.Q4_added_a_verdict_pct}%`);
console.log(`Outcomes: ${JSON.stringify(scorecard.outcomeBreakdown)}`);
console.log(`\nWrote ${outPath}`);
