// Live readiness run sourced from the HOSTED /explore (deeper delegation +
// MCP-Registry federation) instead of the local resolve()+delegate path.
//
// Measures whether /explore's richer recall moves more services to
// ready / credentials-required. Same 12 domains, same polyglot client, so the
// scorecard is directly comparable to run-readiness.mjs (local path).
//
// DEPENDENCY NOTE: uses https://nessgate.com/explore as a data source (see
// explore.mjs). Writes last-run-explore.json. Usage: node run-readiness-explore.mjs [domain ...]

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assessReadiness } from "./readiness.mjs";
import { fetchExplore } from "./explore.mjs";
import { PROFILES } from "./profiles.mjs";

const SEED = ["supabase.com", "elevenlabs.io", "vercel.com", "stripe.com", "anthropic.com", "huggingface.co", "mintlify.com", "zapier.com", "sentry.io", "linear.app", "notion.so", "cloudflare.com"];
const domains = process.argv.slice(2).length ? process.argv.slice(2) : SEED;
const client = PROFILES.polyglot;

const rows = [];
for (const domain of domains) {
  const t0 = Date.now();
  let discovery;
  try { discovery = await fetchExplore(domain, { timeoutMs: 30000 }); }
  catch (e) { rows.push({ domain, error: String(e && e.message || e) }); console.log(`\n■ ${domain}  EXPLORE ERROR: ${e && e.message}`); continue; }

  let report;
  try { report = await assessReadiness(discovery, client, { timeoutMs: 8000, maxAssess: 6 }); }
  catch (e) { rows.push({ domain, error: "assess:" + String(e && e.message || e) }); console.log(`\n■ ${domain}  ASSESS ERROR: ${e && e.message}`); continue; }

  const ms = Date.now() - t0;
  const c = report.connection;
  rows.push({
    domain, ms, outcome: report.outcome,
    resources: discovery.resources.length,
    protocol: c ? c.protocol : null, version: c ? c.version : null, transport: c ? c.transport : null,
    authType: c && c.auth ? c.auth.type : null, tokenEndpoint: c && c.auth ? c.auth.tokenEndpoint : null,
    missing: report.missing, alternatives: report.alternatives.map((a) => `${a.protocol}:${a.outcome}`),
  });

  console.log(`\n■ ${domain}  (${ms}ms, ${discovery.resources.length} resources)  →  ${report.outcome.toUpperCase()}`);
  if (c) {
    console.log(`   ${c.protocol}  v=${c.version ?? "?"}  transport=${c.transport ?? "?"}  endpoint=${c.endpoint ?? "?"}`);
    if (c.auth && c.auth.required) {
      console.log(`   auth: ${c.auth.type}${c.auth.tokenEndpoint ? `  token=${c.auth.tokenEndpoint}` : ""}${c.auth.authorizationEndpoint ? `  authorize=${c.auth.authorizationEndpoint}` : ""}`);
      if (c.auth.scopes) console.log(`   scopes: ${c.auth.scopes.join(" ")}`);
      if (c.auth.dynamicClientRegistration) console.log(`   dynamic client registration: yes`);
    } else if (c.auth) console.log(`   auth: none required`);
    if (c.verified) console.log(`   verified handshake: ${c.verified.handshake}`);
  }
  if (report.missing && report.missing.length) report.missing.forEach((m) => console.log(`   MISSING: ${m}`));
  if (report.alternatives.length) console.log(`   alternatives: ${report.alternatives.map((a) => a.protocol + "→" + a.outcome).join(", ")}`);
}

const ok = rows.filter((r) => !r.error);
const n = ok.length || 1;
const count = (o) => ok.filter((r) => r.outcome === o).length;
const scorecard = {
  ranAt: new Date().toISOString(), source: "hosted /explore?org=1&related=1",
  domainsTested: rows.length, errors: rows.filter((r) => r.error).length,
  outcomes: { ready: count("ready"), "credentials-required": count("credentials-required"), incomplete: count("incomplete"), "no-compatible-method": count("no-compatible-method") },
  connectionReady_pct: Math.round(((count("ready") + count("credentials-required")) / n) * 100),
  namedMissing_of_incomplete: ok.filter((r) => r.outcome === "incomplete" && r.missing && r.missing.length).length,
  incomplete_total: count("incomplete"), rows,
};
const outPath = fileURLToPath(new URL("./last-run-explore.json", import.meta.url));
writeFileSync(outPath, JSON.stringify(scorecard, null, 2));

console.log("\n============ READINESS SCORECARD (via /explore) ============");
console.log(`Domains: ${scorecard.domainsTested}  (errors: ${scorecard.errors})`);
console.log(`  ready:                ${scorecard.outcomes.ready}`);
console.log(`  credentials-required: ${scorecard.outcomes["credentials-required"]}`);
console.log(`  incomplete:           ${scorecard.outcomes.incomplete}`);
console.log(`  no-compatible-method: ${scorecard.outcomes["no-compatible-method"]}`);
console.log(`\nConnection-ready-or-creds: ${scorecard.connectionReady_pct}%   (local path was 17%)`);
console.log(`Incomplete cases that NAME what's missing: ${scorecard.namedMissing_of_incomplete}/${scorecard.incomplete_total}`);
console.log(`\nWrote ${outPath}`);
