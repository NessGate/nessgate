// Live test of the READINESS pipeline against real services.
//
// resolve() (unmodified) → assessReadiness() (fill connection details + safe
// handshake) → one of: ready / credentials-required / incomplete / no-compatible.
// Measures: how many services can NessGate make
// connection-ready-except-credentials, and for the rest, does it name EXACTLY
// what their published metadata is missing?
//
// Network required (lab tool, off in CI). Writes last-run-readiness.json.
// Usage: node run-readiness.mjs [domain ...]

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "../../packages/resolver/index.mjs";
import { assessReadiness } from "./readiness.mjs";
import { expandByDelegation } from "./delegate.mjs";
import { PROFILES } from "./profiles.mjs";

// Seed = the earlier groundtruth-positive set + services likely to expose MCP
// with OAuth (to exercise the RFC 9728 → RFC 8414 chain).
const SEED = ["supabase.com", "elevenlabs.io", "vercel.com", "stripe.com", "anthropic.com", "huggingface.co", "mintlify.com", "zapier.com", "sentry.io", "linear.app", "notion.so", "cloudflare.com"];
const domains = process.argv.slice(2).length ? process.argv.slice(2) : SEED;
const client = PROFILES.polyglot; // broad client → measures the SERVICE's readiness

const rows = [];
for (const domain of domains) {
  const t0 = Date.now();
  let discovery;
  try {
    discovery = await resolve(domain, { verify: true, mcp: true, org: true, timeoutMs: 8000, deadlineMs: 20000 });
  } catch (e) { rows.push({ domain, error: String(e && e.message || e) }); console.log(`\n■ ${domain}  ERROR: ${e && e.message}`); continue; }

  // Bounded, read-only delegation: follow pointer/catalog surfaces one level to
  // the endpoints the publisher declared, then assess those too.
  let delegated = 0;
  try { const ex = await expandByDelegation(discovery, { timeoutMs: 8000 }); discovery = ex.discovery; delegated = ex.delegated; }
  catch {}

  let report;
  try { report = await assessReadiness(discovery, client, { timeoutMs: 8000 }); }
  catch (e) { rows.push({ domain, error: "assess:" + String(e && e.message || e) }); console.log(`\n■ ${domain}  ASSESS ERROR: ${e && e.message}`); continue; }

  const ms = Date.now() - t0;
  const c = report.connection;
  rows.push({
    domain, ms, outcome: report.outcome, delegated,
    protocol: c ? c.protocol : null,
    version: c ? c.version : null,
    transport: c ? c.transport : null,
    authType: c && c.auth ? c.auth.type : null,
    tokenEndpoint: c && c.auth ? c.auth.tokenEndpoint : null,
    missing: report.missing,
    alternatives: report.alternatives.map((a) => `${a.protocol}:${a.outcome}`),
  });

  console.log(`\n■ ${domain}  (${ms}ms)  →  ${report.outcome.toUpperCase()}${delegated ? `  [+${delegated} via delegation]` : ""}`);
  if (c) {
    console.log(`   ${c.protocol}  v=${c.version ?? "?"}  transport=${c.transport ?? "?"}  endpoint=${c.endpoint ?? "?"}`);
    if (c.auth && c.auth.required) {
      console.log(`   auth: ${c.auth.type}${c.auth.tokenEndpoint ? `  token=${c.auth.tokenEndpoint}` : ""}${c.auth.authorizationEndpoint ? `  authorize=${c.auth.authorizationEndpoint}` : ""}`);
      if (c.auth.scopes) console.log(`   scopes: ${c.auth.scopes.join(" ")}`);
      if (c.auth.dynamicClientRegistration) console.log(`   dynamic client registration: yes (${c.auth.registrationEndpoint})`);
    } else if (c.auth) console.log(`   auth: none required`);
    if (c.verified) console.log(`   verified handshake: ${c.verified.handshake}`);
  }
  if (report.missing && report.missing.length) report.missing.forEach((m) => console.log(`   MISSING: ${m}`));
  if (report.alternatives.length) console.log(`   alternatives: ${report.alternatives.map((a) => a.protocol + "→" + a.outcome).join(", ")}`);
}

// --- scorecard ------------------------------------------------------------
const ok = rows.filter((r) => !r.error);
const n = ok.length || 1;
const count = (o) => ok.filter((r) => r.outcome === o).length;
const scorecard = {
  ranAt: new Date().toISOString(),
  domainsTested: rows.length,
  errors: rows.filter((r) => r.error).length,
  outcomes: { ready: count("ready"), "credentials-required": count("credentials-required"), incomplete: count("incomplete"), "no-compatible-method": count("no-compatible-method") },
  connectionReady_pct: Math.round(((count("ready") + count("credentials-required")) / n) * 100),
  namedMissing_of_incomplete: ok.filter((r) => r.outcome === "incomplete" && r.missing && r.missing.length).length,
  incomplete_total: count("incomplete"),
  rows,
};
const outPath = fileURLToPath(new URL("./last-run-readiness.json", import.meta.url));
writeFileSync(outPath, JSON.stringify(scorecard, null, 2));

console.log("\n================ READINESS SCORECARD ================");
console.log(`Domains: ${scorecard.domainsTested}  (errors: ${scorecard.errors})`);
console.log(`  ready:                ${scorecard.outcomes.ready}`);
console.log(`  credentials-required: ${scorecard.outcomes["credentials-required"]}`);
console.log(`  incomplete:           ${scorecard.outcomes.incomplete}`);
console.log(`  no-compatible-method: ${scorecard.outcomes["no-compatible-method"]}`);
console.log(`\nConnection-ready-or-creds (the target): ${scorecard.connectionReady_pct}%`);
console.log(`Incomplete cases that NAME what's missing: ${scorecard.namedMissing_of_incomplete}/${scorecard.incomplete_total}`);
console.log(`\nWrote ${outPath}`);
