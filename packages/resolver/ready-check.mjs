#!/usr/bin/env node
// nessgate-ready — open connection-readiness self-test for YOUR domain.
//
//   npx @nessgate/resolver yourdomain.com          (bin name: nessgate-ready)
//
// Runs the published readiness predicate CLIENT-SIDE, on your machine or CI:
// discovers what the domain publishes (dependency-free, direct fetch — no
// reliance on nessgate.com), assesses every connectable endpoint (OpenAPI
// servers+securitySchemes, A2A cards, the MCP OAuth chain RFC 9728 → RFC 8414),
// and repeats the whole observation N times. The verdict is honest and strict:
//
//   PASS  — at least one endpoint is unanimously `ready` (connect now, no
//           credentials) or `credentials-required` (everything known; you
//           supply your own secret) across ALL observations.  exit 0
//   FAIL  — otherwise: `unstable` (observations disagreed),
//           `broken` (declared but demonstrably fails), `incomplete` (the
//           protocol-defined metadata is not published; missing[] names each
//           field), or nothing connectable at all.               exit 1
//
// Unanimity is the strict small-N mapping of the observation-semantics draft's
// ≥80% majority rule (docs/readiness-observation-semantics.md). This CI profile
// runs observations back-to-back; spaced runs distribute them across a window
// (--spacing). Read-only; no credentials are ever sent; nothing is
// reported anywhere — the check runs and stays on your machine.
//
// Options: --observations=N (default 3) · --spacing=SECONDS (default 0)
//          --timeout=MS (default 8000) · --json · --help

import { resolve, assessReadiness, readinessProtocol } from "./index.mjs";

// Pure: map one endpoint's outcomes across observations to a verdict.
// Any disagreement is "unstable" — a flaky endpoint must not pass CI.
export function majorityVerdict(outcomes) {
  const outs = (outcomes || []).filter(Boolean);
  if (!outs.length) return "unobserved";
  return new Set(outs).size === 1 ? outs[0] : "unstable";
}

const VERDICT_RANK = { ready: 0, "credentials-required": 1, unstable: 2, broken: 3, incomplete: 4 };

export async function readyCheck(domain, opts = {}) {
  const observations = Math.max(1, opts.observations || 3);
  const spacingMs = Math.max(0, opts.spacingMs || 0);
  const fetchImpl = opts.fetch || globalThis.fetch;
  const timeoutMs = opts.timeoutMs || 8000;

  const perEndpoint = new Map(); // url -> outcomes[]
  const detail = new Map(); // url -> last readiness record
  const observationErrors = [];

  for (let i = 0; i < observations; i++) {
    if (i && spacingMs) await new Promise((r) => setTimeout(r, spacingMs));
    let discovery;
    try {
      discovery = await resolve(domain, { fetch: fetchImpl, timeoutMs, deadlineMs: opts.deadlineMs || 20000 });
    } catch (e) {
      observationErrors.push(`observation ${i + 1}: discovery failed (${e && e.message})`);
      continue;
    }
    const seen = new Set();
    for (const r of discovery.resources || []) {
      if (!readinessProtocol(r) || seen.has(r.url)) continue;
      seen.add(r.url);
      let rec;
      try { rec = await assessReadiness(r, { fetch: fetchImpl, timeoutMs }); }
      catch (e) { rec = { protocol: readinessProtocol(r), outcome: "incomplete", missing: [`assessment failed: ${e && e.message}`] }; }
      if (!perEndpoint.has(r.url)) perEndpoint.set(r.url, []);
      perEndpoint.get(r.url).push(rec.outcome);
      detail.set(r.url, rec);
    }
  }

  const endpoints = [];
  for (const [url, outs] of perEndpoint) {
    const verdict = majorityVerdict(outs);
    const rec = detail.get(url) || {};
    endpoints.push({
      url,
      protocol: rec.protocol,
      verdict,
      observations: outs,
      ...(rec.auth ? { auth: rec.auth } : {}),
      ...(rec.missing && rec.missing.length ? { missing: rec.missing } : {}),
    });
  }
  endpoints.sort((a, b) => (VERDICT_RANK[a.verdict] ?? 9) - (VERDICT_RANK[b.verdict] ?? 9) || String(a.url).localeCompare(String(b.url)));

  const best = endpoints[0];
  const pass = !!best && (best.verdict === "ready" || best.verdict === "credentials-required");
  const verdict = best ? best.verdict : "nothing-connectable";

  return {
    domain,
    verdict, // ready | credentials-required | unstable | broken | incomplete | nothing-connectable
    pass,
    observations,
    endpoints,
    ...(observationErrors.length ? { observationErrors } : {}),
    note: pass
      ? "PASS: a connectable path is unanimously usable across all observations. Credentials (if any) stay with the caller."
      : best
        ? "FAIL: no endpoint passed unanimously. Fix what missing[] names (incomplete = publish it, broken = repair it, unstable = investigate flakiness) and re-run."
        : "FAIL: nothing connectable was discovered. Publish a machine-readable surface (e.g. openapi.json with servers+security, an MCP endpoint with OAuth metadata, or an A2A agent card) and re-run.",
  };
}

/* ------------------------------- CLI ------------------------------- */
import { pathToFileURL } from "node:url";
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const args = process.argv.slice(2);
  const flag = (name) => { const a = args.find((x) => x.startsWith(`--${name}=`)); return a ? a.split("=").slice(1).join("=") : null; };
  const domain = args.find((a) => !a.startsWith("--"));
  if (!domain || args.includes("--help")) {
    console.log("usage: nessgate-ready <domain> [--observations=3] [--spacing=SECONDS] [--timeout=8000] [--json]");
    process.exit(domain ? 0 : 2);
  }
  const opts = {
    observations: flag("observations") ? parseInt(flag("observations"), 10) : 3,
    spacingMs: flag("spacing") ? parseInt(flag("spacing"), 10) * 1000 : 0,
    timeoutMs: flag("timeout") ? parseInt(flag("timeout"), 10) : 8000,
  };
  try {
    const result = await readyCheck(domain, opts);
    if (args.includes("--json")) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(`nessgate-ready ${result.domain}  (${result.observations} observation${result.observations > 1 ? "s" : ""})\n`);
      for (const e of result.endpoints) {
        console.log(`  ${e.verdict.padEnd(21)} [${e.protocol}] ${e.url}`);
        if (e.observations.length > 1 && new Set(e.observations).size > 1) console.log(`${"".padEnd(24)}observations: ${e.observations.join(", ")}`);
        if (e.auth && e.auth.required) console.log(`${"".padEnd(24)}auth: ${e.auth.type}${e.auth.tokenEndpoint ? `  token=${e.auth.tokenEndpoint}` : ""}`);
        for (const m of e.missing || []) console.log(`${"".padEnd(24)}MISSING: ${m}`);
      }
      if (!result.endpoints.length) console.log("  (no connectable endpoints discovered)");
      for (const err of result.observationErrors || []) console.log(`  note: ${err}`);
      console.log(`\n${result.pass ? "PASS" : "FAIL"} — ${result.verdict}`);
      console.log(result.note);
    }
    process.exit(result.pass ? 0 : 1);
  } catch (e) {
    console.error(`error: ${e && e.message}`);
    process.exit(2);
  }
}
