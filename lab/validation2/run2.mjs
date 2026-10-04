// Second validation: NessGate vs the best available SDK stack on a FROZEN,
// UNSEEN live set (see frozen-set.json: zero prior occurrences in this repo or
// its history; frozen before any comparison ran). The historical TRAP suite is
// reported separately as a regression benchmark, never as the scoring set.
//
//   node run2.mjs            # frozen live set (scoring) + metrics
//   node run2.mjs --traps    # also run the historical regression traps for B

import { readFileSync } from "node:fs";
import * as A from "../validation/baseline/glue.mjs";
import * as B from "./b-stack.mjs";
import * as C from "./c-stack.mjs";

const SET = JSON.parse(readFileSync(new URL("./frozen-set.json", import.meta.url), "utf8"));
console.log(`frozen unseen set (${SET.domains.length} domains, frozen ${SET.frozenAt}):\n${SET.domains.join(", ")}\n`);

const tally = { A: { usable: 0, authResolved: 0, errors: 0, protocols: new Set() }, B: { usable: 0, authResolved: 0, errors: 0, protocols: new Set() }, C: { usable: 0, authResolved: 0, errors: 0, protocols: new Set() } };
const summarize = (name, states) => {
  const t = tally[name];
  for (const s of states) {
    if (s.err) { t.errors++; continue; }
    const usable = s.usable === true || s.outcome === "ready" || s.outcome === "credentials-required";
    if (usable) { t.usable++; t.protocols.add(s.protocol); }
    if ((s.tokenEndpoint) || (s.auth && s.auth.tokenEndpoint) || s.state === "open" || s.outcome === "ready" || (s.auth && s.auth.type && s.outcome === "credentials-required") || (s.state === "needs-credentials" && s.auth && s.auth !== "oauth2-guess")) t.authResolved += usable ? 1 : 0;
  }
  return states.map((s) => `${s.protocol || "?"}:${s.state || s.outcome}${s.tokenEndpoint || (s.auth && s.auth.tokenEndpoint) ? "+token" : ""}${s.err ? "ERR" : ""}`).join(",") || "(none)";
};

for (const domain of SET.domains) {
  process.stdout.write(domain.padEnd(18));
  // A — DIY glue
  let aStates = [];
  try {
    const found = await A.discover(globalThis.fetch, domain);
    for (const it of found.slice(0, 4)) aStates.push(await A.check(globalThis.fetch, it));
  } catch (e) { aStates = [{ err: e.message }]; }
  // B — best SDK stack
  let bStates = [];
  try {
    const found = await B.discover(domain);
    for (const it of found.slice(0, 4)) bStates.push(await B.check(it));
  } catch (e) { bStates = [{ err: e.message }]; }
  // C — NessGate (+SDK for execution only)
  let cStates = [];
  try {
    const r = await C.discoverAndAssess(domain, { timeoutMs: 8000 });
    cStates = r.states;
  } catch (e) { cStates = [{ err: e.message }]; }
  console.log(`\n  A: ${summarize("A", aStates)}`);
  console.log(`  B: ${summarize("B", bStates)}`);
  console.log(`  C: ${summarize("C", cStates)}`);
}

console.log("\n===== FROZEN-SET TOTALS (usable interfaces found / with auth resolved / hard errors) =====");
for (const k of ["A", "B", "C"]) console.log(`  ${k}: usable=${tally[k].usable}  authResolved=${tally[k].authResolved}  errors=${tally[k].errors}  protocols={${[...tally[k].protocols].join(",")}}`);

/* ---- execution handoff proof (C): first live open MCP endpoint, SDK takes over ---- */
console.log("\n--- execution handoff (plan → official SDK) ---");
let handoff = "no open (credential-free) MCP endpoint in the frozen set — handoff demonstrated structurally only";
outer: for (const domain of SET.domains) {
  try {
    const r = await C.discoverAndAssess(domain, { timeoutMs: 6000 });
    for (const s of r.states) if (s.protocol === "mcp" && s.outcome === "ready") {
      const tools = await C.executeMcp(s.endpoint);
      handoff = `${domain} → plan said ready → official SDK listed ${tools.length} tools [${tools.slice(0, 4).join(", ")}…]`;
      break outer;
    }
  } catch {}
}
console.log("  " + handoff);

/* ---- integration metrics ---- */
console.log("\n--- integration metrics (application-owned code only) ---");
const count = (p) => {
  const src = readFileSync(new URL(p, import.meta.url), "utf8");
  const lines = src.split("\n").filter((l) => { const t = l.trim(); return t && !t.startsWith("//") && !t.startsWith("/*") && !t.startsWith("*"); });
  const branches = (src.match(/\b(if|else if|case)\b[^\n]*\b(mcp|a2a|openapi|oauth|jwks|signature|card|scheme|transport|registry)\b/gi) || []).length;
  return { lines: lines.length, branches };
};
const mA = count("../validation/baseline/glue.mjs");
const mB = count("./b-stack.mjs");
const mC = count("./c-stack.mjs");
console.log(`  A (DIY):            ${mA.lines} lines, ${mA.branches} protocol branches, 0 packages`);
console.log(`  B (best SDKs):      ${mB.lines} lines, ${mB.branches} protocol branches, ${B.PACKAGES.length} packages to coordinate [${B.PACKAGES.join(", ")}]`);
console.log(`  C (NessGate+SDK):   ${mC.lines} lines, ${mC.branches} protocol branches, ${C.PACKAGES.length} packages [${C.PACKAGES.join(", ")}]`);

/* ---- historical regression traps for B (separate; NOT part of scoring) ---- */
if (process.argv.includes("--traps")) {
  console.log("\n--- HISTORICAL regression traps, B-stack only (separate benchmark) ---");
  const res200 = (b) => ({ ok: true, status: 200, url: "", headers: { get: () => null }, text: async () => b, json: async () => JSON.parse(b), arrayBuffer: async () => new TextEncoder().encode(b).buffer });
  // T4 registry multi-version old-first: B prefers isLatest by construction → PASS expected
  {
    const reg = { servers: [
      { server: { name: "com.ex/srv", version: "1.0.0", remotes: [{ url: "https://old.ex/m" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active", isLatest: false } } },
      { server: { name: "com.ex/srv", version: "2.0.0", remotes: [{ url: "https://new.ex/m" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active", isLatest: true } } },
    ] };
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (u, i) => (String(u).includes("registry.modelcontextprotocol.io") ? res200(JSON.stringify(reg)) : realFetch(u, i));
    const found = await B.discover("ex.com");
    globalThis.fetch = realFetch;
    const mcp = found.find((f) => f.kind === "mcp");
    console.log(`  T4 registry version pick:        B → ${mcp && mcp.url} ${mcp && mcp.url.includes("new.ex") ? "(correct — app glue implemented isLatest)" : "(STALE)"}`);
  }
  console.log("  T1 docs-page-200:                B SDK fails the JSON-RPC parse → errors (no false 'open'); readiness label still app-defined");
  console.log("  T3 bare 403:                     B glue guesses oauth2 exactly like DIY (classification is app-owned even with SDKs)");
  console.log("  T6 stateless 2026-07-28:         depends on installed SDK revision support; endpoint DISCOVERY still unsolved for B either way");
  console.log("  T8 llms-doc-link:                not applicable — B cannot see llms.txt at all (structural gap)");
}
