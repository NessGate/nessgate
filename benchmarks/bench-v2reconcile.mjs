// Reconciled apples-to-apples benchmark (per review).
//   A = current v1.6 FULL strict+explore  (the REAL /explore, org+related, run
//       against a LOCAL worker of unchanged production code).
//   B = the same exact capabilities + CT + sitemap under the v2 two-axis model
//       (A's explore output, two-axis-mapped, composed with the library's
//       CT/sitemap discovery adapters).
// Measures the TRUE incremental of CT+sitemap OVER the full existing capability
// — not over exact-host-only (the flaw in the first Stage-1 bench).
//
// One run per domain produces both A and B, so they share the same execution.
// Hardened/paced like prior benches. No domain hardcoding.
//
// Usage: node benchmarks/bench-v2reconcile.mjs <exploreBase> <outJsonl>
import { readFileSync, appendFileSync, writeFileSync, existsSync } from "node:fs";
import { resolveV2 } from "../packages/resolver/v2.mjs";

const [exploreBase, outFile] = process.argv.slice(2);
if (!exploreBase || !outFile) { console.error("usage: node bench-v2reconcile.mjs <exploreBase> <outJsonl>"); process.exit(1); }

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

const OPTS = { timeoutMs: 6000, ctTimeoutMs: 20000, maxBytes: 1_000_000, ctCap: 8, sitemapCap: 8, hostVerifyCap: 5 };
const norm = (h) => String(h || "").toLowerCase().replace(/^www\./, "").replace(/\.+$/, "");
const hostOf = (it) => norm((it.provenance.find((p) => p.host) || {}).host);

function exploreHostsOf(j) {
  const hosts = new Set();
  for (const r of j.resources || []) { try { hosts.add(norm(new URL(r.url).hostname)); } catch {} }
  for (const rel of j.related || []) { if (rel.host) hosts.add(norm(rel.host)); }
  return hosts;
}

async function online() {
  try { const r = await fetch("https://cloudflare-dns.com/dns-query?name=example.com&type=A", { headers: { Accept: "application/dns-json" } }); return r.ok; }
  catch { return false; }
}

let sinceCooldown = 0;
async function one(cohort, d, idx) {
  let redos = 0;
  for (;;) {
    if (++sinceCooldown >= 15) { sinceCooldown = 0; await new Promise((r) => setTimeout(r, 45000)); }
    const row = await attempt(cohort, d, idx);
    const exploreDown = !!row.exploreError && (!row.explore || !row.explore.ok);   // local worker unreachable
    const collapsed = !row.error && row.explore == null && row.discovery == null;
    if (collapsed || row.error === "hard-timeout" || exploreDown) {
      if (!(await online())) { process.stdout.write(`OFFLINE at ${d} — cooling down…\n`); while (!(await online())) await new Promise((r) => setTimeout(r, 60000)); }
      if (exploreDown) { process.stdout.write(`explore worker unreachable at ${d} — waiting 20s…\n`); await new Promise((r) => setTimeout(r, 20000)); }
      if (++redos <= 3) continue;
    }
    appendFileSync(outFile, JSON.stringify(row) + "\n");
    const e = row.explore || {}, v = row.discovery || {};
    process.stdout.write(`${idx + 1}/200 ${cohort} ${d}: A=${e.positive ? "Y" : "n"} exploreHosts=${e.hostCount ?? "-"} disc.L2=${v.l2Count ?? "-"} incr=${v.incrementalHosts ? v.incrementalHosts.length : "-"} ${Math.round(row.ms / 1000)}s\n`);
    return;
  }
}

async function attempt(cohort, d, idx) {
  const t0 = Date.now();
  const row = { cohort, domain: d, ms: 0, explore: null, discovery: null };
  const ipHeader = { "CF-Connecting-IP": `10.${Math.floor(idx / 200) + 1}.${(idx % 200) + 1}.7` };
  try {
    const guard = new Promise((_, rej) => setTimeout(() => rej(new Error("hard-timeout")), 150000));
    const run = (async () => {
      // A: real /explore (org + related) from the local unchanged worker
      let ex = null;
      try {
        const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 35000);
        const res = await fetch(`${exploreBase}/explore/${encodeURIComponent(d)}?org=1&related=1`, { headers: { Accept: "application/json", ...ipHeader }, signal: ctrl.signal });
        clearTimeout(t);
        if (res.ok) ex = await res.json();
      } catch (e) { row.exploreError = String((e && e.message) || e); }
      const exHosts = ex ? exploreHostsOf(ex) : new Set();
      const nRes = ex ? (ex.resources || []).length : 0;
      const nRel = ex ? (ex.related || []).length : 0;
      row.explore = {
        ok: !!ex, positive: nRes > 0 || nRel > 0,
        nResources: nRes, nRelated: nRel, hostCount: exHosts.size, hosts: [...exHosts].slice(0, 40),
        classes: ex ? tallyClasses(ex) : {},
        requests: ex && ex.stats ? ex.stats.requests : null, truncated: ex && ex.stats ? !!ex.stats.truncated : null,
      };

      // B (additive): library CT + sitemap discovery, then dedupe against explore
      const disc = await resolveV2(d, { ...OPTS, tier: "discovery" });
      const l2 = disc.level2.map((it) => ({ host: hostOf(it), rel: it.relationship, type: it.resource.type, url: it.resource.url }));
      const l2Hosts = new Set(l2.map((x) => x.host).filter(Boolean));
      const incrementalHosts = [...l2Hosts].filter((h) => !exHosts.has(h));
      const bySource = {};
      for (const it of l2) bySource[it.rel] = (bySource[it.rel] || 0) + 1;
      row.discovery = {
        l2Count: l2.length, hostCount: l2Hosts.size, bySource,
        incrementalHosts,                                  // hosts CT/sitemap found that explore did NOT
        incrementalItems: l2.filter((x) => incrementalHosts.includes(x.host)),
        requests: disc.stats.requests, unreachable: disc.stats.unreachable, reachableEmpty: disc.stats.reachableEmpty,
        ctSkipped: (disc.stats.skipped || []).some((s) => s.startsWith("ct(")),
        sitemapSkipped: (disc.stats.skipped || []).some((s) => s.startsWith("sitemap(")),
        skipped: disc.stats.skipped, ms: disc.stats.ms,
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

function tallyClasses(ex) {
  const t = {};
  for (const r of ex.resources || []) { const c = r.evidence || "unknown"; t[c] = (t[c] || 0) + 1; }
  for (const rel of ex.related || []) { const c = rel.class || "related"; t[c] = (t[c] || 0) + 1; }
  return t;
}

const queue = domains.map((x, i) => [x[0], x[1], i]).filter((x) => !alreadyDone.has(x[1]));
console.log(`resuming: ${alreadyDone.size} done, ${queue.length} to go`);
async function workerLoop() { for (;;) { const x = queue.shift(); if (!x) return; await one(x[0], x[1], x[2]); } }
await Promise.all([workerLoop(), workerLoop()]);
console.log("BENCH DONE");
