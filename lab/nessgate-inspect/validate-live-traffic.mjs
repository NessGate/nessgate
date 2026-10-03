// Live-traffic validation (lab tool, network + zone analytics).
//
// Runs Inspect over nessgate.com's REAL inbound traffic: pulls (userAgent,
// clientIP, request-count) groups from Cloudflare zone analytics for the last N
// days, runs each distinct caller tuple through inspect() with per-call timing,
// and reports (a) the evidence-tier distribution — per distinct caller and
// request-weighted — and (b) the inspection latency, split by whether a network
// check ran. Nothing is changed in production; nothing new is stored.
//
// Measurement boundary (stated so nobody over-reads the result):
//  - Edge analytics expose method/status/path/IP/UA, NOT request headers — so
//    Web Bot Auth signatures are invisible here and the cryptographic tier is
//    unmeasurable from this dataset. Measuring it needs in-path capture.
//  - Network attribution (reverse DNS, published IP ranges) runs from THIS
//    machine's vantage, not the edge.
//  - The dataset is adaptive-sampled; rows are weighted by sampleInterval and
//    the report says when sampling was in effect.
//
// Privacy: raw IPs are used in-memory for the network checks only; the output
// file contains aggregates and truncated user-agent strings, never IPs.
//
// Auth: CLOUDFLARE_API_TOKEN, else the local wrangler OAuth token (same
// mechanism as scripts/usage-analytics.mjs).
//
//   node validate-live-traffic.mjs [--days=7] [--json]

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "../../packages/inspect/inspect.mjs";
import { networkMethodFor } from "../../packages/inspect/netattr.mjs";

const API = "https://api.cloudflare.com/client/v4/graphql";
const ZONE = process.env.NESSGATE_ZONE_TAG || "93ba78d35b23082dbb4880dfeed7fd47"; // nessgate.com (public identifier)
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const m = a.match(/^--([^=]+)(?:=(.*))?$/); return m ? [m[1], m[2] === undefined ? true : m[2]] : [a, true]; }));
const DAYS = Math.max(1, Math.min(31, parseInt(args.days, 10) || 7));
const NET_CHECK_CAP = 400; // bound on tuples given a live network check (disclosed if hit)
const WORKER_EGRESS_IP = "2a06:98c0:3600::103"; // shared Cloudflare-Workers egress; empty-UA rows from it are platform cache ops

function getToken() {
  if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN.trim();
  const candidates = [
    process.env.WRANGLER_CONFIG,
    process.env.APPDATA && join(process.env.APPDATA, "xdg.config/.wrangler/config/default.toml"),
    process.env.XDG_CONFIG_HOME && join(process.env.XDG_CONFIG_HOME, ".wrangler/config/default.toml"),
    process.env.HOME && join(process.env.HOME, ".config/.wrangler/config/default.toml"),
    process.env.HOME && join(process.env.HOME, ".wrangler/config/default.toml"),
  ].filter(Boolean);
  for (const c of candidates) {
    try { const m = readFileSync(c, "utf8").match(/^oauth_token\s*=\s*"([^"]+)"/m); if (m) return m[1]; } catch {}
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function gql(token, query, variables, attempt = 0) {
  const res = await fetch(API, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ query, variables }) });
  const j = await res.json();
  if (j.errors && j.errors.length) {
    const msg = j.errors.map((e) => e.message).join("; ");
    if (/rate limit/i.test(msg) && attempt < 4) { await sleep(2500 * (attempt + 1)); return gql(token, query, variables, attempt + 1); }
    throw new Error(msg);
  }
  return j.data;
}

const QUERY = `query($zone:String!,$since:Time!,$until:Time!){
  viewer{ zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:1000, filter:{AND:[{datetime_geq:$since},{datetime_lt:$until},{clientRequestPath_notlike:"/cache-op/%"}]}, orderBy:[count_DESC]){
      count avg{ sampleInterval } dimensions{ userAgent clientIP }
    }
  }}
}`;

const token = getToken();
if (!token) { console.error("No Cloudflare token (CLOUDFLARE_API_TOKEN or wrangler login)."); process.exit(2); }

// --- pull the window, one query per day, dedupe tuples, sum weights ---
const now = new Date();
const midnightUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
const tuples = new Map(); // "ua\u0000ip" -> { ua, ip, requests }
let sampled = false;
for (let i = DAYS - 1; i >= -1; i--) { // -1 includes today (partial)
  const since = new Date(midnightUTC - i * 86400000).toISOString();
  const until = new Date(midnightUTC - (i - 1) * 86400000).toISOString();
  const data = await gql(token, QUERY, { zone: ZONE, since, until });
  const groups = data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups || [];
  for (const g of groups) {
    const ua = g.dimensions.userAgent || "";
    const ip = g.dimensions.clientIP || "";
    if (!ua && ip === WORKER_EGRESS_IP) continue; // platform cache operations, not callers
    const si = (g.avg && g.avg.sampleInterval) || 1;
    if (si > 1) sampled = true;
    const key = ua + "\u0000" + ip;
    const t = tuples.get(key) || { ua, ip, requests: 0 };
    t.requests += g.count * si;
    tuples.set(key, t);
  }
  await sleep(350);
}
console.log(`window: last ${DAYS} day(s) + today (partial) · distinct (UA, IP) tuples: ${tuples.size}${sampled ? " · adaptive sampling was in effect (counts are weighted estimates)" : ""}`);

// --- run Inspect over each tuple, timed ---
const TIER_ORDER = ["network-verified", "cryptographically-verified", "directory-attributed", "claimed", "unknown"];
const topTierOf = (r) => TIER_ORDER.find((t) => (r.summary[t] || 0) > 0) || "unknown";
const rows = [];
let netChecks = 0, netCapHit = false;
for (const t of tuples.values()) {
  const wired = !!(t.ua && networkMethodFor(t.ua));
  let doNet = wired;
  if (wired && netChecks >= NET_CHECK_CAP) { doNet = false; netCapHit = true; }
  if (doNet) netChecks++;
  const t0 = process.hrtime.bigint();
  let result;
  try {
    result = await inspect(
      { method: "GET", url: "https://nessgate.com/", headers: t.ua ? { "user-agent": t.ua } : {} },
      doNet ? { sourceIp: t.ip } : {}
    );
  } catch { continue; }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const attr = result.facts.find((f) => f.kind === "public-attribution");
  const net = result.facts.find((f) => f.kind === "network-attribution");
  rows.push({
    ua: t.ua.slice(0, 80), requests: Math.round(t.requests), ms: +ms.toFixed(1),
    topTier: topTierOf(result),
    operator: (net && net.tier === "network-verified" && net.operator) || (attr && attr.operator) || null,
    networkChecked: doNet, networkVerified: !!(net && net.tier === "network-verified"),
  });
}

// --- aggregate ---
const byTier = {}; const byTierWeighted = {};
for (const tname of TIER_ORDER) { byTier[tname] = 0; byTierWeighted[tname] = 0; }
for (const r of rows) { byTier[r.topTier]++; byTierWeighted[r.topTier] += r.requests; }
const totalReq = rows.reduce((n, r) => n + r.requests, 0);
const pct = (n, d) => (d ? Math.round((n / d) * 1000) / 10 : 0);

const operators = {};
for (const r of rows) if (r.operator) {
  const o = (operators[r.operator] ||= { tuples: 0, requests: 0, networkVerified: 0, attributedOnly: 0, checkFailed: 0 });
  o.tuples++; o.requests += r.requests;
  if (r.networkVerified) o.networkVerified++;
  else if (r.networkChecked) o.checkFailed++;
  else o.attributedOnly++;
}

const lat = (sel) => {
  const xs = rows.filter(sel).map((r) => r.ms).sort((a, b) => a - b);
  if (!xs.length) return null;
  const q = (p) => xs[Math.min(xs.length - 1, Math.floor(p * xs.length))];
  return { n: xs.length, p50: q(0.5), p95: q(0.95), max: xs[xs.length - 1] };
};

const report = {
  ranAt: new Date().toISOString(), zone: "nessgate.com", days: DAYS, sampled,
  distinctCallers: rows.length, weightedRequests: totalReq,
  tierDistribution: {
    byDistinctCaller: Object.fromEntries(TIER_ORDER.map((t) => [t, { n: byTier[t], pct: pct(byTier[t], rows.length) }])),
    byRequestWeight: Object.fromEntries(TIER_ORDER.map((t) => [t, { n: byTierWeighted[t], pct: pct(byTierWeighted[t], totalReq) }])),
  },
  operators: Object.fromEntries(Object.entries(operators).sort((a, b) => b[1].requests - a[1].requests)),
  latencyMs: { uaOnly: lat((r) => !r.networkChecked), withNetworkCheck: lat((r) => r.networkChecked) },
  networkChecks: { ran: netChecks, cap: NET_CHECK_CAP, capHit: netCapHit },
  boundaries: [
    "edge analytics do not expose request headers: Web Bot Auth signatures are invisible here, so the cryptographically-verified tier cannot be measured from this dataset",
    "network attribution ran from the analysis machine's vantage, not the edge",
    sampled ? "adaptive sampling was in effect; request counts are weighted estimates" : "no sampling in effect",
  ],
  topCallers: rows.sort((a, b) => b.requests - a.requests).slice(0, 25).map((r) => ({ ua: r.ua, requests: r.requests, tier: r.topTier, operator: r.operator, networkVerified: r.networkVerified })),
};

writeFileSync(fileURLToPath(new URL("./last-run-live-traffic.json", import.meta.url)), JSON.stringify(report, null, 2));
console.log(`\n===== LIVE TRAFFIC (${DAYS}d, ${rows.length} distinct callers, ~${totalReq} weighted requests) =====`);
console.log("tier (distinct / request-weighted):");
for (const tname of TIER_ORDER) console.log(`  ${tname.padEnd(27)} ${String(byTier[tname]).padStart(5)} (${pct(byTier[tname], rows.length)}%)   ${String(byTierWeighted[tname]).padStart(8)} (${pct(byTierWeighted[tname], totalReq)}%)`);
console.log("operators:", Object.entries(operators).map(([k, v]) => `${k}: ${v.tuples} callers/${v.requests} req (netVerified ${v.networkVerified}, attributedOnly ${v.attributedOnly}, checkFailed ${v.checkFailed})`).join(" · ") || "(none attributed)");
console.log("latency ms:", JSON.stringify(report.latencyMs));
if (netCapHit) console.log(`note: network-check cap (${NET_CHECK_CAP}) was hit; some wired-operator tuples were inspected without the network check`);
console.log("wrote last-run-live-traffic.json");
