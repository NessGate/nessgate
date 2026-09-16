// NessGate — REAL external-usage report (Cloudflare zone analytics).
//
// Measures actual external requests to the adoption endpoints (/mcp, /discover,
// /explore, /check) over the last N days, using Cloudflare's GraphQL Analytics
// API. This reads edge request counts Cloudflare already records — it adds NO
// tracking, NO storage, and no change to NessGate's no-store stance.
//
// Honesty notes:
//  - Benchmark traffic does NOT appear here: benchmarks resolve OTHER domains,
//    which never touch the nessgate.com zone.
//  - CI smoke (a handful of requests per deploy) and local dev/testing DO hit
//    these paths from the operator's IP. Pass --exclude-ip=<ip> to remove a
//    known internal source; otherwise it is counted and noted.
//
// Auth: uses CLOUDFLARE_API_TOKEN if set (recommend a token scoped to
// Account/Zone Analytics:Read); otherwise falls back to the local wrangler
// OAuth token. No token is ever written or printed.
//
// Usage:
//   node scripts/usage-analytics.mjs [--days=7] [--zone=<tag>] [--exclude-ip=<ip>] [--json]
import { readFileSync } from "node:fs";
import { join } from "node:path";

const API = "https://api.cloudflare.com/client/v4/graphql";
const DEFAULT_ZONE = "93ba78d35b23082dbb4880dfeed7fd47"; // nessgate.com (public identifier, not a secret)

const args = Object.fromEntries(process.argv.slice(2).map((a) => {
  const m = a.match(/^--([^=]+)(?:=(.*))?$/);
  return m ? [m[1], m[2] === undefined ? true : m[2]] : [a, true];
}));
const DAYS = Math.max(1, Math.min(31, parseInt(args.days, 10) || 7));
const ZONE = args.zone || process.env.NESSGATE_ZONE_TAG || DEFAULT_ZONE;
const EXCLUDE_IP = args["exclude-ip"] || null;
const AS_JSON = !!args.json;

// The endpoints that represent adoption (an external caller depending on NessGate).
const ENDPOINTS = [
  { key: "/mcp", label: "MCP tool server  (/mcp)", filter: { clientRequestPath: "/mcp" } },
  { key: "/discover", label: "Hosted resolve  (/discover/*)", filter: { clientRequestPath_like: "/discover/%" } },
  { key: "/explore", label: "Evidence resolve (/explore/*)", filter: { clientRequestPath_like: "/explore/%" } },
  { key: "/check", label: "Compatibility   (/check*)", filter: { clientRequestPath_like: "/check%" } },
];

function getToken() {
  if (process.env.CLOUDFLARE_API_TOKEN) return { token: process.env.CLOUDFLARE_API_TOKEN.trim(), src: "CLOUDFLARE_API_TOKEN" };
  const candidates = [
    process.env.WRANGLER_CONFIG,
    process.env.APPDATA && join(process.env.APPDATA, "xdg.config/.wrangler/config/default.toml"),
    process.env.XDG_CONFIG_HOME && join(process.env.XDG_CONFIG_HOME, ".wrangler/config/default.toml"),
    process.env.HOME && join(process.env.HOME, ".config/.wrangler/config/default.toml"),
    process.env.HOME && join(process.env.HOME, ".wrangler/config/default.toml"),
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      const m = readFileSync(c, "utf8").match(/^oauth_token\s*=\s*"([^"]+)"/m);
      if (m) return { token: m[1], src: "wrangler oauth token" };
    } catch { /* try next */ }
  }
  return null;
}

async function gql(token, query, variables) {
  const res = await fetch(API, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  const j = await res.json();
  if (j.errors && j.errors.length) throw new Error(j.errors.map((e) => e.message).join("; "));
  return j.data;
}

// One 1-day window per query (the zone dataset caps each query at 1 day).
function dayWindows(n) {
  const out = [];
  const now = new Date();
  const midnightUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  for (let i = 0; i < n; i++) {
    const start = new Date(midnightUTC - i * 86400000);
    const end = new Date(midnightUTC - (i - 1) * 86400000);
    out.push({ since: start.toISOString(), until: end.toISOString() });
  }
  return out.reverse();
}

const QUERY = `query($zone:String!,$since:Time!,$until:Time!,$f:[ZoneHttpRequestsAdaptiveGroupsFilter_InputObject!]){
  viewer{ zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:100, filter:{AND:$f}, orderBy:[count_DESC]){
      count dimensions{ edgeResponseStatus }
    }
  }}
}`;

function statusBucket(code) {
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "redir";
  if (code >= 400 && code < 500) return "clientErr";
  return "serverErr";
}

async function run() {
  const auth = getToken();
  if (!auth) {
    console.error("No Cloudflare token. Set CLOUDFLARE_API_TOKEN (Account+Zone Analytics:Read) or log in with `wrangler login`.");
    process.exit(2);
  }
  const windows = dayWindows(DAYS);
  const totals = {};
  for (const ep of ENDPOINTS) totals[ep.key] = { ok: 0, redir: 0, clientErr: 0, serverErr: 0, total: 0 };

  for (const w of windows) {
    for (const ep of ENDPOINTS) {
      const f = [{ datetime_geq: w.since }, { datetime_leq: w.until }, ep.filter];
      if (EXCLUDE_IP) f.push({ clientIP_neq: EXCLUDE_IP });
      let data;
      try { data = await gql(auth.token, QUERY, { zone: ZONE, since: w.since, until: w.until, f }); }
      catch (e) { console.error(`  ! ${ep.key} ${w.since.slice(0, 10)}: ${e.message}`); continue; }
      const rows = data.viewer.zones?.[0]?.httpRequestsAdaptiveGroups || [];
      for (const r of rows) {
        const b = statusBucket(Number(r.dimensions.edgeResponseStatus));
        totals[ep.key][b] += r.count;
        totals[ep.key].total += r.count;
      }
    }
  }

  if (AS_JSON) {
    console.log(JSON.stringify({ zone: ZONE, days: DAYS, since: windows[0].since, until: windows[windows.length - 1].until, excludeIp: EXCLUDE_IP, endpoints: totals }, null, 2));
    return;
  }

  const grand = Object.values(totals).reduce((a, t) => a + t.total, 0);
  console.log(`\nNessGate external usage — zone ${ZONE} — last ${DAYS} day(s)`);
  console.log(`window: ${windows[0].since.slice(0, 10)} → ${windows[windows.length - 1].until.slice(0, 10)}  (auth: ${auth.src})`);
  console.log(`${EXCLUDE_IP ? `excluding IP ${EXCLUDE_IP}\n` : ""}`);
  console.log("  endpoint                        total     2xx    3xx    4xx    5xx");
  console.log("  " + "-".repeat(70));
  for (const ep of ENDPOINTS) {
    const t = totals[ep.key];
    console.log(`  ${ep.label.padEnd(30)} ${String(t.total).padStart(6)}  ${String(t.ok).padStart(6)} ${String(t.redir).padStart(6)} ${String(t.clientErr).padStart(6)} ${String(t.serverErr).padStart(6)}`);
  }
  console.log("  " + "-".repeat(70));
  console.log(`  ${"ALL ADOPTION ENDPOINTS".padEnd(30)} ${String(grand).padStart(6)}`);
  console.log(`\nnote: benchmark traffic is NOT counted (it targets other domains, never this zone).`);
  console.log(`      CI smoke + local dev hit these paths from the operator IP${EXCLUDE_IP ? " (excluded above)" : "; pass --exclude-ip=<ip> to remove"}.`);
}

run().catch((e) => { console.error("usage-analytics failed:", e.message); process.exit(1); });
