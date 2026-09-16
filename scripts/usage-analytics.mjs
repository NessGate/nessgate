// NessGate — REAL external-usage report (Cloudflare zone analytics).
//
// Measures actual external requests to the adoption endpoints (/mcp, /discover,
// /explore, /check) over the last N days, using Cloudflare's GraphQL Analytics
// API. This reads edge request counts Cloudflare already records — it adds NO
// tracking, NO storage, and no change to NessGate's no-store stance.
//
// Measurement honesty (the numbers this script prints are the numbers we may
// publicly repeat, so they must not flatter):
//  - Cloudflare's adaptive dataset is SAMPLED. Every row is weighted by its
//    sampleInterval; totals are estimates, and the report says so whenever any
//    sampling was in effect.
//  - Traffic is SEGMENTED by user agent: registry liveness bots and monitors
//    (the bulk of /mcp traffic) are separated from possible real clients.
//    Requests are not users, and monitored uptime is not adoption.
//  - The window ends "now": the newest day is PARTIAL and labeled as such.
//  - Benchmark traffic never appears here (it resolves OTHER domains, which
//    never touch this zone). CI smoke + local dev DO hit these paths from the
//    operator's IP — pass --exclude-ip=<ip> to remove a known internal source.
//
// Auth: CLOUDFLARE_API_TOKEN if set (recommend Account+Zone Analytics:Read),
// else the local wrangler OAuth token. No token is ever written or printed.
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

// UA classes. "monitor" = self-declared bots, health checkers, crawlers and
// research probes (they ping every server in the MCP Registry — uptime, not
// adoption). "unidentified" = empty UA (scanners, curl-alikes). Everything else
// counts as a POSSIBLE client — an upper bound on real usage, not proof of it.
const MONITOR_RE = /bot|crawl|spider|probe|monitor|liveness|audit|research|collector|watch|beat|sentinel|registry|scan|health|uptime|pingdom|checker/i;
function uaClass(ua) {
  if (!ua || !ua.trim()) return "unidentified";
  return MONITOR_RE.test(ua) ? "monitor" : "client";
}

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
    httpRequestsAdaptiveGroups(limit:500, filter:{AND:$f}, orderBy:[count_DESC]){
      count avg{ sampleInterval } dimensions{ edgeResponseStatus userAgent }
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
  let sampled = false;
  for (const ep of ENDPOINTS) {
    totals[ep.key] = {
      ok: 0, redir: 0, clientErr: 0, serverErr: 0, total: 0,
      segments: { monitor: 0, unidentified: 0, client: 0 },
    };
  }

  for (const w of windows) {
    for (const ep of ENDPOINTS) {
      const f = [{ datetime_geq: w.since }, { datetime_leq: w.until }, ep.filter];
      if (EXCLUDE_IP) f.push({ clientIP_neq: EXCLUDE_IP });
      let data;
      try { data = await gql(auth.token, QUERY, { zone: ZONE, since: w.since, until: w.until, f }); }
      catch (e) { console.error(`  ! ${ep.key} ${w.since.slice(0, 10)}: ${e.message}`); continue; }
      const rows = data.viewer.zones?.[0]?.httpRequestsAdaptiveGroups || [];
      for (const r of rows) {
        // Adaptive sampling: each stored row represents ~sampleInterval real
        // requests. Weight, or high-traffic windows silently undercount.
        const si = (r.avg && r.avg.sampleInterval) || 1;
        if (si > 1.001) sampled = true;
        const n = Math.round(r.count * si);
        const t = totals[ep.key];
        t[statusBucket(Number(r.dimensions.edgeResponseStatus))] += n;
        t.total += n;
        t.segments[uaClass(r.dimensions.userAgent)] += n;
      }
    }
  }

  const meta = {
    zone: ZONE, days: DAYS,
    since: windows[0].since, until: windows[windows.length - 1].until,
    lastDayPartial: true, sampled, excludeIp: EXCLUDE_IP,
  };
  if (AS_JSON) {
    console.log(JSON.stringify({ ...meta, endpoints: totals }, null, 2));
    return;
  }

  const grand = Object.values(totals).reduce((a, t) => a + t.total, 0);
  console.log(`\nNessGate external usage — zone ${ZONE} — last ${DAYS} day(s), newest day PARTIAL`);
  console.log(`window: ${meta.since.slice(0, 10)} → ${meta.until.slice(0, 10)}  (auth: ${auth.src})`);
  console.log(`counts are ${sampled ? "ESTIMATES (Cloudflare adaptive sampling was in effect; rows weighted by sampleInterval)" : "unsampled (sampleInterval 1 throughout)"}`);
  console.log(`${EXCLUDE_IP ? `excluding IP ${EXCLUDE_IP}` : "operator IP NOT excluded (pass --exclude-ip=<ip>)"}\n`);
  console.log("  endpoint                        total     2xx    3xx    4xx    5xx | monitors  no-UA  possible-clients");
  console.log("  " + "-".repeat(104));
  for (const ep of ENDPOINTS) {
    const t = totals[ep.key];
    console.log(
      `  ${ep.label.padEnd(30)} ${String(t.total).padStart(6)}  ${String(t.ok).padStart(6)} ${String(t.redir).padStart(6)} ${String(t.clientErr).padStart(6)} ${String(t.serverErr).padStart(6)} | ${String(t.segments.monitor).padStart(8)} ${String(t.segments.unidentified).padStart(6)} ${String(t.segments.client).padStart(9)}`
    );
  }
  console.log("  " + "-".repeat(104));
  console.log(`  ${"ALL ADOPTION ENDPOINTS".padEnd(30)} ${String(grand).padStart(6)}`);
  console.log(`\n"possible-clients" is an UPPER BOUND on real usage (any non-bot-labeled UA), not proof of adoption.`);
  console.log(`Adoption is measured in integration events (a listing merged, a named dependent, a self-hosted deploy),`);
  console.log(`never in request counts. Benchmark traffic targets other domains and never appears here.`);
}

run().catch((e) => { console.error("usage-analytics failed:", e.message); process.exit(1); });
