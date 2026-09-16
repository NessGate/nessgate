// NessGate — external-usage / adoption report (Cloudflare zone analytics).
//
// NessGate is infrastructure FOR AI agents, so automated traffic is the point,
// not noise. This report does NOT ask "human or bot" — it asks what each
// automated caller REPRESENTS, using the functional taxonomy:
//
//   first-party   — the operator's own systems (e.g. NessReady). Meaningful
//                   adoption, but NOT independent. Identified by caller IP
//                   prefix, declared out-of-band (never hardcoded — this repo
//                   is public): --first-party=<prefix,prefix> or env
//                   NESSGATE_FIRST_PARTY (comma-separated IP prefixes).
//   monitoring    — self-declared registry/health/security probes (they ping
//                   every MCP server; ecosystem presence, not dependency).
//   independent   — everything else: candidate genuine external agent usage.
//                   This is the number that matters for real adoption.
//   unidentified  — empty user agent (scanners / bare clients).
//
// Metrics reported per the strategic goal: successful calls (edge 2xx),
// DISTINCT independent callers, and REPEAT independent callers (seen on >=2
// days) — repeat use by external systems is the strongest adoption signal the
// edge can see.
//
// MEASUREMENT BOUNDARY (stated so nobody over-reads this): edge analytics see
// method + status + path + IP + country, NOT the JSON-RPC method or which
// domains were resolved or whether provenance was returned (those are in the
// encrypted body). So "successful call" = edge 2xx = an UPPER BOUND on
// "successful resource discovery". Measuring discovery/provenance success
// needs app-level counters, which is a separate decision against the no-store
// stance — deliberately not done here.
//
// Sampling: Cloudflare's dataset is adaptive-sampled; every row is weighted by
// sampleInterval and the report says so when sampling was in effect. The newest
// day is PARTIAL. Benchmark traffic never appears (it targets other domains).
//
// Auth: CLOUDFLARE_API_TOKEN if set, else the local wrangler OAuth token. No
// token is ever written or printed.
//
//   node scripts/usage-analytics.mjs [--days=7] [--first-party=197.200.,197.204.] [--top=8] [--json]
import { readFileSync } from "node:fs";
import { join } from "node:path";

const API = "https://api.cloudflare.com/client/v4/graphql";
const DEFAULT_ZONE = "93ba78d35b23082dbb4880dfeed7fd47"; // nessgate.com (public identifier)

const args = Object.fromEntries(process.argv.slice(2).map((a) => {
  const m = a.match(/^--([^=]+)(?:=(.*))?$/);
  return m ? [m[1], m[2] === undefined ? true : m[2]] : [a, true];
}));
const DAYS = Math.max(1, Math.min(31, parseInt(args.days, 10) || 7));
const ZONE = args.zone || process.env.NESSGATE_ZONE_TAG || DEFAULT_ZONE;
const TOP = Math.max(0, parseInt(args.top, 10) || 8);
const AS_JSON = !!args.json;
const FIRST_PARTY = String(args["first-party"] || process.env.NESSGATE_FIRST_PARTY || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

const ENDPOINTS = [
  { key: "/mcp", label: "MCP tool server  (/mcp)", filter: { clientRequestPath: "/mcp" } },
  { key: "/discover", label: "Hosted resolve  (/discover/*)", filter: { clientRequestPath_like: "/discover/%" } },
  { key: "/explore", label: "Evidence resolve (/explore/*)", filter: { clientRequestPath_like: "/explore/%" } },
  { key: "/check", label: "Compatibility   (/check*)", filter: { clientRequestPath_like: "/check%" } },
];

const MONITOR_RE = /bot|crawl|spider|probe|monitor|liveness|audit|research|collector|watch|witness|beat|sentinel|registry|scan|health|uptime|checker|rugpull|census|grader|observatory|oracle/i;
// The self-identifying bot convention — a "(+https://…)" info URL in the UA — is
// the most robust monitor signal: registry/health/security probes announce an
// info page this way (Googlebot-style), genuine agent clients almost never do.
// Catches monitors that dodge the keyword list (mcpqueen-grader, aiagentboard-hub…).
const ANNOUNCED_URL_RE = /\(\+https?:\/\//i;
function classOf(ip, ua) {
  if (FIRST_PARTY.some((p) => ip.startsWith(p))) return "first-party";
  if (MONITOR_RE.test(ua || "") || ANNOUNCED_URL_RE.test(ua || "")) return "monitoring";
  if (!ua || !ua.trim()) return "unidentified";
  return "independent";
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
    try { const m = readFileSync(c, "utf8").match(/^oauth_token\s*=\s*"([^"]+)"/m); if (m) return { token: m[1], src: "wrangler oauth token" }; }
    catch { /* next */ }
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Cloudflare's GraphQL analytics API rate-limits bursts, so queries are spaced
// and a rate-limited query backs off and retries rather than silently dropping
// a window (which would under-report — the failure mode this tool exists to avoid).
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

function dayWindows(n) {
  const out = [];
  const now = new Date();
  const midnightUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  for (let i = 0; i < n; i++) out.push({ since: new Date(midnightUTC - i * 86400000).toISOString(), until: new Date(midnightUTC - (i - 1) * 86400000).toISOString(), idx: i });
  return out.reverse();
}

const QUERY = `query($zone:String!,$since:Time!,$until:Time!,$f:[ZoneHttpRequestsAdaptiveGroupsFilter_InputObject!]){
  viewer{ zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:500, filter:{AND:$f}, orderBy:[count_DESC]){
      count avg{ sampleInterval } dimensions{ edgeResponseStatus userAgent clientIP clientCountryName }
    }
  }}
}`;

function bucket(code) { if (code >= 200 && code < 300) return "ok"; if (code >= 300 && code < 400) return "redir"; if (code >= 400 && code < 500) return "clientErr"; return "serverErr"; }
const CLASSES = ["independent", "first-party", "monitoring", "unidentified"];

async function run() {
  const auth = getToken();
  if (!auth) { console.error("No Cloudflare token. Set CLOUDFLARE_API_TOKEN (Account+Zone Analytics:Read) or `wrangler login`."); process.exit(2); }
  const windows = dayWindows(DAYS);
  let sampled = false;

  const totals = {};
  for (const ep of ENDPOINTS) {
    totals[ep.key] = { total: 0, ok: 0, redir: 0, clientErr: 0, serverErr: 0, byClass: {}, indepIpDays: new Map(), countries: new Set() };
    for (const c of CLASSES) totals[ep.key].byClass[c] = { total: 0, ok: 0 };
  }

  let firstQuery = true;
  for (const w of windows) {
    for (const ep of ENDPOINTS) {
      if (!firstQuery) await sleep(350); // space queries so the analytics API doesn't rate-limit the burst
      firstQuery = false;
      let data;
      try { data = await gql(auth.token, QUERY, { zone: ZONE, since: w.since, until: w.until, f: [{ datetime_geq: w.since }, { datetime_leq: w.until }, ep.filter] }); }
      catch (e) { console.error(`  ! ${ep.key} ${w.since.slice(0, 10)}: ${e.message}`); continue; }
      const rows = data.viewer.zones?.[0]?.httpRequestsAdaptiveGroups || [];
      for (const r of rows) {
        const si = (r.avg && r.avg.sampleInterval) || 1; if (si > 1.001) sampled = true;
        const n = Math.round(r.count * si);
        const t = totals[ep.key];
        const b = bucket(Number(r.dimensions.edgeResponseStatus));
        const cls = classOf(r.dimensions.clientIP || "", r.dimensions.userAgent);
        t.total += n; t[b] += n;
        t.byClass[cls].total += n; if (b === "ok") t.byClass[cls].ok += n;
        if (r.dimensions.clientCountryName) t.countries.add(r.dimensions.clientCountryName);
        if (cls === "independent" && b === "ok") {
          const ip = r.dimensions.clientIP || "?";
          if (!t.indepIpDays.has(ip)) t.indepIpDays.set(ip, { days: new Set(), n: 0, ctry: r.dimensions.clientCountryName });
          const e = t.indepIpDays.get(ip); e.days.add(w.idx); e.n += n;
        }
      }
    }
  }

  const summarize = (t) => {
    const indep = [...t.indepIpDays.entries()].map(([ip, v]) => ({ ip, n: v.n, days: v.days.size, ctry: v.ctry }));
    return {
      total: t.total, status: { ok: t.ok, redir: t.redir, clientErr: t.clientErr, serverErr: t.serverErr },
      classes: t.byClass, countries: t.countries.size,
      independentCallers: indep.length,
      independentRepeatCallers: indep.filter((x) => x.days >= 2).length,
      topIndependent: indep.sort((a, b) => b.n - a.n).slice(0, TOP),
    };
  };
  const report = {}; for (const ep of ENDPOINTS) report[ep.key] = summarize(totals[ep.key]);
  const meta = { zone: ZONE, days: DAYS, since: windows[0].since, until: windows[windows.length - 1].until, lastDayPartial: true, sampled, firstPartyPrefixes: FIRST_PARTY };

  if (AS_JSON) { console.log(JSON.stringify({ ...meta, endpoints: report }, null, 2)); return; }

  console.log(`\nNessGate usage & adoption — zone ${ZONE} — last ${DAYS} day(s), newest PARTIAL`);
  console.log(`window: ${meta.since.slice(0, 10)} → ${meta.until.slice(0, 10)}  (auth: ${auth.src})`);
  console.log(`counts are ${sampled ? "ESTIMATES (adaptive sampling; weighted by sampleInterval)" : "unsampled"}`);
  console.log(FIRST_PARTY.length ? `first-party IP prefixes: ${FIRST_PARTY.join(", ")}` : `NO first-party prefixes declared — first-party traffic will show as "independent". Pass --first-party=<prefix,..> or set NESSGATE_FIRST_PARTY.`);
  for (const ep of ENDPOINTS) {
    const s = report[ep.key];
    if (!s.total) { console.log(`\n${ep.label}: (no traffic)`); continue; }
    const c = s.classes;
    console.log(`\n${ep.label} — ${s.total} req  [2xx ${s.status.ok} · 4xx ${s.status.clientErr} · 5xx ${s.status.serverErr}]  ${s.countries} countries`);
    console.log(`   by class (successful 2xx / total):  independent ${c.independent.ok}/${c.independent.total} · first-party ${c["first-party"].ok}/${c["first-party"].total} · monitoring ${c.monitoring.ok}/${c.monitoring.total} · no-UA ${c.unidentified.ok}/${c.unidentified.total}`);
    console.log(`   INDEPENDENT external callers: ${s.independentCallers} distinct, ${s.independentRepeatCallers} repeat (>=2 days)`);
    if (s.topIndependent.length) for (const x of s.topIndependent) console.log(`      ${String(x.n).padStart(5)} 2xx  ${x.days}d  ${x.ip} (${x.ctry || "?"})`);
  }
  console.log(`\nADOPTION READING: "independent + repeat" is the real signal. "successful call" = edge 2xx = UPPER BOUND`);
  console.log(`on successful discovery (edge can't see JSON-RPC method, resolved domain, or provenance — that needs`);
  console.log(`app-level counters, a separate decision vs. no-store). Monitoring = ecosystem presence, not dependency.`);
}

run().catch((e) => { console.error("usage-analytics failed:", e.message); process.exit(1); });
