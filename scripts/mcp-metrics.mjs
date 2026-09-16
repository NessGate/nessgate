// Reads the anonymous discovery-outcome events (Charter Promise 6) from
// Cloudflare Analytics Engine and reports daily fulfilment. The events are
// categorical only — one outcome label per discovery call — so this is the only
// place aggregation happens (at query time), exactly as the Charter/privacy
// wording states.
//
// Honesty: Analytics Engine adaptively SAMPLES under load; each row carries
// _sample_interval and true counts are SUM(_sample_interval). At NessGate's
// volume sampling is usually 1, but not guaranteed — so every count here is an
// ESTIMATE and labelled as such. "resources" means a response CONTAINED
// resources, NOT that any agent used them.
//
// Auth: CLOUDFLARE_API_TOKEN (needs Account Analytics: Read) if set, else the
// local wrangler OAuth token (may lack the scope — reported honestly if so).
//
//   node scripts/mcp-metrics.mjs [--days=7]
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ACCOUNT = process.env.NESSGATE_ACCOUNT_ID || "5eec758513cbd446ac35baa4b59a315b";
const DATASET = "nessgate_discovery_v1";
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const m = a.match(/^--([^=]+)(?:=(.*))?$/); return m ? [m[1], m[2] ?? true] : [a, true]; }));
const DAYS = Math.max(1, Math.min(90, parseInt(args.days, 10) || 7));

function getToken() {
  if (process.env.CLOUDFLARE_API_TOKEN) return process.env.CLOUDFLARE_API_TOKEN.trim();
  for (const c of [process.env.APPDATA && join(process.env.APPDATA, "xdg.config/.wrangler/config/default.toml"), process.env.HOME && join(process.env.HOME, ".config/.wrangler/config/default.toml")].filter(Boolean)) {
    try { const m = readFileSync(c, "utf8").match(/^oauth_token\s*=\s*"([^"]+)"/m); if (m) return m[1]; } catch { /* next */ }
  }
  return null;
}

const OUTCOMES = ["resources", "empty", "invalid", "error"];

async function run() {
  const token = getToken();
  if (!token) { console.error("No Cloudflare token (CLOUDFLARE_API_TOKEN or wrangler login)."); process.exit(2); }
  const sql = `SELECT blob1 AS outcome, toStartOfDay(timestamp) AS day, SUM(_sample_interval) AS n, COUNT() AS rows
    FROM ${DATASET} WHERE timestamp > now() - INTERVAL '${DAYS}' DAY GROUP BY outcome, day ORDER BY day ASC`;
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/analytics_engine/sql`, {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "text/plain" }, body: sql,
  });
  const text = await res.text();
  if (!res.ok) {
    if (/not.*exist|unknown.*table|table.*nessgate/i.test(text)) { console.log(`No data yet — dataset ${DATASET} has no events (Analytics Engine just enabled, or no discovery calls since).`); return; }
    if (res.status === 403 || /authentication|authorization|permission/i.test(text)) {
      console.error(`Auth failed reading Analytics Engine (${res.status}). The token needs Account Analytics: Read — the wrangler OAuth token may lack it; create a scoped API token and set CLOUDFLARE_API_TOKEN.`);
      process.exit(3);
    }
    console.error(`Query failed (${res.status}): ${text.slice(0, 300)}`); process.exit(1);
  }
  const rows = JSON.parse(text).data || [];
  if (!rows.length) { console.log("No discovery-outcome events in the window yet."); return; }

  const byDay = {}; let sampled = false;
  for (const r of rows) {
    const day = String(r.day).slice(0, 10);
    (byDay[day] ??= { resources: 0, empty: 0, invalid: 0, error: 0 });
    byDay[day][r.outcome] = Math.round(Number(r.n));
    if (Number(r.n) > Number(r.rows)) sampled = true; // sample_interval > 1 somewhere
  }

  console.log(`\nNessGate discovery fulfilment (anonymous outcome events) — last ${DAYS} day(s)`);
  console.log(`counts are ESTIMATES${sampled ? " (Analytics Engine sampling was in effect; weighted by _sample_interval)" : " (no sampling detected in this window)"}`);
  console.log(`\n  day          calls  resources   empty  invalid   error  |  fulfilment`);
  console.log("  " + "-".repeat(72));
  const tot = { resources: 0, empty: 0, invalid: 0, error: 0 };
  for (const day of Object.keys(byDay).sort()) {
    const d = byDay[day]; for (const k of OUTCOMES) tot[k] += d[k];
    const calls = OUTCOMES.reduce((a, k) => a + d[k], 0);
    const rate = calls ? ((100 * d.resources) / calls).toFixed(0) + "%" : "—";
    console.log(`  ${day}  ${String(calls).padStart(6)}  ${String(d.resources).padStart(8)} ${String(d.empty).padStart(7)} ${String(d.invalid).padStart(8)} ${String(d.error).padStart(7)}  |  ${rate.padStart(5)}`);
  }
  const calls = OUTCOMES.reduce((a, k) => a + tot[k], 0);
  console.log("  " + "-".repeat(72));
  console.log(`  TOTAL        ${String(calls).padStart(6)}  ${String(tot.resources).padStart(8)} ${String(tot.empty).padStart(7)} ${String(tot.invalid).padStart(8)} ${String(tot.error).padStart(7)}  |  ${calls ? ((100 * tot.resources) / calls).toFixed(1) + "%" : "—"}`);
  console.log(`\nfulfilment = responses containing resources ÷ discovery calls. It does NOT prove an agent used them.`);
}
run().catch((e) => { console.error("mcp-metrics failed:", e.message); process.exit(1); });
