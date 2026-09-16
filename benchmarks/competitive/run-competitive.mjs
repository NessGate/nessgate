// Competitive benchmark harness — NessGate /discover vs DNS-AID (dns-aid-core).
//
// Runs both resolvers on the frozen holdout (benchmarks/holdout-unseen.json) and
// records, per domain and per tool: which protocols/resources each found, recall
// vs. independently-established ground truth, latency, and — the reviewer's key
// metric — NessGate's ADDITIONAL correct discoveries beyond what DNS-AID's
// claimed surfaces can obtain.
//
// FAIR-PLAY RULES (per the review: "do not compare systems on functions they do
// not claim to perform"):
//   * DNS-AID claims DNS agent records (_agents/_aiagents SVCB/TXT) + ARD catalog
//     dereferencing (--use-http-index probes /.well-known/ai-catalog.json). So it
//     is scored ONLY on the ARD-catalog + AID surfaces.
//   * NessGate's "incremental" = correct resources on the OTHER surfaces
//     (llms.txt, openapi, api-catalog, a2a, host-meta, awp, ucp, anp, ord, gbz)
//     that DNS-AID structurally cannot read. The report must disclose that this
//     is a breadth-of-surfaces advantage that DECAYS as ARD adoption grows (a
//     complete ARD catalog can itself list those same resources).
//
// The competitor binary lives OUTSIDE this repo. Point at it with --dnsaid=<path>
// or env DNSAID_BIN (default: C:\ng-bench\venv\Scripts\dns-aid.exe).
//
//   node benchmarks/competitive/run-competitive.mjs [--limit=N] [--offset=N]
//        [--strata=multi-protocol,positive-single] [--out=results-smoke.jsonl]
//        [--dnsaid=<path>] [--timeout=45000]
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const args = Object.fromEntries(process.argv.slice(2).map((a) => {
  const m = a.match(/^--([^=]+)(?:=(.*))?$/);
  return m ? [m[1], m[2] === undefined ? true : m[2]] : [a, true];
}));
const DNSAID = args.dnsaid || process.env.DNSAID_BIN || "C:\\ng-bench\\venv\\Scripts\\dns-aid.exe";
const TIMEOUT = parseInt(args.timeout, 10) || 45000;
const OUT = join(HERE, args.out || "results-smoke.jsonl");
const STRATA = args.strata ? String(args.strata).split(",") : null;

// ARD is reachable via several adapters; all collapse to the ard-catalog surface.
const norm = (t) => (t === "ard-link" || t === "ard-agentmap" ? "ard-catalog" : t);
// The only surfaces DNS-AID claims to read.
const DNSAID_SURFACES = new Set(["ard-catalog", "aid"]);

const holdout = JSON.parse(readFileSync(join(REPO, "benchmarks", "holdout-unseen.json"), "utf8"));
let domains = holdout.domains;
if (STRATA) domains = domains.filter((d) => STRATA.includes(d.stratum));
const offset = parseInt(args.offset, 10) || 0;
const limit = parseInt(args.limit, 10) || domains.length;
domains = domains.slice(offset, offset + limit);

async function nessgate(domain) {
  const t0 = Date.now();
  try {
    const r = await fetch(`https://nessgate.com/discover/${domain}`, { headers: { "user-agent": "nessgate-competitive-bench/1.0" } });
    const j = await r.json();
    const found = [...new Set((j.discovered || []).map((d) => norm(d.type)))];
    return { ok: true, status: r.status, found, resourceCount: (j.resources || []).length, ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: String(e.message || e).slice(0, 120), ms: Date.now() - t0 };
  }
}

// Extract the first complete brace-balanced JSON object from mixed output.
function extractJson(s) {
  const i = s.indexOf("{");
  if (i < 0) return "";
  let depth = 0, inStr = false, esc = false;
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; }
    else if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") { if (--depth === 0) return s.slice(i, j + 1); }
  }
  return s.slice(i);
}

function dnsaid(domain) {
  const t0 = Date.now();
  const res = spawnSync(DNSAID, ["-q", "discover", domain, "-j", "--use-http-index"], {
    encoding: "utf8", timeout: TIMEOUT, windowsHide: true,
  });
  const ms = Date.now() - t0;
  if (res.error) return { ok: false, error: String(res.error.message || res.error).slice(0, 120), ms };
  // JSON is printed to stdout; extract the FIRST complete brace-balanced object
  // (nested braces broke a naive lastIndexOf grab, masking nonzero results).
  const out = res.stdout || "";
  const json = extractJson(out);
  try {
    const j = JSON.parse(json);
    const agents = j.agents || [];
    const urls = agents.map((a) => a.endpoint || a.url || a.target_host || a.uri).filter(Boolean);
    // count>0 means it found + dereferenced a catalog or DNS agent record.
    return { ok: true, count: j.count ?? agents.length, method: j.discovery_method, agentUrls: urls.slice(0, 20), ms };
  } catch (e) {
    return { ok: false, error: "parse: " + String(e.message).slice(0, 80), raw: out.slice(0, 160), ms };
  }
}

const rows = [];
let i = 0;
for (const d of domains) {
  i++;
  const gt = new Set(d.groundTruthProtocols || []);
  const positive = d.stratum === "multi-protocol" || d.stratum === "positive-single";
  const [ng, da] = [await nessgate(d.domain), dnsaid(d.domain)];

  const ngFound = new Set(ng.found || []);
  const ngHit = [...ngFound].filter((p) => gt.has(p));
  const ngRecall = positive && gt.size ? ngHit.length / gt.size : null;
  const ngFalse = [...ngFound].filter((p) => !gt.has(p)); // for negatives, any = FP
  // NessGate's correct discoveries on surfaces DNS-AID cannot read:
  const ngIncrementalCorrect = ngHit.filter((p) => !DNSAID_SURFACES.has(p));
  // Did the domain publish an ARD catalog (the surface both claim)?
  const gtHasArd = gt.has("ard-catalog");
  const daFoundSomething = da.ok && da.count > 0;

  const row = {
    domain: d.domain, stratum: d.stratum, groundTruth: [...gt], reachable: d.reachable,
    nessgate: { found: [...ngFound], recall: ngRecall, falsePositives: positive ? undefined : ngFalse, ms: ng.ms, status: ng.status, error: ng.error },
    dnsaid: { count: da.count, method: da.method, ms: da.ms, error: da.error },
    incremental: { ngCorrectBeyondDnsaid: ngIncrementalCorrect, gtHasArd, dnsaidFoundArdOrDns: daFoundSomething },
  };
  rows.push(row);
  const rc = ngRecall === null ? " n/a" : `${Math.round(ngRecall * 100)}%`;
  console.log(`[${i}/${domains.length}] ${d.domain.padEnd(24)} ${d.stratum.padEnd(16)} NG recall ${rc.padStart(4)} (${ngFound.size}p) | DNS-AID ${da.ok ? da.count + " agents" : "ERR " + da.error} | +${ngIncrementalCorrect.length} beyond`);
}

mkdirSync(HERE, { recursive: true });
writeFileSync(OUT, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

// ---- summary ----
const pos = rows.filter((r) => r.stratum === "multi-protocol" || r.stratum === "positive-single");
const neg = rows.filter((r) => r.stratum === "negative-control");
const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
const med = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const ngRecalls = pos.map((r) => r.nessgate.recall).filter((x) => x != null);
const daArdDomains = pos.filter((r) => r.incremental.gtHasArd);
const daFoundOnArd = daArdDomains.filter((r) => r.incremental.dnsaidFoundArdOrDns);
const incrementalDomains = pos.filter((r) => r.incremental.ngCorrectBeyondDnsaid.length > 0);

console.log("\n==== SUMMARY ====");
console.log(`positives tested: ${pos.length} | negatives: ${neg.length}`);
console.log(`NessGate mean recall (positives): ${(mean(ngRecalls) * 100).toFixed(1)}%  (perfect on ${ngRecalls.filter((x) => x === 1).length}/${ngRecalls.length})`);
console.log(`DNS-AID: found something on ${daFoundOnArd.length}/${daArdDomains.length} ARD-publishing domains; nonzero on ${pos.filter((r) => r.dnsaid.count > 0).length}/${pos.length} positives total`);
console.log(`NessGate incremental (correct, DNS-AID cannot read): ${incrementalDomains.length}/${pos.length} domains gained something; total correct-surface hits beyond DNS-AID = ${pos.reduce((n, r) => n + r.incremental.ngCorrectBeyondDnsaid.length, 0)}`);
console.log(`negative-control: NessGate false-positive domains = ${neg.filter((r) => (r.nessgate.falsePositives || []).length > 0).length}/${neg.length}; DNS-AID nonzero = ${neg.filter((r) => r.dnsaid.count > 0).length}/${neg.length}`);
console.log(`latency median ms — NessGate ${med(rows.map((r) => r.nessgate.ms))} | DNS-AID ${med(rows.map((r) => r.dnsaid.ms))}`);
console.log(`\nwrote ${rows.length} rows → ${OUT}`);
