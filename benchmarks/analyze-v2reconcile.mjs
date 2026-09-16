// Analyze the reconciled A/B benchmark. A = real strict+explore; B = A + CT/sitemap.
// Reports the TRUE incremental of the new adapters over the full existing capability.
// Usage: node benchmarks/analyze-v2reconcile.mjs <results.jsonl>
import { readFileSync } from "node:fs";

const [file] = process.argv.slice(2);
const rows = readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

const CC2 = new Set(["co.uk","org.uk","ac.uk","com.au","net.au","org.au","co.jp","or.jp","ne.jp","com.br","com.cn","com.mx","co.in","co.za","com.sg","com.tr","co.kr","com.tw","co.nz"]);
const reg = (h) => { const p = String(h||"").toLowerCase().split("."); if (p.length<=2) return p.join("."); const l2=p.slice(-2).join("."); return CC2.has(l2)?p.slice(-3).join("."):l2; };
const pct = (n,d) => d ? (100*n/d).toFixed(1)+"%" : "n/a";
const q = (a,p) => { if(!a.length) return 0; const s=a.slice().sort((x,y)=>x-y); return s[Math.min(s.length-1,Math.floor(p*(s.length-1)))]; };

// Rows where explore actually ran (worker reachable). Others are excluded from
// coverage and listed — they are a harness artifact, not a measurement.
const usable = rows.filter((r) => r.explore && r.explore.ok);
const exploreFailed = rows.filter((r) => !r.explore || !r.explore.ok);

const S = {
  rows: rows.length, usable: usable.length, exploreFailed: exploreFailed.length,
  exploreFailedDomains: exploreFailed.map((r) => r.domain).slice(0, 30),
  aPositive: 0, bPositive: 0,
  rescuedEmpty: [],            // A empty → B positive via CT/sitemap incremental
  discL2Total: 0, discHostsTotal: 0, incrementalHostsTotal: 0, overlapHostsTotal: 0,
  incrementalBySource: {}, incrementalExamples: [], crossRegIncremental: 0, crossRegExamples: [],
  ctSkipped: 0, sitemapSkipped: 0,
  exploreReq: [], discReq: [], ms: [],
};

for (const r of usable) {
  const ex = r.explore, dv = r.discovery || { l2Count: 0, hostCount: 0, incrementalHosts: [], incrementalItems: [], bySource: {} };
  if (ex.positive) S.aPositive++;
  const incr = dv.incrementalHosts || [];
  const bPos = ex.positive || incr.length > 0;   // B counts only TRUE additions over explore
  if (bPos) S.bPositive++;
  if (!ex.positive && incr.length > 0) S.rescuedEmpty.push({ domain: r.domain, hosts: incr });

  S.discL2Total += dv.l2Count || 0;
  S.discHostsTotal += dv.hostCount || 0;
  S.incrementalHostsTotal += incr.length;
  S.overlapHostsTotal += (dv.hostCount || 0) - incr.length;
  for (const it of dv.incrementalItems || []) {
    S.incrementalBySource[it.rel] = (S.incrementalBySource[it.rel] || 0) + 1;
    const cross = reg(it.host) !== reg(r.domain);
    if (cross) { S.crossRegIncremental++; if (S.crossRegExamples.length < 40) S.crossRegExamples.push({ seed: r.domain, host: it.host, rel: it.rel, type: it.type }); }
    if (S.incrementalExamples.length < 60) S.incrementalExamples.push({ seed: r.domain, host: it.host, rel: it.rel, type: it.type });
  }
  if (dv.ctSkipped) S.ctSkipped++;
  if (dv.sitemapSkipped) S.sitemapSkipped++;
  if (typeof ex.requests === "number") S.exploreReq.push(ex.requests);
  if (typeof dv.requests === "number") S.discReq.push(dv.requests);
  S.ms.push(r.ms || 0);
}

const summary = {
  integrity: { rows: S.rows, usable: S.usable, exploreFailed: S.exploreFailed, exploreFailedDomains: S.exploreFailedDomains },
  coverage: {
    A_strictExplore_positive: `${S.aPositive}/${S.usable} (${pct(S.aPositive, S.usable)})`,
    B_plusCTsitemap_positive: `${S.bPositive}/${S.usable} (${pct(S.bPositive, S.usable)})`,
    trueIncrementalDomains: S.bPositive - S.aPositive,
    rescuedFromEmpty: S.rescuedEmpty.length,
    rescuedExamples: S.rescuedEmpty.slice(0, 30),
    frozenBaselineNote: "Historical frozen v1.6 baseline was 57/200 (28.5%). Compare A above (fresh run).",
  },
  level2Additions: {
    discoveryL2Items_total: S.discL2Total,
    discoveryHosts_total: S.discHostsTotal,
    hostsAlreadyFoundByExplore_overlap: S.overlapHostsTotal,
    hostsNEWvsExplore_incremental: S.incrementalHostsTotal,
    incrementalBySource: S.incrementalBySource,
    reconciliationNote: "overlap = CT/sitemap hosts explore's org/related ALSO found (no new coverage). incremental = genuinely new hosts.",
    incrementalExamples: S.incrementalExamples,
  },
  falseNoisyAssociations: {
    crossRegistrableIncremental: S.crossRegIncremental,
    note: "cross-registrable incremental hosts are the noise-prone case; all are Level 2, never authoritative. Audit:",
    examples: S.crossRegExamples,
  },
  cost: {
    exploreRequests_p50: q(S.exploreReq, 0.5), exploreRequests_p90: q(S.exploreReq, 0.9),
    discoveryRequests_p50: q(S.discReq, 0.5), discoveryRequests_p90: q(S.discReq, 0.9),
    combinedMs_p50: q(S.ms, 0.5), combinedMs_p90: q(S.ms, 0.9),
    note: "combined ms = explore + discovery in this harness (exact-host runs twice; a unified balanced would share it once).",
  },
  adapterFailureRates: {
    ctSkipped: `${S.ctSkipped}/${S.usable} (${pct(S.ctSkipped, S.usable)})`,
    sitemapSkipped: `${S.sitemapSkipped}/${S.usable} (${pct(S.sitemapSkipped, S.usable)})`,
    note: "high crt.sh abort rate makes the incremental a LOWER BOUND; see CT-source investigation.",
  },
};
console.log(JSON.stringify(summary, null, 2));
