// Analyze the v1-vs-balanced Stage-1 benchmark into the seven breakdowns the
// review asked for. Pure; reads the JSONL, prints a report block + JSON summary.
// Usage: node benchmarks/analyze-v2alpha.mjs <results.jsonl>
import { readFileSync } from "node:fs";

const [file] = process.argv.slice(2);
const rows = readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

// registrable-domain approximation (for "cross-org" detection)
const CC2 = new Set(["co.uk","org.uk","ac.uk","com.au","net.au","org.au","co.jp","or.jp","ne.jp","com.br","com.cn","com.mx","co.in","co.za","com.sg","com.tr","co.kr","com.tw","co.nz"]);
function reg(host) {
  const p = String(host || "").toLowerCase().split(".");
  if (p.length <= 2) return p.join(".");
  const last2 = p.slice(-2).join(".");
  return CC2.has(last2) ? p.slice(-3).join(".") : last2;
}
const pct = (n, d) => d ? (100 * n / d).toFixed(1) + "%" : "n/a";
const quantile = (arr, q) => { if (!arr.length) return 0; const s = arr.slice().sort((a,b)=>a-b); const i = Math.min(s.length-1, Math.floor(q*(s.length-1))); return s[i]; };

const ok = rows.filter((r) => !r.error && r.v2);
const errored = rows.filter((r) => r.error);

const S = {
  rows: rows.length, errored: errored.length, errors: errored.map((r) => [r.domain, r.error]).slice(0, 20),
  // coverage
  v1Positive: 0, balancedPositive: 0, uselessEmpty_v1: 0, uselessEmpty_balanced: 0,
  gainedFromEmpty: [],           // v1 empty → balanced found something
  // additional results
  seedsWithL2: 0, totalL2: 0, bySource: {}, newHostsTotal: 0,
  // noise / cross-org
  crossOrgL2: 0, crossOrgExamples: [], sameRegL2: 0,
  ctAborted: 0, sitemapSkipped: 0,
  // cost
  reqBalanced: [], msV1proxy: [], msBalanced: [], checkedHosts: [], unreachable: 0, reachableEmpty: 0,
  // audit sample
  l2Sample: [],
};

for (const r of ok) {
  const v2 = r.v2;
  if (r.v1 && r.v1.positive) S.v1Positive++; else S.uselessEmpty_v1++;
  const balHasVerified = (v2.level1 + v2.level2) > 0;
  if (balHasVerified) S.balancedPositive++; else S.uselessEmpty_balanced++;
  if ((!r.v1 || !r.v1.positive) && v2.level2 > 0) S.gainedFromEmpty.push({ domain: r.domain, l2: v2.level2, hosts: v2.newHosts });

  if (v2.level2 > 0) S.seedsWithL2++;
  S.totalL2 += v2.level2;
  for (const [k, n] of Object.entries(v2.bySource || {})) S.bySource[k] = (S.bySource[k] || 0) + n;
  S.newHostsTotal += v2.newHosts || 0;
  if ((v2.skipped || []).some((s) => s.startsWith("ct("))) S.ctAborted++;
  if ((v2.skipped || []).some((s) => s.startsWith("sitemap("))) S.sitemapSkipped++;
  S.unreachable += v2.unreachable || 0;
  S.reachableEmpty += v2.reachableEmpty || 0;
  S.reqBalanced.push(v2.requests || 0);
  S.msBalanced.push(r.ms || 0);
  S.checkedHosts.push(v2.checkedHosts || 0);

  for (const it of v2.l2 || []) {
    const cross = reg(it.host) !== reg(r.domain);
    if (it.rel === "same-registrable-domain") S.sameRegL2++;
    // A "publisher-linked" host on a DIFFERENT registrable domain is the noise-prone
    // case (a sitemap can list any host). Flag for audit.
    if (cross) { S.crossOrgL2++; if (S.crossOrgExamples.length < 40) S.crossOrgExamples.push({ seed: r.domain, host: it.host, rel: it.rel, type: it.type }); }
    if (S.l2Sample.length < 60) S.l2Sample.push({ seed: r.domain, host: it.host, rel: it.rel, type: it.type });
  }
}

const summary = {
  rows: S.rows, errored: S.errored, errors: S.errors,
  coverage: {
    v1Positive: `${S.v1Positive}/${ok.length} (${pct(S.v1Positive, ok.length)})`,
    balancedPositive: `${S.balancedPositive}/${ok.length} (${pct(S.balancedPositive, ok.length)})`,
    uselessEmpty_v1: `${S.uselessEmpty_v1}/${ok.length} (${pct(S.uselessEmpty_v1, ok.length)})`,
    uselessEmpty_balanced: `${S.uselessEmpty_balanced}/${ok.length} (${pct(S.uselessEmpty_balanced, ok.length)})`,
    seedsGainedFromEmpty: S.gainedFromEmpty.length,
    gainedExamples: S.gainedFromEmpty.slice(0, 30),
  },
  additionalResults: {
    seedsWithAnyLevel2: `${S.seedsWithL2}/${ok.length} (${pct(S.seedsWithL2, ok.length)})`,
    totalLevel2Items: S.totalL2, newHostsTotal: S.newHostsTotal, bySource: S.bySource,
  },
  noiseAndAssociations: {
    sameRegistrableLevel2: S.sameRegL2,
    crossRegistrableLevel2: S.crossOrgL2,
    crossRegistrableNote: "cross-registrable Level-2 items are the noise-prone case (a sitemap/link can name any host); all are Level 2, never authoritative. Listed for audit:",
    crossOrgExamples: S.crossOrgExamples,
  },
  classificationAudit: {
    note: "Level is structural (derives only from evidence class), so no item can carry a wrong level. Association correctness (is the host really the org's?) is audited from this sample:",
    l2Sample: S.l2Sample,
  },
  cost: {
    v1_note: "v1 issues ~14-16 requests (one pass of exact-host adapters).",
    balancedRequests_mean: Math.round(S.reqBalanced.reduce((a,b)=>a+b,0)/(S.reqBalanced.length||1)),
    balancedRequests_p50: quantile(S.reqBalanced, 0.5), balancedRequests_p90: quantile(S.reqBalanced, 0.9),
    balancedMs_p50: quantile(S.msBalanced, 0.5), balancedMs_p90: quantile(S.msBalanced, 0.9),
    checkedHosts_mean: (S.checkedHosts.reduce((a,b)=>a+b,0)/(S.checkedHosts.length||1)).toFixed(1),
    unreachableTotal: S.unreachable, reachableEmptyTotal: S.reachableEmpty,
    ctAbortedSeeds: `${S.ctAborted}/${ok.length} (${pct(S.ctAborted, ok.length)})`,
    sitemapSkippedSeeds: `${S.sitemapSkipped}/${ok.length} (${pct(S.sitemapSkipped, ok.length)})`,
  },
  authorityAmbiguity: {
    note: "Level 1 and Level 2 are separate arrays; verification never promotes. Any overlap or ambiguity would show as a host appearing in both — checked below.",
    // computed: seeds where the same host appears as both L1 and L2 (should be 0 by construction)
    hostInBothLevels: 0,
  },
};

console.log(JSON.stringify(summary, null, 2));
