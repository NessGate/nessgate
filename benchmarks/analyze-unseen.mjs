// Separated unseen-domain metrics (never one accuracy number).
import { readFileSync } from "node:fs";
const rows = readFileSync(process.argv[2], "utf8").trim().split("\n").filter(Boolean).map((l)=>JSON.parse(l));
const q=(a,p)=>{if(!a.length)return 0;const s=a.slice().sort((x,y)=>x-y);return s[Math.min(s.length-1,Math.floor(p*(s.length-1)))];};
const pct=(n,d)=>d?(100*n/d).toFixed(1)+"%":"n/a";
const pos = rows.filter(r=>r.stratum==="multi-protocol"||r.stratum==="positive-single");
const neg = rows.filter(r=>r.stratum==="negative-control");
const blk = rows.filter(r=>r.stratum==="blocked");
// authoritative-resource recall (protocol-level, positives only)
let gtTotal=0, hits=0; const missed=[];
for(const r of pos){ gtTotal+=r.gt.length; hits+=r.recallHits.length; if(r.missed.length) missed.push({domain:r.domain, missed:r.missed}); }
// per-protocol recall
const perProto={};
for(const r of pos){ for(const p of r.gt){ perProto[p]=perProto[p]||{gt:0,found:0}; perProto[p].gt++; if(r.recallHits.includes(p)) perProto[p].found++; } }
// false positives
const negFP = neg.filter(r=>(r.foundProtocols||[]).length>0);
const posFP = pos.filter(r=>r.falsePositives.length>0);
// domain-level full recall
const fullRecall = pos.filter(r=>r.missed.length===0).length;
const withItems = rows.filter(r=>r.itemCount>0);
const out = {
  strata: { multiProtocol: rows.filter(r=>r.stratum==="multi-protocol").length, positiveSingle: rows.filter(r=>r.stratum==="positive-single").length, negativeControl: neg.length, blocked: blk.length },
  authoritativeRecall: { protocolLevel: `${hits}/${gtTotal} (${pct(hits,gtTotal)})`, domainFullRecall: `${fullRecall}/${pos.length} (${pct(fullRecall,pos.length)})`, perProtocol: Object.fromEntries(Object.entries(perProto).map(([k,v])=>[k,`${v.found}/${v.gt}`])) },
  recallMisses: missed,
  falsePositives: { negativeControls_withAnyResult: `${negFP.length}/${neg.length} (${pct(negFP.length,neg.length)})`, negFPdomains: negFP.map(r=>({d:r.domain,found:r.foundProtocols})), positiveDomains_extra: posFP.map(r=>({d:r.domain,extra:r.falsePositives})) },
  classificationCorrectness: `${withItems.filter(r=>r.classOk).length}/${withItems.length} (${pct(withItems.filter(r=>r.classOk).length,withItems.length)})`,
  provenanceCorrectness: `${withItems.filter(r=>r.provOk).length}/${withItems.length} (${pct(withItems.filter(r=>r.provOk).length,withItems.length)})`,
  protocolParserFailures: rows.filter(r=>r.error).map(r=>({d:r.domain,err:r.error})),
  blockedStratum: blk.map(r=>({d:r.domain, found:r.foundProtocols||[], note:"reported separately, not a negative"})),
  cost: { ms_p50:q(rows.map(r=>r.ms),0.5), ms_p90:q(rows.map(r=>r.ms),0.9), requests_p50:q(rows.map(r=>r.requests||0),0.5), requests_p90:q(rows.map(r=>r.requests||0),0.9) },
};
console.log(JSON.stringify(out,null,2));
