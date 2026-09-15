// Group empty-result domains by recurring discoverability pattern, looking for
// GENERAL rules (no domain-specific logic). Per empty domain, one bounded probe
// set: (1) homepage final host after redirects — is the canonical host different
// from the literal apex? (2) if so, does the CANONICAL host serve a
// content-valid llms.txt or ard.json the apex probe missed? (3) does the apex
// serve security.txt / robots.txt (well-known-capable operator without AI files)?
import { validateProbeContent, probeShapeOk } from "../src/worker.js";
import { readFileSync } from "node:fs";

const domains = readFileSync(process.argv[2], "utf8").trim().split("\n").filter(Boolean);
async function get(u) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), 10000);
  try {
    const r = await fetch(u, { signal: c.signal, redirect: "follow", headers: { "User-Agent": "Mozilla/5.0" } });
    return { status: r.status, finalUrl: r.url, text: await r.text() };
  } catch { return { status: 0, finalUrl: u, text: "" }; }
  finally { clearTimeout(t); }
}
const out = [];
async function work(list) {
  for (const d of list) {
    const home = await get(`https://${d}/`);
    let canonicalHost = null;
    try { canonicalHost = new URL(home.finalUrl).hostname.toLowerCase(); } catch {}
    const hostDiffers = canonicalHost && canonicalHost !== d;
    // Safeguard: only a redirect that STAYS within the same registrable domain
    // (www./subdomain of the apex) can feed an automatic-fallback rule. A
    // redirect to a different registrable domain is recorded ONLY as a
    // publisher-redirect candidate (provenance: the homepage redirect) and must
    // go through the existing evidence rules — never silently authoritative.
    const sameRegDomain = hostDiffers && (canonicalHost === "www." + d || canonicalHost.endsWith("." + d));
    const crossRegDomain = hostDiffers && !sameRegDomain;
    let canonicalHasFiles = false;
    if (hostDiffers) {
      const l = await get(`https://${canonicalHost}/llms.txt`);
      if (l.status === 200 && validateProbeContent("text", l.text)) canonicalHasFiles = true;
      else {
        const a = await get(`https://${canonicalHost}/.well-known/ard.json`);
        if (a.status === 200 && probeShapeOk("ard-catalog", "json", a.text)) canonicalHasFiles = true;
      }
    }
    // security.txt: DESCRIPTIVE DIAGNOSTIC ONLY — never evidence for AI-discovery
    // likelihood and never part of any promotion rule.
    const sec = await get(`https://${d}/.well-known/security.txt`);
    const secOk = sec.status === 200 && validateProbeContent("text", sec.text) && /contact:/i.test(sec.text);
    out.push({ d, homeStatus: home.status, canonicalHost, sameRegDomain, crossRegDomain, canonicalHasFiles, securityTxt: secOk });
    console.log(`${d}: home=${home.status} canonical=${canonicalHost || "-"} same-reg=${sameRegDomain} cross-reg=${crossRegDomain} canonicalFiles=${canonicalHasFiles} sec.txt(diag)=${secOk}`);
  }
}
const N = 6;
await Promise.all(Array.from({ length: N }, (_, i) => work(domains.filter((_, j) => j % N === i))));
const n = out.length;
const c = (f) => out.filter(f).length;
console.log(`\n=== pattern summary (${n} empties) ===`);
console.log(`no functional homepage (status 0/5xx): ${c((o) => !o.homeStatus || o.homeStatus >= 500)}`);
console.log(`canonical redirects WITHIN registrable domain (www./sub): ${c((o) => o.sameRegDomain)}`);
console.log(`  ...with valid llms/ard on the canonical host: ${c((o) => o.sameRegDomain && o.canonicalHasFiles)}  <-- automatic-fallback rule candidate`);
console.log(`canonical redirects to a DIFFERENT registrable domain: ${c((o) => o.crossRegDomain)}`);
console.log(`  ...with valid files there: ${c((o) => o.crossRegDomain && o.canonicalHasFiles)}  <-- publisher-redirect candidates ONLY (existing evidence rules; never silently authoritative)`);
console.log(`[diagnostic only] valid security.txt present: ${c((o) => o.securityTxt)}`);
console.log(`same-reg fallback flips: ${out.filter((o) => o.sameRegDomain && o.canonicalHasFiles).map((o) => o.d + "->" + o.canonicalHost).join(", ") || "none"}`);
console.log(`cross-reg redirect candidates: ${out.filter((o) => o.crossRegDomain && o.canonicalHasFiles).map((o) => o.d + "->" + o.canonicalHost).join(", ") || "none"}`);
