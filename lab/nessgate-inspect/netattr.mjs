// Verified Network Attribution (lab-only) for NessGate Inspect.
//
// Confirms whether a request's SOURCE IP belongs to infrastructure an operator
// officially attributes to its bot — using THAT operator's documented method:
//   - Google / Bing / Apple: reverse DNS + forward-confirm (PTR ends with the
//     operator's documented host suffix, AND forward-resolving that host returns
//     the original source IP).
//   - OpenAI (GPTBot / ChatGPT-User / OAI-SearchBot): membership in the operator's
//     officially published IP/CIDR ranges.
//
// Hard rules:
//   - The source IP MUST be the real connection peer. Forwarded headers
//     (X-Forwarded-For, etc.) are NEVER trusted here; the caller supplies
//     opts.sourceIp from the actual socket (or an explicitly trusted proxy).
//   - A success means ONLY "this request originated from infrastructure attributed
//     to operator X." It is NOT trust, authorization, safety, or allow.
//   - Failure or unavailability falls back honestly (no network-verified fact);
//     a non-match is never asserted as proof of spoofing (a new/proxied IP can
//     also fail) and never a false positive.
//   - Reuses each operator's own published method/source; invents nothing.

import dnsPromises from "node:dns/promises";
import { safeFetchJson } from "./webbotauth.mjs";

// Operator network-verification specs (each operator's OFFICIAL method/source).
export const NETWORK_METHODS = [
  { match: /Googlebot|Google-Extended|GoogleOther|Google-CloudVertexBot/i, operator: "Google", method: "rdns-forward-confirm", suffixes: [".googlebot.com", ".google.com", ".googleusercontent.com"], doc: "https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot" },
  { match: /bingbot|BingPreview|MicrosoftPreview|adidxbot/i, operator: "Microsoft (Bing)", method: "rdns-forward-confirm", suffixes: [".search.msn.com"], doc: "https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26" },
  { match: /Applebot/i, operator: "Apple", method: "rdns-forward-confirm", suffixes: [".applebot.apple.com"], doc: "https://support.apple.com/en-us/119829" },
  { match: /GPTBot/i, operator: "OpenAI", method: "ip-ranges", rangesUrl: "https://openai.com/gptbot.json", doc: "https://platform.openai.com/docs/bots" },
  { match: /OAI-SearchBot/i, operator: "OpenAI", method: "ip-ranges", rangesUrl: "https://openai.com/searchbot.json", doc: "https://platform.openai.com/docs/bots" },
  { match: /ChatGPT-User/i, operator: "OpenAI", method: "ip-ranges", rangesUrl: "https://openai.com/chatgpt-user.json", doc: "https://platform.openai.com/docs/bots" },
];

export function networkMethodFor(userAgent) {
  if (typeof userAgent !== "string") return null;
  return NETWORK_METHODS.find((s) => s.match.test(userAgent)) || null;
}

/* ------------------------------ CIDR matching ------------------------------ */
function ip4ToInt(ip) {
  const p = String(ip).split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) { const x = Number(o); if (!Number.isInteger(x) || x < 0 || x > 255) return null; n = n * 256 + x; }
  return n >>> 0;
}
function inCidr4(ip, net, bits) {
  const a = ip4ToInt(ip), b = ip4ToInt(net);
  if (a == null || b == null || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}
function ip6ToBig(ip) {
  ip = String(ip).toLowerCase();
  const m = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/); // v4-mapped tail
  if (m) { const v4 = ip4ToInt(m[2]); if (v4 == null) return null; ip = m[1] + ((v4 >>> 16).toString(16)) + ":" + ((v4 & 0xffff).toString(16)); }
  const parts = ip.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":").filter(Boolean) : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":").filter(Boolean) : [];
  const fill = 8 - (head.length + tail.length);
  if (fill < 0 || (parts.length === 1 && head.length !== 8)) return null;
  const groups = parts.length === 2 ? [...head, ...Array(fill).fill("0"), ...tail] : head;
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) { const x = parseInt(g || "0", 16); if (Number.isNaN(x)) return null; n = (n << 16n) + BigInt(x); }
  return n;
}
function inCidr6(ip, net, bits) {
  const a = ip6ToBig(ip), b = ip6ToBig(net);
  if (a == null || b == null || bits < 0 || bits > 128) return false;
  const mask = bits === 0 ? 0n : ((~0n) << BigInt(128 - bits)) & ((1n << 128n) - 1n);
  return (a & mask) === (b & mask);
}
// normalize v4-mapped ("::ffff:1.2.3.4") to its v4 form for v4 range checks.
export function normalizeIp(ip) {
  const m = String(ip || "").toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return m ? m[1] : String(ip || "");
}
export function ipInCidr(ip, cidr) {
  const [net, bitsS] = String(cidr).split("/");
  const bits = Number(bitsS);
  if (!Number.isInteger(bits)) return false;
  const nip = normalizeIp(ip);
  const v6 = cidr.includes(":");
  if (v6) return inCidr6(nip, net, bits);
  if (nip.includes(":")) return false; // v4 range, v6 address → no match
  return inCidr4(nip, net, bits);
}

/* --------------------------- method implementations ------------------------ */
async function rdnsForwardConfirm(dns, ip, suffixes) {
  let ptrs = [];
  try { ptrs = await dns.reverse(ip); } catch (e) { return { verified: false, reason: "no reverse DNS record (" + (e && e.code || "error") + ")" }; }
  for (const raw of ptrs) {
    const host = String(raw).toLowerCase().replace(/\.$/, "");
    if (!suffixes.some((s) => host === s.slice(1) || host.endsWith(s))) continue;
    const resolver = ip.includes(":") ? dns.resolve6 : dns.resolve4;
    let fwd = [];
    try { fwd = await resolver.call(dns, host); } catch { fwd = []; }
    if (fwd.map(normalizeIp).includes(normalizeIp(ip))) return { verified: true, hostname: host, confirmedVia: "forward-confirm" };
    return { verified: false, reason: `reverse DNS ${host} did not forward-confirm to the source IP`, ptrs };
  }
  return { verified: false, reason: "reverse DNS did not match the operator's documented host suffixes", ptrs };
}

async function fetchRanges(fetchImpl, url, timeoutMs) {
  const r = await safeFetchJson(fetchImpl, url, timeoutMs);
  if (r.error) return { error: r.error };
  const doc = r.json || {};
  const prefixes = [];
  for (const p of Array.isArray(doc.prefixes) ? doc.prefixes : []) {
    if (p && typeof p.ipv4Prefix === "string") prefixes.push(p.ipv4Prefix);
    else if (p && typeof p.ipv6Prefix === "string") prefixes.push(p.ipv6Prefix);
    else if (typeof p === "string") prefixes.push(p);
  }
  if (!prefixes.length) return { error: "published ranges document has no prefixes" };
  return { prefixes };
}

// Verify. Returns a structured result; never throws. opts.dns / opts.fetch /
// opts.ranges are injectable for testing; defaults use node:dns + global fetch.
export async function verifyNetworkAttribution({ userAgent, sourceIp }, opts = {}) {
  if (!sourceIp) return { attempted: false, reason: "no source IP supplied (connection peer required; forwarded headers are not trusted)" };
  const spec = networkMethodFor(userAgent);
  if (!spec) return { attempted: true, verified: false, reason: "no documented network-verification method is wired for this caller" };
  const base = { attempted: true, operator: spec.operator, method: spec.method, documentation: spec.doc, sourceIp: normalizeIp(sourceIp) };

  if (spec.method === "rdns-forward-confirm") {
    const dns = opts.dns || dnsPromises;
    const res = await rdnsForwardConfirm(dns, normalizeIp(sourceIp), spec.suffixes).catch((e) => ({ verified: false, reason: "rDNS error: " + (e && e.message) }));
    return res.verified
      ? { ...base, verified: true, evidence: { reverseDns: res.hostname, forwardConfirmed: true } }
      : { ...base, verified: false, reason: res.reason, observedReverseDns: res.ptrs };
  }
  if (spec.method === "ip-ranges") {
    const fetchImpl = opts.fetch || globalThis.fetch;
    const ranges = opts.ranges ? { prefixes: opts.ranges } : await fetchRanges(fetchImpl, spec.rangesUrl, opts.timeoutMs);
    if (ranges.error) return { ...base, verified: false, reason: "published ranges unavailable: " + ranges.error, rangesUrl: spec.rangesUrl };
    const hit = ranges.prefixes.find((c) => ipInCidr(sourceIp, c));
    return hit
      ? { ...base, verified: true, evidence: { matchedCidr: hit, rangesUrl: spec.rangesUrl, prefixesChecked: ranges.prefixes.length } }
      : { ...base, verified: false, reason: "source IP is not in the operator's published ranges", rangesUrl: spec.rangesUrl, prefixesChecked: ranges.prefixes.length };
  }
  return { ...base, verified: false, reason: "unsupported method" };
}
