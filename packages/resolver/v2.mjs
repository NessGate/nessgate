// NessGate resolver — v2 ALPHA (EXPERIMENTAL). Stage 1: library-only.
//
// ⚠ This module exercises capabilities PROPOSED under Charter v2, which is NOT
// YET ACTIVE. Charter v1 governs the production hosted resolver. Nothing here
// runs unless you explicitly call resolveV2(); the stable v1 `resolve()` in
// ./index.mjs is imported unchanged and is never modified by this file.
//
// What Stage 1 adds, and ONLY this:
//   1. A two-axis / two-level result model (verification × relationship → level).
//   2. A formalized, self-describing adapter architecture (V2_ADAPTERS).
//   3. Deterministic CT-subdomain and sitemap-host discovery adapters (balanced).
//   4. Provenance attached to every result.
//
// Explicitly NOT here (later stages, gated on Charter v2 becoming active):
// persistent storage/index, publisher registration, hosted crawling/page-reading,
// async refresh, registry federation, any NessReady integration. This module has
// NO store and reads nothing but the domain's own well-known files, its
// robots/sitemap, and public certificate-transparency data — each with provenance.
//
// SSRF: like the v1 core, this fetches hosts derived from the input (now also
// from CT logs and sitemaps, which are attacker-influenceable). A basic host
// guard rejects IP literals / localhost / reserved suffixes and non-HTTPS, but a
// caller passing UNTRUSTED input in a server environment MUST still validate.

import { resolve as resolveV1, normalizeDomain } from "./index.mjs";

export const EXPERIMENTAL = true;
export const CHARTER_STATUS =
  "Exercises capabilities PROPOSED under Charter v2 (NOT active). Charter v1 governs production.";

/* ----------------------------- two-axis model ----------------------------- */

// Relationship (evidence) class → level. LEVEL is the ONLY thing that decides
// authoritative (1) vs discovered (2). Verification NEVER appears here: a fully
// verified resource on a discovered host stays Level 2.
export const LEVEL = Object.freeze({
  // Level 1 — authoritative
  "publisher-hosted": 1,
  "publisher-declared": 1,
  "namespace-verified": 1,
  "registered": 1,
  "publisher-declared-related": 1,
  // Level 2 — discovered
  "same-registrable-domain": 2,
  "publisher-linked": 2,
  "registry-attributed": 2,
  "publisher-redirect-candidate": 2,
  "infrastructure-correlated": 2,
  "candidate": 2,
});

// Deterministic grouping order: Level 1 classes first, then Level 2, in a fixed
// sequence. Ordering WITHIN a group is by host then url. Grouping is not ranking.
const CLASS_ORDER = [
  "publisher-hosted", "publisher-declared", "namespace-verified", "registered", "publisher-declared-related",
  "same-registrable-domain", "publisher-linked", "registry-attributed",
  "publisher-redirect-candidate", "infrastructure-correlated", "candidate",
];

export function levelFor(relationship) {
  const l = LEVEL[relationship];
  if (l === undefined) throw new Error("unknown evidence class: " + relationship);
  return l;
}

// Build one two-axis result item. INVARIANT (enforced here, tested separately):
// `level` is derived ONLY from `relationship`; `verification` cannot change it.
// Provenance is REQUIRED and must be non-empty — every result explains itself.
export function classify(resource, relationship, provenance, verification = "verified") {
  if (!resource || typeof resource !== "object") throw new Error("resource required");
  if (!["verified", "unreachable", "none"].includes(verification)) throw new Error("bad verification: " + verification);
  if (!Array.isArray(provenance) || provenance.length === 0) throw new Error("provenance required on every result");
  return {
    resource,
    verification,               // axis 1: is the resource itself real? (from which read)
    relationship,               // axis 2: why is it associated with the domain?
    level: levelFor(relationship),
    provenance: provenance.slice(),
  };
}

/* --------------------------- pure host helpers ---------------------------- */

const RESERVED_SUFFIXES = [".local", ".localhost", ".internal", ".intranet", ".corp", ".home", ".lan", ".onion"];

// Minimal SSRF-lite guard for hosts we derive from CT/sitemap. Not a substitute
// for full validation in untrusted server contexts (documented above).
export function isSafeHttpsHost(host) {
  if (typeof host !== "string" || !host) return false;
  host = host.toLowerCase().replace(/\.+$/, "");
  if (host === "localhost") return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;   // IPv4 literal
  if (host.includes(":")) return false;                      // IPv6 literal / port
  if (!host.includes(".")) return false;                     // bare hostname
  if (/[^a-z0-9.-]/.test(host)) return false;                // ASCII hostnames only (punycode ok)
  if (RESERVED_SUFFIXES.some((s) => host.endsWith(s))) return false;
  return true;
}

// crt.sh JSON → unique real subdomains under the apex (wildcards stripped).
export function parseCtNames(jsonText, apex, cap = 40) {
  let arr;
  try { arr = JSON.parse(jsonText); } catch { return []; }
  if (!Array.isArray(arr)) return [];
  const seen = new Set(), out = [];
  for (const row of arr) {
    for (const raw of String((row && row.name_value) || "").split(/\n/)) {
      const h = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.+$/, "");
      if (!h || h === apex || h === "www." + apex || !h.endsWith("." + apex)) continue;
      if (!isSafeHttpsHost(h) || seen.has(h)) continue;
      seen.add(h); out.push(h);
      if (out.length >= cap) return out;
    }
  }
  return out;
}

export function parseSitemapLocs(xml) {
  if (typeof xml !== "string") return [];
  const out = [], seen = new Set();
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m;
  while ((m = re.exec(xml))) {
    const u = m[1].trim();
    if (u && !seen.has(u)) { seen.add(u); out.push(u); }
  }
  return out;
}

export function parseRobotsSitemaps(txt) {
  if (typeof txt !== "string") return [];
  const out = [];
  for (const line of txt.split(/\r?\n/)) {
    const m = line.match(/^\s*sitemap\s*:\s*(\S+)/i);
    if (m) out.push(m[1].trim());
  }
  return out;
}

// Distinct hosts appearing in sitemap <loc> URLs, excluding the apex (covered by
// exact-host) and unsafe hosts.
export function hostsFromLocs(locs, apex, cap = 40) {
  const seen = new Set(), out = [];
  for (const loc of locs) {
    let h;
    try { h = new URL(loc).hostname.toLowerCase().replace(/^www\./, "").replace(/\.+$/, ""); } catch { continue; }
    if (h === apex || !isSafeHttpsHost(h) || seen.has(h)) continue;
    seen.add(h); out.push(h);
    if (out.length >= cap) return out;
  }
  return out;
}

/* ------------------------------ local fetch ------------------------------- */
// A small text fetch (v1's fetchText is not exported). Dependency-free.
async function fetchText(fetchImpl, url, accept, timeoutMs, maxBytes) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      signal: ctrl.signal,
      headers: { Accept: accept || "*/*", "User-Agent": "NessGate-Resolver-v2alpha/0 (+https://nessgate.com/charter-v2)" },
    });
    if (!res || !res.ok) throw new Error("HTTP " + (res && res.status));
    const text = await res.text();
    if (text.length > maxBytes) throw new Error("too large");
    return text;
  } finally {
    clearTimeout(timer);
  }
}

// Run the full v1 resolver against a discovered host, then distinguish
// unreachable from none when it finds nothing. Returns {status, resources}.
async function verifyHost(ctx, host) {
  ctx.seenHosts.add(host);
  let r;
  try {
    r = await resolveV1(host, { fetch: ctx.fetchImpl, timeoutMs: ctx.timeoutMs, maxBytes: ctx.maxBytes });
  } catch {
    return { status: "unreachable", resources: [] };
  }
  ctx.stat.requests += r && r.checked ? r.checked.length : 0;
  if (r && r.resources && r.resources.length) return { status: "verified", resources: r.resources };
  try {
    const res = await ctx.fetchImpl("https://" + host + "/", { redirect: "manual" });
    ctx.stat.requests++;
    const s = res && res.status;
    if (s === 403 || (typeof s === "number" && s >= 500)) return { status: "unreachable", resources: [] };
    return { status: "none", resources: [] };
  } catch {
    return { status: "unreachable", resources: [] };
  }
}

/* --------------------------- adapter architecture ------------------------- */
// Self-describing v2 adapters. Each declares what it discovers, the evidence
// class it produces, whether it can establish authority (Level 1), its tier,
// its external dependency, and a run(ctx) that returns two-axis items.

export const V2_ADAPTERS = [
  {
    id: "exact-host",
    standard: "* (v1 core: llms.txt/ARD/A2A/api-catalog/OpenAPI/ORD/AWP/host-meta/ANP/UCP/AID/GB-Z)",
    discovers: "resources",
    evidenceClass: "publisher-hosted",
    canEstablishAuthority: true,   // reading the domain's OWN well-known files
    tier: "fast",
    external: null,
    async run(ctx) {
      let r;
      try {
        r = await resolveV1(ctx.domain, { fetch: ctx.fetchImpl, timeoutMs: ctx.timeoutMs, maxBytes: ctx.maxBytes });
      } catch { ctx.stat.skipped.push("exact-host(error)"); return []; }
      ctx.stat.requests += r && r.checked ? r.checked.length : 0;
      return (r.resources || []).map((res) =>
        classify(res, "publisher-hosted",
          [{ adapter: "exact-host", host: ctx.domain, sourceUrl: res.sourceUrl }], "verified"));
    },
  },
  {
    id: "ct-subdomains",
    standard: "certificate-transparency (crt.sh)",
    discovers: "hosts",
    evidenceClass: "same-registrable-domain",  // namespace proximity ONLY
    canEstablishAuthority: false,
    tier: "balanced",
    external: "ct-log",
    async run(ctx) {
      const items = [];
      let text;
      try {
        text = await fetchText(ctx.fetchImpl, "https://crt.sh/?q=%25." + encodeURIComponent(ctx.domain) + "&output=json",
          "application/json", ctx.timeoutMs, ctx.maxBytes);
        ctx.stat.requests++;
      } catch (e) { ctx.stat.skipped.push("ct(" + ((e && e.message) || "err") + ")"); return items; }
      const names = parseCtNames(text, ctx.domain, ctx.caps.ctCap);
      for (const host of names.slice(0, ctx.caps.hostVerifyCap)) {
        if (ctx.seenHosts.has(host)) continue;
        const v = await verifyHost(ctx, host);
        ctx.stat.checkedHosts++;
        if (v.status === "unreachable") { ctx.stat.unreachable++; continue; }
        if (v.status === "none") { ctx.stat.reachableEmpty++; continue; }
        for (const res of v.resources) {
          items.push(classify(res, "same-registrable-domain", [
            { adapter: "ct-subdomains", source: "ct-log", query: "crt.sh %." + ctx.domain, host },
            { adapter: "exact-host", host, sourceUrl: res.sourceUrl },
          ], "verified"));
        }
      }
      return items;
    },
  },
  {
    id: "sitemap-hosts",
    standard: "sitemaps.org (+ robots Sitemap:)",
    discovers: "hosts",
    evidenceClass: "publisher-linked",  // reached via the publisher's own sitemap
    canEstablishAuthority: false,
    tier: "balanced",
    external: null,
    async run(ctx) {
      const items = [];
      const sitemaps = [];
      try {
        const robots = await fetchText(ctx.fetchImpl, "https://" + ctx.domain + "/robots.txt", "text/plain", ctx.timeoutMs, ctx.maxBytes);
        ctx.stat.requests++;
        for (const s of parseRobotsSitemaps(robots).slice(0, 2)) sitemaps.push(s);
      } catch { /* fall back to conventional path */ }
      if (!sitemaps.length) sitemaps.push("https://" + ctx.domain + "/sitemap.xml");
      const locs = [];
      for (const sm of sitemaps.slice(0, 2)) {
        try {
          const xml = await fetchText(ctx.fetchImpl, sm, "application/xml,text/xml", ctx.timeoutMs, ctx.maxBytes);
          ctx.stat.requests++;
          for (const l of parseSitemapLocs(xml)) locs.push(l);
        } catch { ctx.stat.skipped.push("sitemap(" + sm + ")"); }
      }
      const hosts = hostsFromLocs(locs, ctx.domain, ctx.caps.sitemapCap);
      for (const host of hosts.slice(0, ctx.caps.hostVerifyCap)) {
        if (ctx.seenHosts.has(host)) continue;  // already covered (e.g. by ct-subdomains)
        const v = await verifyHost(ctx, host);
        ctx.stat.checkedHosts++;
        if (v.status === "unreachable") { ctx.stat.unreachable++; continue; }
        if (v.status === "none") { ctx.stat.reachableEmpty++; continue; }
        for (const res of v.resources) {
          items.push(classify(res, "publisher-linked", [
            { adapter: "sitemap-hosts", source: "sitemap", host },
            { adapter: "exact-host", host, sourceUrl: res.sourceUrl },
          ], "verified"));
        }
      }
      return items;
    },
  },
];

// Introspection: descriptors without the run() closure.
export function adapterInfo() {
  return V2_ADAPTERS.map(({ id, standard, discovers, evidenceClass, canEstablishAuthority, tier, external }) =>
    ({ id, standard, discovers, evidenceClass, canEstablishAuthority, tier, external }));
}

/* -------------------------------- resolveV2 ------------------------------- */

function nowMs() { return Date.now(); }

function orderItems(items) {
  const rank = (c) => { const i = CLASS_ORDER.indexOf(c); return i === -1 ? 999 : i; };
  const hostOf = (it) => (it.provenance.find((p) => p.host) || {}).host || "";
  return items.slice().sort((a, b) =>
    a.level - b.level ||
    rank(a.relationship) - rank(b.relationship) ||
    hostOf(a).localeCompare(hostOf(b)) ||
    String(a.resource.url).localeCompare(String(b.resource.url)));
}

// resolveV2(domain, { tier, fetch, timeoutMs, maxBytes, ctCap, sitemapCap, hostVerifyCap })
//   tier: "fast" (exact-host only) | "balanced" (adds CT + sitemap) | "deep"
//         (not implemented in the alpha; clamps to balanced and discloses it)
// Returns a two-axis result: items[] (grouped by evidence class, deterministic
// within group), plus level1[]/level2[] splits, checked adapters, and stats.
export async function resolveV2(domain, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("no fetch available; pass opts.fetch");
  const d = normalizeDomain(domain);
  if (!d) throw new Error("invalid domain");

  const tier = opts.tier || "fast";
  const truncations = [];
  let wanted;
  if (tier === "fast") wanted = new Set(["fast"]);
  else if (tier === "balanced") wanted = new Set(["fast", "balanced"]);
  else if (tier === "deep") { wanted = new Set(["fast", "balanced"]); truncations.push("deep tier not implemented in alpha; ran balanced"); }
  else throw new Error("unknown tier: " + tier);

  const ctx = {
    domain: d,
    fetchImpl,
    timeoutMs: opts.timeoutMs || 8000,
    maxBytes: opts.maxBytes || 1_000_000,
    caps: {
      ctCap: opts.ctCap ?? 20,
      sitemapCap: opts.sitemapCap ?? 20,
      hostVerifyCap: opts.hostVerifyCap ?? 8,
    },
    seenHosts: new Set([d, "www." + d]),
    stat: { requests: 0, checkedHosts: 0, unreachable: 0, reachableEmpty: 0, skipped: [] },
  };

  const start = nowMs();
  const selected = V2_ADAPTERS.filter((a) => wanted.has(a.tier));
  const raw = [];
  for (const adapter of selected) {          // sequential: later adapters see seenHosts
    try {
      const produced = await adapter.run(ctx);
      for (const it of produced) raw.push(it);
    } catch (e) {
      ctx.stat.skipped.push(adapter.id + "(" + ((e && e.message) || "err") + ")");
    }
  }

  // Dedupe by resource URL; merge provenance; keep the earliest-by-adapter class
  // (exact-host < ct-subdomains < sitemap-hosts), so a resource never appears twice.
  const byUrl = new Map();
  for (const it of raw) {
    const key = it.resource.url + " " + it.resource.source;
    if (!byUrl.has(key)) { byUrl.set(key, it); continue; }
    const kept = byUrl.get(key);
    for (const p of it.provenance) kept.provenance.push(p);
  }
  const items = orderItems([...byUrl.values()]);
  const level1 = items.filter((i) => i.level === 1);
  const level2 = items.filter((i) => i.level === 2);

  return {
    domain: d,
    tier,
    experimental: true,
    charter: CHARTER_STATUS,
    checked: selected.map((a) => a.id),
    items,
    level1,
    level2,
    stats: {
      total: items.length,
      level1: level1.length,
      level2: level2.length,
      verified: items.filter((i) => i.verification === "verified").length,
      requests: ctx.stat.requests,
      checkedHosts: ctx.stat.checkedHosts,
      unreachable: ctx.stat.unreachable,
      reachableEmpty: ctx.stat.reachableEmpty,
      skipped: ctx.stat.skipped,
      ms: nowMs() - start,
    },
    truncations,
  };
}

export default {
  EXPERIMENTAL, CHARTER_STATUS, LEVEL, levelFor, classify,
  isSafeHttpsHost, parseCtNames, parseSitemapLocs, parseRobotsSitemaps, hostsFromLocs,
  V2_ADAPTERS, adapterInfo, resolveV2,
};
