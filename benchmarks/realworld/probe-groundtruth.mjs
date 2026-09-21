// INDEPENDENT ground-truth prober for the real-world compatibility corpus.
//
// This establishes what each domain ACTUALLY publishes by fetching the raw
// documents directly and validating them with its OWN lightweight checks — it
// imports NOTHING from NessGate's resolver, so the ground truth is never defined
// by NessGate's own output (the whole point of the exercise).
//
// Bounded + safe: HTTPS only, per-fetch timeout + size cap, a descriptive UA,
// and it NEVER tries to circumvent a 403/bot-wall (those are recorded as
// "blocked", not bypassed). No credentials, no auth. Public domains only.
//
//   node benchmarks/realworld/probe-groundtruth.mjs [--only=a.com,b.com] [--concurrency=8]
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const m = a.match(/^--([^=]+)(?:=(.*))?$/); return m ? [m[1], m[2] ?? true] : [a, true]; }));
const VERIFIED_AT = args.date || "2026-09-17"; // stamped; keep deterministic
const CONCURRENCY = Math.max(1, parseInt(args.concurrency, 10) || 8);
const TIMEOUT = 12000, CAP = 512 * 1024;
const UA = "nessgate-corpus-groundtruth/1.0 (+https://nessgate.com; independent benchmark)";

// Candidate domains — deliberately DIVERSE and NOT curated to NessGate's wins:
// AI/dev publishers, plain businesses, news, government, education, retail,
// international, and known stress cases (redirects, bot-walls, large specs).
const CANDIDATES = {
  "ai-dev": ["supabase.com", "stripe.com", "cloudflare.com", "vercel.com", "huggingface.co",
    "anthropic.com", "openai.com", "pinecone.io", "weaviate.io", "clerk.com", "resend.com",
    "mintlify.com", "cursor.com", "replit.com", "railway.app", "render.com", "fly.io",
    "neon.tech", "planetscale.com", "upstash.com", "turso.tech", "elevenlabs.io", "cohere.com",
    "mistral.ai", "modal.com", "together.ai", "deepgram.com", "assemblyai.com", "zapier.com",
    "n8n.io", "retool.com", "posthog.com", "workos.com", "redocly.com", "langchain.com"],
  "dev-docs": ["bun.sh", "deno.com", "astro.build", "svelte.dev", "prisma.io", "tailwindcss.com",
    "python.org", "npmjs.com", "gitlab.com", "apache.org", "kernel.org"],
  "standards": ["modelcontextprotocol.io", "agenticresourcediscovery.org", "ucpchecker.com"],
  "stress": ["perplexity.ai", "gitbook.com", "wordpress.com", "medium.com", "notion.so", "excalidraw.com"],
  "negative-biz": ["walmart.com", "target.com", "homedepot.com", "bestbuy.com", "nike.com",
    "cocacola.com", "toyota.com", "airbnb.com", "booking.com"],
  "negative-news": ["nytimes.com", "bbc.com", "cnn.com", "spiegel.de", "lemonde.fr"],
  "negative-gov-edu": ["whitehouse.gov", "irs.gov", "nasa.gov", "mit.edu", "stanford.edu", "iana.org"],
  "negative-misc": ["wikipedia.org", "reddit.com", "mozilla.org", "example.com", "cloudflare.net"],
  "international": ["baidu.com", "alibaba.com", "rakuten.co.jp", "yandex.ru", "naver.com", "post.dz"],
};

// ---- independent fetch (bounded) ----
async function get(url, { asPrefix = false } = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort("timeout"), TIMEOUT);
  try {
    const r = await fetch(url, { headers: { "user-agent": UA, accept: "*/*" }, redirect: "follow", signal: ac.signal });
    const ct = r.headers.get("content-type") || "";
    const reader = r.body?.getReader();
    let received = 0; const chunks = [];
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.length; chunks.push(value);
        if (received >= CAP) { try { await reader.cancel(); } catch {} break; }
      }
    }
    const buf = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let o = 0; for (const c of chunks) { buf.set(c, o); o += c.length; }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(buf).slice(0, asPrefix ? 65536 : CAP);
    return { status: r.status, finalUrl: r.url, contentType: ct, text };
  } catch (e) {
    return { status: 0, error: String(e && e.message || e).slice(0, 60), text: "", contentType: "" };
  } finally { clearTimeout(timer); }
}

async function dohTxt(name) {
  const r = await get(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`);
  if (r.status !== 200) return [];
  try { const j = JSON.parse(r.text); return (j.Answer || []).map((a) => String(a.data || "").replace(/^"|"$/g, "")); }
  catch { return []; }
}

// ---- independent validators (human-judgment shape checks; NOT NessGate's) ----
const looksHtml = (t) => /^\s*(<!doctype html|<html[\s>]|<\?xml|<rss)/i.test(t.slice(0, 400));
const parse = (t) => { try { return JSON.parse(t); } catch { return undefined; } };

// openapi: detect the version marker in the document HEAD without full-parsing a
// possibly multi-MB spec (a human inspecting the top of the file sees it too).
// This corrects an earlier prober bug where JSON.parse of a truncated large-spec
// prefix failed, wrongly recording NO openapi on real large specs.
function openApiHead(text) {
  const m = text.slice(0, 8192).match(/"(openapi|swagger)"\s*:\s*"([0-9][0-9.]*)"/);
  return m ? { version: m[2] } : null;
}

function validateJson(protocol, text) {
  const o = parse(text);
  if (o === undefined || o === null || typeof o !== "object") return null;
  switch (protocol) {
    case "ard-catalog": return Array.isArray(o.entries) ? { version: o.specVersion || "0.91" } : null;
    case "a2a-agent-card": return (o.name && (o.url || Array.isArray(o.supportedInterfaces) || Array.isArray(o.endpoints) || Array.isArray(o.endPoints))) ? { version: o.protocolVersion || "1.0" } : null;
    case "api-catalog": return Array.isArray(o.linkset) ? { version: "rfc9727" } : null;
    case "ai-info.json": return { version: "draft" };
    case "openapi": return (o.openapi || o.swagger) ? { version: String(o.openapi || o.swagger) } : null;
    case "ord": return (o.openResourceDiscoveryV1 || o.openResourceDiscovery || o.$schema && /open-resource-discovery/i.test(String(o.$schema))) ? { version: "1" } : null;
    case "awp": return (o.protocols && typeof o.protocols === "object") ? { version: "draft" } : null;
    case "host-meta": return Array.isArray(o.links) ? { version: "rfc6415" } : null;
    case "anp": return (Array.isArray(o.items) || /CollectionPage/i.test(String(o["@type"] || ""))) ? { version: "draft" } : null;
    case "ucp": return (o.ucp_version || Array.isArray(o.capabilities)) ? { version: o.ucp_version || "draft" } : null;
    default: return null;
  }
}

// Each standard: paths to probe (independently) + kind.
const STANDARDS = [
  { protocol: "llms.txt", kind: "text", paths: ["/llms.txt"] },
  { protocol: "ard-catalog", kind: "json", paths: ["/.well-known/ard.json", "/.well-known/ai-catalog.json"] },
  { protocol: "a2a-agent-card", kind: "json", paths: ["/.well-known/agent-card.json", "/.well-known/agent.json"] },
  { protocol: "api-catalog", kind: "json", paths: ["/.well-known/api-catalog"] },
  { protocol: "ai-info.json", kind: "json", paths: ["/ai-info.json"] },
  { protocol: "openapi", kind: "json-prefix", paths: ["/openapi.json"] },
  { protocol: "ord", kind: "json", paths: ["/.well-known/open-resource-discovery"] },
  { protocol: "awp", kind: "json", paths: ["/.well-known/awp.json"] },
  { protocol: "host-meta", kind: "json", paths: ["/.well-known/host-meta.json"] },
  { protocol: "anp", kind: "json", paths: ["/.well-known/agent-descriptions"] },
  { protocol: "ucp", kind: "json", paths: ["/.well-known/ucp", "/.well-known/ucp/manifest.json"] },
];

async function probeDomain(domain, category) {
  const groundTruth = [];
  const notes = [];
  let anyBlocked = false, reachable = false;

  // homepage reachability (for link-rel + a reachability signal)
  const home = await get(`https://${domain}/`, { asPrefix: true });
  if (home.status >= 200 && home.status < 400) reachable = true;
  if (home.status === 403 || home.status === 429) { anyBlocked = true; notes.push(`home ${home.status}`); }
  // A thorough inspector follows the homepage to its canonical host (apex →
  // www./about./docs. of the SAME registrable domain) and looks there too —
  // many orgs publish llms.txt/ARD on that host, not the bare apex.
  let canonHost = null;
  try { const h = new URL(home.finalUrl).hostname.toLowerCase().replace(/\.+$/, ""); if (h !== domain && h.endsWith("." + domain)) canonHost = h; } catch {}

  // Probe one (host, standard) and return a GT record or null. No NessGate code.
  async function probeOn(host, std) {
    for (const path of std.paths) {
      const r = await get(`https://${host}${path}`, { asPrefix: std.kind === "json-prefix" });
      if (r.status === 403 || r.status === 429) { anyBlocked = true; continue; }
      if (r.status !== 200) continue;
      const src = `https://${host}${path}`;
      if (std.kind === "text") {
        if (!looksHtml(r.text) && r.text.trim().length > 20) return { protocol: std.protocol, path, sourceUrl: src, host, version: "1.0", verifiedAt: VERIFIED_AT };
        continue;
      }
      if (looksHtml(r.text)) continue; // JSON/openapi path returning an HTML shell = not real
      const v = std.kind === "json-prefix" ? openApiHead(r.text) : validateJson(std.protocol, r.text);
      if (v) return { protocol: std.protocol, path, sourceUrl: src, host, version: v.version, verifiedAt: VERIFIED_AT };
    }
    return null;
  }

  for (const std of STANDARDS) {
    let rec = await probeOn(domain, std);
    // For the surfaces commonly hosted on a canonical subdomain, look there too.
    if (!rec && canonHost && (std.protocol === "llms.txt" || std.protocol === "ard-catalog")) rec = await probeOn(canonHost, std);
    if (rec) groundTruth.push(rec);
  }

  // ARD via <link rel="ard"|"ai-catalog"> in the homepage
  if (home.status === 200 && /<link[^>]+rel=["']?(ard|ai-catalog)["']?[^>]*>/i.test(home.text)) {
    groundTruth.push({ protocol: "ard-link", path: "/", sourceUrl: `https://${domain}/`, version: "0.91", verifiedAt: VERIFIED_AT });
  }
  // ARD via robots.txt Agentmap
  const robots = await get(`https://${domain}/robots.txt`);
  if (robots.status === 200 && /^\s*agentmap:/im.test(robots.text)) {
    groundTruth.push({ protocol: "ard-agentmap", path: "/robots.txt", sourceUrl: `https://${domain}/robots.txt`, version: "0.91", verifiedAt: VERIFIED_AT });
  }
  // AID: TXT record v=aid1 at _agent.<domain>
  const txt = await dohTxt(`_agent.${domain}`);
  if (txt.some((t) => /v=aid1/i.test(t))) {
    groundTruth.push({ protocol: "aid", path: `dns:_agent.${domain}`, sourceUrl: `dns:_agent.${domain}`, version: "aid1", verifiedAt: VERIFIED_AT });
  }

  const protocols = [...new Set(groundTruth.map((g) => g.protocol))];
  let stratum;
  if (anyBlocked && protocols.length === 0) stratum = "blocked";
  else if (protocols.length === 0) stratum = "negative";
  else if (protocols.length === 1) stratum = "single";
  else stratum = "multi";
  return { domain, category, reachable, blocked: anyBlocked, stratum, groundTruthProtocols: protocols, groundTruth, notes };
}

// ---- run with bounded concurrency ----
const only = args.only ? String(args.only).split(",") : null;
const all = Object.entries(CANDIDATES).flatMap(([cat, ds]) => ds.map((d) => [d, cat]));
const list = only ? all.filter(([d]) => only.includes(d)) : all;

const out = [];
let idx = 0;
async function worker() {
  while (idx < list.length) {
    const i = idx++;
    const [domain, category] = list[i];
    try {
      const rec = await probeDomain(domain, category);
      out.push(rec);
      console.log(`[${out.length}/${list.length}] ${domain.padEnd(26)} ${rec.stratum.padEnd(9)} ${rec.groundTruthProtocols.join(",") || "-"}`);
    } catch (e) {
      out.push({ domain, category, error: String(e.message).slice(0, 80) });
      console.log(`[${out.length}/${list.length}] ${domain.padEnd(26)} ERROR ${e.message}`);
    }
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));
out.sort((a, b) => a.domain.localeCompare(b.domain));

const corpus = {
  generatedAt: VERIFIED_AT,
  method: "Independent ground truth: each path fetched directly and validated by this script's own shape checks; NessGate's resolver was NOT consulted. Bounded (HTTPS, 12s timeout, 512KB cap), no bypass of 403/bot-walls, no credentials.",
  totalDomains: out.length,
  domains: out,
};
writeFileSync(join(HERE, "corpus.json"), JSON.stringify(corpus, null, 2) + "\n");
const byStratum = {};
for (const d of out) byStratum[d.stratum || "error"] = (byStratum[d.stratum || "error"] || 0) + 1;
console.log(`\nwrote corpus.json — ${out.length} domains; strata: ${JSON.stringify(byStratum)}`);
