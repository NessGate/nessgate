// M0.5 — INDEPENDENT ground-truth probe for the unseen-domain holdout.
// Directly fetches each protocol's own surface URLs and applies a MINIMAL,
// self-contained validity check. It does NOT import @nessgate/resolver, so the
// benchmark that later runs the resolver against this ground truth is a fair
// ruler, not a tautology. Output is reviewed by hand before freezing.
//
// Candidate pool is drawn from sources NOT used by cohort A (Tranco) or cohort B
// (public-apis): dev-tool llms.txt adopters, ARD/MCP adopters, and negative /
// blocked controls. The probe records what each domain actually serves; strata
// are assigned after review.
//
// Usage: node benchmarks/probe-groundtruth.mjs <outJsonl>
import { appendFileSync, writeFileSync, existsSync, readFileSync } from "node:fs";

const [outFile] = process.argv.slice(2);
if (!outFile) { console.error("usage: node probe-groundtruth.mjs <outJsonl>"); process.exit(1); }

// Surfaces = each domain's OWN authoritative locations (Level-1 publisher-hosted
// ground truth). [path, kind, protocol-label]. AID (DNS TXT) probed separately.
const SURFACES = [
  ["/llms.txt", "text", "llms.txt"],
  ["/.well-known/ard.json", "json", "ard-catalog"],
  ["/.well-known/ai-catalog.json", "json", "ard-catalog"],
  ["/.well-known/agent-card.json", "json", "a2a-agent-card"],
  ["/.well-known/agent.json", "json", "a2a-agent-card"],
  ["/.well-known/api-catalog", "json", "api-catalog"],
  ["/ai-info.json", "json", "ai-info.json"],
  ["/openapi.json", "json", "openapi"],
  ["/.well-known/open-resource-discovery", "json", "ord"],
  ["/.well-known/awp.json", "json", "awp"],
  ["/.well-known/host-meta.json", "json", "host-meta"],
  ["/.well-known/agent-descriptions", "json", "anp"],
  ["/.well-known/ucp", "json", "ucp"],
  ["/.well-known/ucp/manifest.json", "json", "ucp"],
];

// Independent, minimal validity (deliberately NOT the resolver's probeShapeOk).
function validText(body) {
  if (typeof body !== "string" || !body.trim()) return false;
  let h = body.trimStart();
  for (let i = 0; i < 5 && h.startsWith("<!--"); i++) { const e = h.indexOf("-->"); if (e === -1) return false; h = h.slice(e + 3).trimStart(); }
  return !h.startsWith("<");
}
function validJson(body) { try { const o = JSON.parse(body); return !!o && typeof o === "object"; } catch { return false; } }

const CANDIDATES = [
  // dev-tool llms.txt likely-positives (not in cohorts)
  "supabase.com","vercel.com","elevenlabs.io","fast.ai","mintlify.com","gitbook.com","anthropic.com",
  "perplexity.ai","stripe.com","huggingface.co","zapier.com","replit.com","cursor.com","langchain.com",
  "pinecone.io","weaviate.io","resend.com","clerk.com","tailscale.com","railway.app","fly.io","deno.com",
  "bun.sh","astro.build","svelte.dev","biomejs.dev","turso.tech","upstash.com","neon.tech","hono.dev",
  "prisma.io","trigger.dev","inngest.com","posthog.com","modelcontextprotocol.io",
  // ARD / MCP / multi-protocol adopters
  "nylas.com","ucpchecker.com","synscribe.com","design.dev",
  // negative controls (likely no supported surface)
  "example.com","iana.org","w3.org","gnu.org","fsf.org","berkshirehathaway.com","craigslist.org",
  "un.org","loc.gov","mit.edu","stanford.edu","nps.gov","apache.org","kernel.org","debian.org",
  // legacy / infra (host-meta / older well-knowns sometimes present)
  "github.io","wordpress.com","medium.com","substack.com","notion.so","atlassian.com","gitlab.com",
];

const done = new Set();
if (existsSync(outFile)) { for (const l of readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean)) { try { done.add(JSON.parse(l).domain); } catch {} } }
else writeFileSync(outFile, "");

async function get(url, timeoutMs = 6000) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { redirect: "follow", signal: ctrl.signal, headers: { "User-Agent": "NessGate-GroundTruthProbe/0 (+https://nessgate.com)", Accept: "application/json,text/plain,*/*" } });
    const body = await res.text();
    return { status: res.status, finalUrl: res.url, body };
  } catch (e) { return { status: 0, error: String((e && e.name) || e) }; }
  finally { clearTimeout(t); }
}

async function probe(domain) {
  const found = [];
  let blocked = false, reachable = false;
  // homepage reachability / block signal
  const home = await get("https://" + domain + "/");
  if (home.status === 0) blocked = true;
  else { reachable = true; if (home.status === 403 || home.status === 429 || home.status >= 500) blocked = true; }
  for (const [path, kind, proto] of SURFACES) {
    const r = await get("https://" + domain + path);
    if (r.status === 200) {
      const ok = kind === "json" ? validJson(r.body) : validText(r.body);
      if (ok) found.push({ path, proto, kind, finalUrl: r.finalUrl, bytes: (r.body || "").length });
    } else if (r.status === 403 || r.status === 429) blocked = true;
  }
  // AID (DNS TXT v=aid1 at _agent) via DoH — independent
  let aid = false;
  try {
    const d = await get("https://cloudflare-dns.com/dns-query?name=_agent." + encodeURIComponent(domain) + "&type=TXT&ct=application/dns-json", 6000);
    if (d.status === 200) { const j = JSON.parse(d.body); aid = (j.Answer || []).some((a) => a.type === 16 && /v=aid1/i.test(String(a.data))); }
  } catch {}
  if (aid) found.push({ path: "_agent TXT", proto: "aid", kind: "dns" });
  const protos = [...new Set(found.map((f) => f.proto))];
  return { domain, reachable, blocked, found, protocols: protos, nSurfaces: found.length };
}

const queue = CANDIDATES.filter((d) => !done.has(d));
console.log(`probing ${queue.length} candidates (${done.size} already done)`);
let i = 0;
async function worker() {
  for (;;) {
    const d = queue.shift(); if (!d) return;
    const row = await probe(d);
    appendFileSync(outFile, JSON.stringify(row) + "\n");
    process.stdout.write(`${++i}: ${d} → ${row.blocked ? "BLOCKED " : ""}${row.protocols.join(",") || (row.reachable ? "(none)" : "unreachable")}\n`);
  }
}
await Promise.all([worker(), worker(), worker()]);
console.log("PROBE DONE");
