// 50-domain cohort validation for the readiness fixes (lab tool, network).
// Runs GET {BASE}/explore/{domain}?org=1&related=1&readiness=1 per domain and reports:
//   - found / none-found rate
//   - domains with genuinely connectable resources (any readiness ready|credentials-required)
//   - readiness false-positive audit: every mcp `ready` MUST carry a protocolVersion
//   - external-source failures (federatedUnavailable)
// BASE via env COHORT_BASE (default http://localhost:8787 = wrangler dev).
// Writes last-run-cohort50.json (gitignored). Usage: node run-cohort50.mjs

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const BASE = process.env.COHORT_BASE || "http://localhost:8787";
// Tester-named (10 successes + 15 empties) + 25 fill (replicate.com included on purpose).
const COHORT = [
  "supabase.com", "railway.app", "fly.io", "airtable.com", "pinecone.io",
  "vercel.com", "runpod.io", "postman.com", "elevenlabs.io", "render.com",
  "openai.com", "anthropic.com", "twilio.com", "datadoghq.com", "neon.tech",
  "groq.com", "langchain.com", "elastic.co", "snowflake.com", "figma.com",
  "canva.com", "discord.com", "segment.com", "stability.ai", "x.ai",
  "replicate.com", "zapier.com", "sentry.io", "linear.app", "notion.so",
  "cloudflare.com", "stripe.com", "huggingface.co", "mintlify.com", "github.com",
  "gitlab.com", "mongodb.com", "redis.io", "docker.com", "deno.com",
  "bun.sh", "astro.build", "svelte.dev", "clerk.com", "resend.com",
  "tailscale.com", "weaviate.io", "perplexity.ai", "replit.com", "modal.com",
];

const rows = [];
for (let i = 0; i < COHORT.length; i++) {
  const domain = COHORT[i];
  const t0 = Date.now();
  try {
    const res = await fetch(`${BASE}/explore/${domain}?org=1&related=1&readiness=1`, { signal: AbortSignal.timeout(90000) });
    const j = await res.json();
    const all = [...(j.resources || []), ...((j.related || []).flatMap((g) => g.resources || []))];
    const withR = all.filter((r) => r.readiness);
    const connectable = withR.filter((r) => ["ready", "credentials-required"].includes(r.readiness.outcome));
    // FP audit: an mcp `ready` without protocol evidence is a false positive.
    const mcpReadyNoEvidence = withR.filter((r) => r.readiness.protocol === "mcp" && r.readiness.outcome === "ready" && !r.readiness.version);
    rows.push({
      domain, ms: Date.now() - t0, status: res.status, outcome: j.outcome,
      resources: all.length, connectable: connectable.length,
      connectableDetail: connectable.map((r) => `${r.readiness.protocol}:${r.readiness.outcome}@${r.readiness.endpoint || r.url}`),
      fpMcpReadyNoEvidence: mcpReadyNoEvidence.map((r) => r.readiness.endpoint || r.url),
      registryUnavailable: !!(j.federatedUnavailable && j.federatedUnavailable.length),
    });
    console.log(`[${i + 1}/50] ${domain.padEnd(18)} ${String(j.outcome).padEnd(11)} res=${all.length} connectable=${connectable.length}${mcpReadyNoEvidence.length ? "  FP!" : ""}${j.federatedUnavailable ? "  registry-unavailable" : ""}`);
  } catch (e) {
    rows.push({ domain, error: String(e && e.message || e) });
    console.log(`[${i + 1}/50] ${domain.padEnd(18)} ERROR ${e && e.message}`);
  }
}

const ok = rows.filter((r) => !r.error);
const found = ok.filter((r) => r.outcome === "found").length;
const summary = {
  ranAt: new Date().toISOString(), base: BASE, total: rows.length, errors: rows.length - ok.length,
  found, foundRate: Math.round((found / (ok.length || 1)) * 100) + "%",
  domainsWithConnectable: ok.filter((r) => r.connectable > 0).length,
  falsePositives: ok.flatMap((r) => (r.fpMcpReadyNoEvidence || []).map((u) => ({ domain: r.domain, url: u }))),
  registryUnavailableCount: ok.filter((r) => r.registryUnavailable).length,
  rows,
};
writeFileSync(fileURLToPath(new URL("./last-run-cohort50.json", import.meta.url)), JSON.stringify(summary, null, 2));
console.log(`\n===== COHORT-50 =====`);
console.log(`found: ${found}/${ok.length} (${summary.foundRate})  connectable-domains: ${summary.domainsWithConnectable}  FPs: ${summary.falsePositives.length}  registry-unavailable: ${summary.registryUnavailableCount}  errors: ${summary.errors}`);
