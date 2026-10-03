// 50-domain cohort validation (lab tool, network).
// Two modes, same cohort and same report shape:
//   COHORT_BASE=<url>  — GET {BASE}/explore/{domain}?org=1&related=1&readiness=1
//   COHORT_BASE=lib    — @nessgate/resolver directly: resolve() with the
//                        registry/delegate/org options + per-endpoint readiness.
// Reports: found rate, domains with connectable resources, the mcp-ready-without-
// protocol-evidence audit, external-source failures (federatedUnavailable), and
// (lib mode) delegation accounting. Writes last-run-cohort50.json (gitignored).

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const BASE = process.env.COHORT_BASE || "http://localhost:8787";
// Externally-named set (10 positives + 15 empties) + 25 fill (replicate.com included on purpose).
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

const line = (i, domain, outcome, res, connectable, fp, regUnavail, trunc) =>
  console.log(`[${i + 1}/50] ${domain.padEnd(18)} ${String(outcome).padEnd(11)} res=${res} connectable=${connectable}${fp ? "  FP!" : ""}${regUnavail ? "  registry-unavailable" : ""}${trunc ? "  walk-truncated" : ""}`);

async function runHosted() {
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
      const fps = withR.filter((r) => r.readiness.protocol === "mcp" && r.readiness.outcome === "ready" && !r.readiness.version).map((r) => r.readiness.endpoint || r.url);
      rows.push({
        domain, ms: Date.now() - t0, status: res.status, outcome: j.outcome,
        resources: all.length, connectable: connectable.length,
        connectableDetail: connectable.map((r) => `${r.readiness.protocol}:${r.readiness.outcome}@${r.readiness.endpoint || r.url}`),
        fpMcpReadyNoEvidence: fps,
        registryUnavailable: !!(j.federatedUnavailable && j.federatedUnavailable.length),
      });
      line(i, domain, j.outcome, all.length, connectable.length, fps.length, j.federatedUnavailable, false);
    } catch (e) {
      rows.push({ domain, error: String(e && e.message || e) });
      console.log(`[${i + 1}/50] ${domain.padEnd(18)} ERROR ${e && e.message}`);
    }
  }
  return rows;
}

async function runLib() {
  const m = await import("../../packages/resolver/index.mjs");
  const rows = [];
  for (let i = 0; i < COHORT.length; i++) {
    const domain = COHORT[i];
    const t0 = Date.now();
    try {
      const d = await m.resolve(domain, { registry: true, delegate: true, org: true, timeoutMs: 8000, deadlineMs: 20000 });
      const seen = new Set();
      let connectable = 0;
      const detail = [], fps = [];
      for (const res of d.resources) {
        if (!m.readinessProtocol(res) || seen.has(res.url) || seen.size >= 4) continue;
        seen.add(res.url);
        const a = await m.assessReadiness(res, { timeoutMs: 8000 }).catch(() => null);
        if (!a) continue;
        if (["ready", "credentials-required"].includes(a.outcome)) { connectable++; detail.push(`${a.protocol}:${a.outcome}@${a.endpoint || res.url}`); }
        if (a.protocol === "mcp" && a.outcome === "ready" && !a.version) fps.push(a.endpoint || res.url);
      }
      rows.push({
        domain, ms: Date.now() - t0, outcome: d.outcome, resources: d.resources.length,
        connectable, connectableDetail: detail, fpMcpReadyNoEvidence: fps,
        registryUnavailable: !!(d.federatedUnavailable && d.federatedUnavailable.length),
        delegation: d.delegation || null,
      });
      line(i, domain, d.outcome, d.resources.length, connectable, fps.length, d.federatedUnavailable, d.delegation && d.delegation.truncated);
    } catch (e) {
      rows.push({ domain, error: String(e && e.message || e) });
      console.log(`[${i + 1}/50] ${domain.padEnd(18)} ERROR ${e && e.message}`);
    }
  }
  return rows;
}

const rows = BASE === "lib" ? await runLib() : await runHosted();

const ok = rows.filter((r) => !r.error);
const found = ok.filter((r) => r.outcome === "found").length;
const summary = {
  ranAt: new Date().toISOString(), base: BASE, total: rows.length, errors: rows.length - ok.length,
  found, foundRate: Math.round((found / (ok.length || 1)) * 100) + "%",
  domainsWithConnectable: ok.filter((r) => r.connectable > 0).length,
  falsePositives: ok.flatMap((r) => (r.fpMcpReadyNoEvidence || []).map((u) => ({ domain: r.domain, url: u }))),
  registryUnavailableCount: ok.filter((r) => r.registryUnavailable).length,
  walkTruncatedCount: ok.filter((r) => r.delegation && r.delegation.truncated).length,
  rows,
};
writeFileSync(fileURLToPath(new URL("./last-run-cohort50.json", import.meta.url)), JSON.stringify(summary, null, 2));
console.log(`\n===== COHORT-50 (${BASE}) =====`);
console.log(`found: ${found}/${ok.length} (${summary.foundRate})  connectable-domains: ${summary.domainsWithConnectable}  FPs: ${summary.falsePositives.length}  registry-unavailable: ${summary.registryUnavailableCount}  walk-truncated: ${summary.walkTruncatedCount}  errors: ${summary.errors}`);
