// Compatibility Lab — anomaly analyzer (offline, deterministic). Reads an
// unseen-benchmark (or discover-failure) results file and clusters anomalies
// into human-reviewable PROPOSALS with fixture skeletons. Reads only; writes
// only under lab/proposals/. No AI, no network, no corpus/resolver change.
//
//   node lab/analyze-failures.mjs benchmarks/unseen-baseline.jsonl
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const [file] = process.argv.slice(2);
if (!file) { console.error("usage: node lab/analyze-failures.mjs <results.jsonl>"); process.exit(1); }
const dir = fileURLToPath(new URL("./", import.meta.url));
const today = new Date().toISOString().slice(0, 10);
const rows = readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

// Clusters: recall misses by protocol, false associations, parser/errors.
const missByProto = {}, falsePos = [], errored = [];
for (const r of rows) {
  for (const p of r.missed || []) (missByProto[p] ||= []).push(r.domain);
  if ((r.falsePositives || []).length) falsePos.push({ domain: r.domain, fp: r.falsePositives });
  if (r.error) errored.push({ domain: r.domain, error: r.error });
}

const proposals = [];
for (const [proto, domains] of Object.entries(missByProto)) {
  proposals.push({
    id: `anomaly-recall-${proto}-${today}`,
    title: `recall miss — ${proto} (${domains.length} domain(s))`,
    body: [
      `# PROPOSAL: recall miss — \`${proto}\``,
      ``,
      `The resolver missed a ground-truth \`${proto}\` surface on: ${domains.join(", ")}.`,
      ``,
      `## Investigation checklist (human)`,
      `- [ ] Fetch the surface directly; is it a size/encoding/redirect/content-type edge case?`,
      `- [ ] Is the miss a parser gap, a probe-shape gap, or a fetch-limit (size/timeout)?`,
      `- [ ] Reproduce as a DOCUMENT-level fixture below (no live domain in the corpus).`,
      ``,
      `## Proposed fixture skeleton — complete + move to \`compat/fixtures/${proto}/<version>/<case>.json\``,
      "```json",
      JSON.stringify({ id: `${proto}/<version>/<case>`, protocol: proto, version: "<version>", kind: "json", origin: "real-world", input: { url: "https://<host>/<surface>", body: "<the exact document that reproduces the miss>" }, expect: { relationship: "publisher-hosted", level: 1, resources: [{ source: proto, type: "<type>", url: "<url>" }] }, notes: "regression for the recall miss on " + domains[0] }, null, 2),
      "```",
      ``,
      `> Per the rule: never fix in code only — land this fixture with the fix. Retire the domain from`,
      `> the holdout and add a fresh unseen one before evaluating.`,
      ``,
    ].join("\n"),
  });
}
if (falsePos.length) proposals.push({
  id: `anomaly-false-assoc-${today}`,
  title: `false associations (${falsePos.length})`,
  body: [`# PROPOSAL: false / noisy associations`, ``, ...falsePos.map((f) => `- ${f.domain}: ${JSON.stringify(f.fp)}`), ``, `## Checklist`, `- [ ] Is each a genuine surface the ground-truth probe missed, or a real false positive?`, `- [ ] If false positive, add a reject fixture reproducing the catch-all; tighten probeShapeOk.`, ``, `> Lab output only.`, ``].join("\n"),
});
if (errored.length) proposals.push({
  id: `anomaly-errors-${today}`,
  title: `parser/resolution errors (${errored.length})`,
  body: [`# PROPOSAL: parser / resolution errors`, ``, ...errored.map((e) => `- ${e.domain}: ${e.error}`), ``, `## Checklist`, `- [ ] Classify: transient (network) vs a resolver bug (timeout/parse).`, `- [ ] For a resolver bug, add a fixture + fix.`, ``, `> Lab output only.`, ``].join("\n"),
});

if (!proposals.length) { console.log(`no anomalies in ${file} — nothing to propose.`); process.exit(0); }
for (const p of proposals) { writeFileSync(dir + "proposals/" + p.id + ".md", p.body); console.log(`  →  proposal: lab/proposals/${p.id}.md — ${p.title}`); }
console.log(`\n${proposals.length} proposal(s) written. Human review required before anything enters compat/ or the resolver.`);
