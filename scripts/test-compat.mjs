// Compatibility corpus runner (layer 2: real-world compatibility). Runs every
// compat/fixtures/**/*.json through the resolver's PURE parse/normalize path and
// asserts the expected records — or, for `reject` fixtures, that the document is
// correctly refused (catch-alls / HTML shells / wrong shape). No network.
// Run with `npm run test:compat`. (Layer 1, official schemas/vectors, arrives in M2.)
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validateProbeContent, probeShapeOk, normalizeResources } from "../packages/resolver/index.mjs";
import { levelFor } from "../packages/resolver/v2.mjs";

let failed = 0, ran = 0;
const ok = (c, n) => { ran++; if (c) console.log(`  ok  ${n}`); else { failed++; console.error(`FAIL  ${n}`); } };

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = dir + "/" + e;
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (e.endsWith(".json")) out.push(p);
  }
  return out;
}

const fixturesDir = fileURLToPath(new URL("../compat/fixtures", import.meta.url));
const files = walk(fixturesDir).sort();
console.log(`--- compatibility corpus: ${files.length} fixtures`);

for (const file of files) {
  let fx;
  try { fx = JSON.parse(readFileSync(file, "utf8")); } catch { failed++; console.error(`FAIL  ${file}: unreadable`); continue; }
  const { id, protocol, kind, input, expect } = fx;
  const accepted = validateProbeContent(kind, input.body) && probeShapeOk(protocol, kind, input.body);

  if (expect && expect.reject) {
    ok(!accepted, `${id}: correctly REJECTED (${fx.notes || ""})`);
    continue;
  }

  // positive fixture
  if (!accepted) { failed++; ran++; console.error(`FAIL  ${id}: expected accept but the resolver rejected it`); continue; }
  const got = normalizeResources(protocol, kind, input.body, input.url);
  const want = expect.resources || [];
  if (got.length !== want.length) { failed++; ran++; console.error(`FAIL  ${id}: expected ${want.length} records, got ${got.length}`); continue; }
  let allMatch = true;
  for (const w of want) {
    const g = got.find((r) => r.url === w.url && r.source === w.source) || got[want.indexOf(w)];
    for (const [k, v] of Object.entries(w)) {
      if (JSON.stringify(g && g[k]) !== JSON.stringify(v)) { allMatch = false; console.error(`FAIL  ${id}: field '${k}' = ${JSON.stringify(g && g[k])}, expected ${JSON.stringify(v)}`); break; }
    }
    if (!allMatch) break;
  }
  ok(allMatch, `${id}: normalized records match (${fx.notes || ""})`);
  if (expect.relationship) ok(levelFor(expect.relationship) === expect.level, `${id}: ${expect.relationship} → Level ${expect.level}`);
}

console.log(failed ? `\n${failed} FAILURES (${ran} checks)` : `\nAll ${ran} compatibility checks passed (${files.length} fixtures).`);
process.exit(failed ? 1 : 0);
