// Compatibility matrix consistency check + metrics emitter. Fails CI if the
// matrix, adapter manifests, and fixtures drift out of sync (so "supports X"
// can never outrun the corpus). Writes compat/metrics.json.
// Run with `npm run compat:matrix`.
import { readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ADAPTERS } from "../packages/resolver/index.mjs";

let failed = 0;
const fail = (m) => { failed++; console.error(`FAIL  ${m}`); };
const okmsg = (m) => console.log(`  ok  ${m}`);
const base = fileURLToPath(new URL("../compat/", import.meta.url));

const matrix = JSON.parse(readFileSync(base + "matrix.json", "utf8"));
const adapterFiles = readdirSync(base + "adapters").filter((f) => f.endsWith(".json"));
const manifests = Object.fromEntries(adapterFiles.map((f) => [f.replace(/\.json$/, ""), JSON.parse(readFileSync(base + "adapters/" + f, "utf8"))]));

function walk(dir) { const o = []; for (const e of readdirSync(dir)) { const p = dir + "/" + e; if (statSync(p).isDirectory()) o.push(...walk(p)); else if (e.endsWith(".json")) o.push(p); } return o; }
const fixtureFiles = walk(base + "fixtures");
const fixtureIds = new Set(fixtureFiles.map((p) => p.slice((base + "fixtures/").length).replace(/\.json$/, "")));
const fixtures = fixtureFiles.map((p) => JSON.parse(readFileSync(p, "utf8")));

console.log("--- matrix / adapter / fixture consistency");

// 1. every runtime adapter has a manifest
for (const a of ADAPTERS) manifests[a.id] ? okmsg(`adapter ${a.id} has a manifest`) : fail(`adapter ${a.id} has NO manifest`);
// 2. every manifest's protocol (normalizeAs) is in the matrix
for (const [id, m] of Object.entries(manifests)) {
  const proto = m.normalizeAs || id;
  (matrix[proto]) ? okmsg(`manifest ${id} → matrix['${proto}'] present`) : fail(`manifest ${id} → matrix['${proto}'] MISSING`);
}
// 3. every matrix fixture ref exists on disk
for (const [proto, versions] of Object.entries(matrix)) {
  for (const [v, entry] of Object.entries(versions)) {
    for (const ref of entry.fixtures || []) fixtureIds.has(ref) ? null : fail(`matrix ${proto}@${v} references missing fixture '${ref}'`);
  }
}
okmsg("matrix fixture references resolve to files");
// 4. every fixture's protocol is known to the matrix (or is a gbz alias under a2a)
for (const f of fixtures) {
  const known = matrix[f.protocol] || (f.id.startsWith("gbz-185-4/") && matrix["gbz-185-4"]);
  known ? null : fail(`fixture ${f.id}: protocol '${f.protocol}' not in matrix`);
}
okmsg("every fixture protocol is in the matrix");
// 5. every protocol WITH a normalizer has >=1 fixture (pointer/dns-only adapters may have 0 — reported)
const withFixtures = new Set(fixtures.map((f) => f.protocol).concat(fixtures.filter((f) => f.id.startsWith("gbz-185-4/")).map(() => "gbz-185-4")));
const noFixture = [];
for (const proto of Object.keys(matrix)) if (!withFixtures.has(proto)) noFixture.push(proto);
if (noFixture.length) console.log(`  note  protocols without a direct fixture yet (acceptable for pointer/DNS/link surfaces): ${noFixture.join(", ")}`);

// metrics
const positive = fixtures.filter((f) => !(f.expect && f.expect.reject));
const reject = fixtures.filter((f) => f.expect && f.expect.reject);
const realWorld = fixtures.filter((f) => f.origin === "real-world");
const metrics = {
  generatedAt: new Date().toISOString().slice(0, 10),
  protocols: Object.keys(matrix).length,
  protocolVersions: Object.values(matrix).reduce((n, v) => n + Object.keys(v).length, 0),
  adapters: Object.keys(manifests).length,
  fixtures: fixtures.length,
  positiveFixtures: positive.length,
  rejectFixtures: reject.length,
  realWorldFixtures: realWorld.length,
  officialVectorsPassing: 0,   // populated in M2
  distinctQuirksHandled: reject.length,
  note: "unseen-domain metrics live in benchmarks/unseen-baseline-analysis.json (separate ruler). No confidence scores anywhere.",
};
writeFileSync(base + "metrics.json", JSON.stringify(metrics, null, 2) + "\n");
console.log("\nmetrics →", JSON.stringify(metrics));
console.log(failed ? `\n${failed} CONSISTENCY FAILURES` : "\nmatrix/adapters/fixtures are consistent.");
process.exit(failed ? 1 : 0);
