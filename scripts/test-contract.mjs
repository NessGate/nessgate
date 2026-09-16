// M4 — adapter contract enforcement. Loads the runtime adapters, manifests,
// matrix, fixtures, and vendored official vectors, and machine-checks the full
// chain via compat/contract.mjs. Fails CI on any drift. Run with `npm run test:contract`.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ADAPTERS } from "../packages/resolver/index.mjs";
import { levelFor } from "../packages/resolver/v2.mjs";
import { validateContract } from "../compat/contract.mjs";

const base = fileURLToPath(new URL("../compat/", import.meta.url));
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
function walk(dir) { const o = []; for (const e of readdirSync(dir)) { const p = dir + "/" + e; if (statSync(p).isDirectory()) o.push(...walk(p)); else o.push(p); } return o; }

const matrix = readJson(base + "matrix.json");
const manifests = Object.fromEntries(readdirSync(base + "adapters").filter((f) => f.endsWith(".json")).map((f) => [f.replace(/\.json$/, ""), readJson(base + "adapters/" + f)]));
const fixtures = walk(base + "fixtures").filter((p) => p.endsWith(".json")).map((p) => readJson(p));
const vendorRels = new Set(walk(base + "vendor").map((p) => p.slice((base + "vendor/").length)));

// Protocols whose documents get a real JSON shape check (probeShapeOk) — these
// must carry both a positive and a reject fixture. gbz-185-4 is content-recognized
// within the a2a surface and is exercised via a2a fixtures, so it's excluded here.
const jsonShapeProtocols = new Set(["ard-catalog", "a2a-agent-card", "api-catalog", "awp", "host-meta", "openapi", "anp", "ucp"]);

const violations = validateContract({ ADAPTERS, manifests, matrix, fixtures, vendorRels, levelFor, jsonShapeProtocols });

console.log(`--- adapter contract (${ADAPTERS.length} adapters, ${Object.keys(manifests).length} manifests, ${fixtures.length} fixtures, ${vendorRels.size} vendored files)`);
if (violations.length === 0) {
  console.log("  ok  adapter ↔ manifest ↔ matrix ↔ fixtures ↔ official vectors all consistent");
  console.log("  ok  surfaces, channels, authority↔level, provenance, and conformance coverage enforced");
  console.log("\nAdapter contract holds.");
  process.exit(0);
}
for (const v of violations) console.error(`FAIL  ${v}`);
console.error(`\n${violations.length} CONTRACT VIOLATIONS`);
process.exit(1);
