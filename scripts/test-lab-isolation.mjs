// M5 hard invariant, machine-checked: the Compatibility Lab may only PROPOSE.
// (1) The resolver core, the compatibility corpus code, and the CI gate import
//     NOTHING from lab/ — there is no production/gate dependency on the Lab.
// (2) Lab tools write ONLY under lab/ (proposals + their own snapshot state) and
//     never into compat/, packages/, src/, or public/.
// Run with `npm run test:lab`.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
let failed = 0;
const ok = (c, n) => { if (c) console.log(`  ok  ${n}`); else { failed++; console.error(`FAIL  ${n}`); } };
function walk(dir) { const o = []; for (const e of readdirSync(dir)) { const p = dir + "/" + e; if (statSync(p).isDirectory()) o.push(...walk(p)); else o.push(p); } return o; }

// (1) Nothing production/gate-side imports the Lab.
const guarded = [
  "packages/resolver/index.mjs", "packages/resolver/v2.mjs", "public/resolver.mjs", "src/worker.js",
  ...walk(root + "compat").filter((p) => p.endsWith(".mjs")),
  ...readdirSync(root + "scripts").filter((f) => f.endsWith(".mjs")).map((f) => "scripts/" + f),
].filter((rel, i, a) => a.indexOf(rel) === i);
for (const rel of guarded) {
  const path = rel.startsWith("/") ? rel : root + rel;
  let src; try { src = readFileSync(path, "utf8"); } catch { continue; }
  const importsLab = /\bfrom\s+["'][^"']*\blab\//.test(src) || /\bimport\s*\(\s*["'][^"']*\blab\//.test(src);
  ok(!importsLab, `${rel} does not import from lab/`);
}

// (2) Lab tools write only within lab/ — never into the corpus or resolver.
const labScripts = walk(root + "lab").filter((p) => p.endsWith(".mjs"));
const FORBIDDEN = ["compat/", "packages/", "public/", "src/", "benchmarks/"];
for (const path of labScripts) {
  const src = readFileSync(path, "utf8");
  // find write-call argument regions and check none reference a forbidden dir
  const writeArgs = [...src.matchAll(/\b(?:writeFileSync|appendFileSync|writeFile|createWriteStream|mkdirSync|rmSync|unlinkSync)\s*\(([^;]*?)\)/gs)].map((m) => m[1]);
  const rel = path.slice(root.length);
  let clean = true;
  for (const arg of writeArgs) for (const f of FORBIDDEN) if (arg.includes('"' + f) || arg.includes("'" + f) || arg.includes("/" + f) || arg.includes("`" + f) || arg.includes(f.replace(/\/$/, "") + '"')) clean = false;
  ok(clean, `${rel} writes only within lab/ (no compat/packages/src/public/benchmarks writes)`);
}

console.log(failed ? `\n${failed} LAB-ISOLATION VIOLATIONS` : "\nLab isolation holds: the Lab only proposes; production and the gate never depend on it.");
process.exit(failed ? 1 : 0);
