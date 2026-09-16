// Privacy + separation invariant for the anonymous discovery-outcome metric.
// The reviewer's hard requirements, machine-checked:
//  (1) Metrics must never influence resource classification or authority — so the
//      discovery/classification CORE (the resolver library + its byte-twin) must
//      reference nothing about metrics at all.
//  (2) No client IP is read or classified for this feature — the emitter takes no
//      `request`, so it structurally cannot see the caller.
//  (3) Exactly one categorical field is emitted (the outcome), nothing else.
// Run with `npm run test:metrics`.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
let failed = 0;
const ok = (c, n) => { if (c) console.log(`  ok  ${n}`); else { failed++; console.error(`FAIL  ${n}`); } };

// (1) The discovery/classification/authority core carries NO metrics reference.
//     classify()/levelFor() (v2.mjs) and normalizeResources() (index.mjs) live here.
for (const rel of ["packages/resolver/index.mjs", "packages/resolver/v2.mjs", "public/resolver.mjs"]) {
  const src = readFileSync(root + rel, "utf8");
  ok(!/METRICS|writeDataPoint|recordDiscovery/.test(src), `${rel} — classification/authority core references no metrics (cannot be influenced by them)`);
}

const worker = readFileSync(root + "src/worker.js", "utf8");

// (3) writeDataPoint appears exactly once (only inside recordDiscovery).
const writes = (worker.match(/writeDataPoint/g) || []).length;
ok(writes === 1, `src/worker.js emits metrics from exactly one site (got ${writes})`);

// One categorical field only: blobs is [outcome]; no doubles/extra blobs.
ok(/writeDataPoint\(\{\s*indexes:\s*\[outcome\],\s*blobs:\s*\[outcome\]\s*\}\)/.test(worker),
  "the event is a single categorical field (blobs:[outcome]) — no domain, body, or count payload");

// (2) The emitter takes no request and reads no client IP.
ok(/function recordDiscovery\(env, outcome\)/.test(worker),
  "recordDiscovery(env, outcome) takes no request — it has no access to the caller");
// Body only (skip the doc-comment, which legitimately says "request path").
const i = worker.indexOf("function recordDiscovery");
const body = worker.slice(worker.indexOf("{", i), i + 400);
ok(!/cf-connecting-ip|clientIP|headers\.get/i.test(body),
  "recordDiscovery reads no client IP or headers (no identity, no classification of callers)");

console.log(failed ? `\n${failed} METRICS-ISOLATION VIOLATIONS` : "\nMetrics isolation holds: outcome-only, IP-free, and structurally unable to influence classification.");
process.exit(failed ? 1 : 0);
