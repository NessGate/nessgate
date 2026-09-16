// Compatibility Lab — spec/version drift watcher (offline, on-demand). Fetches
// the watched sources in sources.json, hashes each, and compares to the frozen
// spec-snapshots.json. New/changed/removed sources emit a drift PROPOSAL under
// lab/proposals/ (never updates the snapshot automatically, never touches the
// corpus or resolver). Requires network → not part of CI.
//
//   node lab/watch-specs.mjs           # detect drift vs the frozen snapshot
//   node lab/watch-specs.mjs --freeze  # (human, after review) re-freeze the snapshot
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const dir = fileURLToPath(new URL("./", import.meta.url));
const freeze = process.argv.includes("--freeze");
const today = new Date().toISOString().slice(0, 10);
const { sources } = JSON.parse(readFileSync(dir + "sources.json", "utf8"));
const snapPath = dir + "spec-snapshots.json";
const snap = existsSync(snapPath) ? JSON.parse(readFileSync(snapPath, "utf8")) : {};

async function get(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  try {
    const res = await fetch(url, { redirect: "follow", signal: ctrl.signal, headers: { "User-Agent": "NessGate-Lab-SpecWatch/0 (+https://nessgate.com)" } });
    if (!res.ok) return { ok: false, status: res.status };
    const body = await res.text();
    return { ok: true, hash: createHash("sha256").update(body).digest("hex").slice(0, 16), bytes: body.length };
  } catch (e) { return { ok: false, error: String((e && e.name) || e) }; }
  finally { clearTimeout(t); }
}

const next = {};
const drift = [];
for (const s of sources) {
  const key = `${s.protocol}:${s.url}`;
  const r = await get(s.url);
  if (!r.ok) { console.log(`  ??  ${s.protocol}: unreachable (${r.status || r.error}) — ${s.url}`); if (snap[key]) next[key] = snap[key]; continue; }
  next[key] = { hash: r.hash, bytes: r.bytes, seen: today };
  const prev = snap[key];
  if (!prev) { drift.push({ s, kind: "new", r }); console.log(`  NEW ${s.protocol}: ${r.hash} (${r.bytes}b)`); }
  else if (prev.hash !== r.hash) { drift.push({ s, kind: "changed", r, prev }); console.log(`  CHG ${s.protocol}: ${prev.hash} → ${r.hash}`); }
  else console.log(`  ok  ${s.protocol}: unchanged (${r.hash})`);
}
for (const key of Object.keys(snap)) if (!next[key] && sources.some((s) => `${s.protocol}:${s.url}` === key)) next[key] = snap[key];

// Emit drift proposals (unless this is the initial/explicit freeze).
if (!freeze) {
  for (const d of drift) {
    const id = `spec-drift-${d.s.protocol}-${today}`;
    const p = dir + "proposals/" + id + ".md";
    writeFileSync(p, [
      `# PROPOSAL: ${d.kind === "new" ? "new watched source" : "spec drift"} — ${d.s.protocol}`,
      ``,
      `Source: ${d.s.url}`,
      `Kind: ${d.s.kind} · Detected: ${today}`,
      d.kind === "changed" ? `Hash: ${d.prev.hash} → ${d.r.hash} (${d.r.bytes} bytes)` : `Hash: ${d.r.hash} (${d.r.bytes} bytes)`,
      ``,
      `## Suggested review (human)`,
      `- [ ] Read the upstream change; does the protocol/version or its shape change?`,
      `- [ ] If our vendored vector is stale, refresh it under \`compat/vendor/${d.s.protocol}/\` (+ SOURCE.md).`,
      `- [ ] If behavior changes, add/adjust a \`compat/fixtures/${d.s.protocol}/\` case (per the fix⇒fixture rule).`,
      `- [ ] Update \`compat/matrix.json\` versions/deviations if needed.`,
      `- [ ] Run \`npm run check\`; then \`node lab/watch-specs.mjs --freeze\` to re-freeze the snapshot.`,
      ``,
      `> Lab output only. No resolver, corpus, or snapshot change was made automatically.`,
      ``,
    ].join("\n"));
    console.log(`  →   proposal: lab/proposals/${id}.md`);
  }
}

if (freeze) { writeFileSync(snapPath, JSON.stringify(next, null, 2) + "\n"); console.log(`\nsnapshot re-frozen (${Object.keys(next).length} sources).`); }
else if (!drift.length) console.log("\nno drift.");
else console.log(`\n${drift.length} drift proposal(s) written to lab/proposals/. Review, then re-freeze with --freeze.`);
