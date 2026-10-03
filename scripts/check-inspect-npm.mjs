// Verifies the published @nessgate/inspect tarball matches the repo byte-for-byte
// (the inspect analogue of check-npm-parity.mjs). Run after any publish:
//   node scripts/check-inspect-npm.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const pkgDir = fileURLToPath(new URL("../packages/inspect/", import.meta.url));
const local = JSON.parse(readFileSync(pkgDir + "package.json", "utf8"));

const meta = await (await fetch("https://registry.npmjs.org/@nessgate%2finspect", { headers: { accept: "application/json" } })).json();
if (meta.error) { console.error(`FAIL  registry: ${meta.error} — @nessgate/inspect is not published yet`); process.exit(1); }
const latest = meta["dist-tags"].latest;
const tarUrl = meta.versions[latest].dist.tarball;
const tar = gunzipSync(Buffer.from(await (await fetch(tarUrl)).arrayBuffer()));

// Minimal tar reader: 512-byte headers, name at 0..100, size octal at 124..136.
const entries = {};
for (let off = 0; off + 512 <= tar.length; ) {
  const name = tar.subarray(off, off + 100).toString("utf8").replace(/\0.*$/, "");
  if (!name) break;
  const size = parseInt(tar.subarray(off + 124, off + 136).toString("utf8").trim(), 8) || 0;
  entries[name.replace(/^package\//, "")] = tar.subarray(off + 512, off + 512 + size);
  off += 512 + Math.ceil(size / 512) * 512;
}

let failed = 0;
const files = ["inspect.mjs", "webbotauth.mjs", "agents.mjs", "agentcard.mjs", "netattr.mjs", "middleware.mjs"];
for (const f of files) {
  const pub = entries[f];
  const loc = readFileSync(pkgDir + f);
  if (pub && Buffer.compare(pub, loc) === 0) console.log(`  ok  ${f} byte-identical`);
  else { failed++; console.error(`FAIL  ${f} ${pub ? "differs from the repo" : "missing from the tarball"}`); }
}
if (latest !== local.version) console.log(`  note published latest is ${latest}; repo package.json says ${local.version}`);
console.log(failed ? `\n${failed} FAILURES` : `\nnpm @nessgate/inspect@${latest} matches the repo.`);
process.exit(failed ? 1 : 0);
