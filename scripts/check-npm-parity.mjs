// Release parity: the code published on npm must be the code in this repo.
// (Found the hard way: 1.4.0 was published the day BEFORE the large-OpenAPI
// fix landed, so library adopters silently lacked the flagship correctness fix.)
//
// Rules, keyed on version comparison between packages/resolver/package.json
// and the npm dist-tag `latest`:
//   equal   -> the published index.mjs must be byte-identical to the repo (FAIL on drift)
//   repo >  -> unpublished release pending: loud warning, but pass (publish is async CI)
//   npm  >  -> repo is BEHIND the registry: FAIL (should never happen)
//
// Dependency-free tar.gz reading (zlib + 512-byte tar headers), like the rest
// of the project. Network required; runs in the `check` chain after smoke.
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const pkg = JSON.parse(readFileSync(root + "packages/resolver/package.json", "utf8"));

function cmpSemver(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  return 0;
}

function tarExtract(buf, wanted) {
  for (let off = 0; off + 512 <= buf.length; ) {
    const name = buf.subarray(off, off + 100).toString("utf8").replace(/\0.*$/, "");
    if (!name) break; // end-of-archive zero blocks
    const size = parseInt(buf.subarray(off + 124, off + 136).toString("utf8").replace(/\0.*$/, "").trim(), 8) || 0;
    if (name === wanted) return buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}

const meta = await (await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg.name).replace("%40", "@")}`)).json();
if (meta.error) { console.error(`FAIL  npm metadata: ${meta.error}`); process.exit(1); }
const latest = meta["dist-tags"].latest;
const cmp = cmpSemver(pkg.version, latest);

if (cmp > 0) {
  console.log(`WARN  ${pkg.name} ${pkg.version} in repo is NOT yet published (npm latest: ${latest}).`);
  console.log(`      Publish it (gh workflow run publish-resolver.yml) — adopters are on the old code until then.`);
  process.exit(0);
}
if (cmp < 0) {
  console.error(`FAIL  repo has ${pkg.version} but npm latest is ${latest} — the repo is behind its own registry.`);
  process.exit(1);
}

const tgz = Buffer.from(await (await fetch(meta.versions[latest].dist.tarball)).arrayBuffer());
const published = tarExtract(gunzipSync(tgz), "package/index.mjs");
if (!published) { console.error("FAIL  package/index.mjs not found in the published tarball"); process.exit(1); }
const local = readFileSync(root + "packages/resolver/index.mjs");
if (!published.equals(local)) {
  console.error(`FAIL  npm ${pkg.name}@${latest} index.mjs differs from the repo at the same version — published code has drifted.`);
  process.exit(1);
}
console.log(`  ok  npm ${pkg.name}@${latest} is byte-identical to the repo library`);
