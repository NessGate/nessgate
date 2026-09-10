// Deploy with an exact build marker so production is provably a specific
// commit. Flow: commit first, then `npm run deploy`, then `npm run check`
// (which verifies /version matches local HEAD).
import { execSync, spawnSync } from "node:child_process";

const sha = execSync("git rev-parse --short HEAD").toString().trim();
if (execSync("git status --porcelain").toString().trim()) {
  console.error("ERROR: working tree has uncommitted changes. Commit first, then deploy.");
  process.exit(1);
}
// Hard pre-deployment gate: the full regression suite must pass locally
// before anything ships. (Deploys run from this machine, not from GitHub,
// so CI alone cannot gate them — this line is the actual gate.)
const t = spawnSync("npm", ["test"], { stdio: "inherit", shell: true });
if (t.status !== 0) {
  console.error("ERROR: regression suite failed. Nothing was deployed.");
  process.exit(1);
}
const build = sha;
console.log("Deploying build", build);

const r = spawnSync("npx", ["wrangler", "deploy", "--var", `BUILD_ID:${build}`], {
  stdio: "inherit",
  shell: true,
});
process.exit(r.status ?? 1);
