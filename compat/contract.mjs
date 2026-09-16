// The adapter contract, formalized in code (M4). One place defines what every
// protocol adapter must declare, and validateContract() machine-checks the full
// chain: runtime adapter ↔ manifest ↔ support matrix ↔ fixtures ↔ official
// vectors — authority semantics, versions, surfaces, provenance, deviations, and
// conformance coverage. scripts/test-contract.mjs runs this and fails CI on any
// drift, so "supports X" can never outrun the corpus, and a manifest can never
// silently diverge from the code.

export const REQUIRED_MANIFEST_FIELDS = [
  "id", "channel", "surfaces", "versions", "authority", "canEstablishAuthority",
  "normalizeAs", "provenanceRequired", "officialSuite", "deviations", "fixtures",
];

// Authority classes an adapter may declare, and the two-axis level each implies.
// Kept in sync with the resolver's LEVEL map (passed in) so the contract and the
// classification model cannot diverge.
export const AUTHORITY_LEVEL = { "publisher-hosted": 1 };

// Derive the surfaces an adapter reads directly from the RUNTIME adapter object,
// so a manifest cannot claim surfaces the code does not actually probe.
export function surfacesForAdapter(a) {
  if (a.paths) return a.paths.slice();
  if (a.rels) return [`<link rel=${a.rels.join("|")}>`];
  if (a.directive) return [`robots ${a.directive}:`];
  if (a.node) return [`DNS TXT ${a.node}`];
  return [];
}

// ctx: { ADAPTERS, manifests:{id->manifest}, matrix, fixtures:[...], vendorRels:Set,
//        levelFor(fn), jsonShapeProtocols:Set } → array of violation strings ([] = clean).
export function validateContract(ctx) {
  const { ADAPTERS, manifests, matrix, fixtures, vendorRels, levelFor, jsonShapeProtocols } = ctx;
  const v = [];
  const fixturesByProto = {};
  for (const f of fixtures) (fixturesByProto[f.protocol] ||= []).push(f);

  for (const a of ADAPTERS) {
    const m = manifests[a.id];
    if (!m) { v.push(`adapter '${a.id}': no manifest`); continue; }
    // 1. required fields present
    for (const k of REQUIRED_MANIFEST_FIELDS) if (!(k in m)) v.push(`manifest '${a.id}': missing field '${k}'`);
    // 2. surfaces match the runtime adapter (no drift)
    const expected = surfacesForAdapter(a);
    if (JSON.stringify(m.surfaces) !== JSON.stringify(expected)) v.push(`manifest '${a.id}': surfaces ${JSON.stringify(m.surfaces)} != runtime ${JSON.stringify(expected)}`);
    // 3. channel matches
    if (m.channel !== a.channel) v.push(`manifest '${a.id}': channel '${m.channel}' != runtime '${a.channel}'`);
    // 4. authority ↔ level ↔ canEstablishAuthority consistency
    if (!(m.authority in AUTHORITY_LEVEL)) v.push(`manifest '${a.id}': unknown authority '${m.authority}'`);
    else {
      const lvl = levelFor(m.authority);
      if (lvl !== AUTHORITY_LEVEL[m.authority]) v.push(`manifest '${a.id}': authority '${m.authority}' → resolver level ${lvl}, contract says ${AUTHORITY_LEVEL[m.authority]}`);
      if (m.canEstablishAuthority !== (lvl === 1)) v.push(`manifest '${a.id}': canEstablishAuthority=${m.canEstablishAuthority} inconsistent with level ${lvl}`);
    }
    // 5. provenance is always required
    if (m.provenanceRequired !== true) v.push(`manifest '${a.id}': provenanceRequired must be true`);
    // 6. normalizeAs protocol is in the matrix
    const proto = m.normalizeAs || a.id;
    if (!matrix[proto]) v.push(`manifest '${a.id}': normalizeAs '${proto}' not in matrix`);
    // 7. every declared fixture exists
    for (const fid of m.fixtures || []) if (!fixtures.some((f) => f.id === fid)) v.push(`manifest '${a.id}': fixture '${fid}' does not exist`);
    // 8. officialSuite (if named in the matrix) points at a real vendored dir
    for (const ver of Object.keys(matrix[proto] || {})) {
      const suite = matrix[proto][ver].officialSuite;
      if (suite) {
        const rel = String(suite).split(" ")[0].replace(/^vendor\//, "").replace(/\/$/, "");
        if (![...vendorRels].some((p) => p.startsWith(rel + "/"))) v.push(`matrix ${proto}@${ver}: officialSuite '${suite}' has no files under compat/vendor/${rel}/`);
      }
    }
  }

  // 9. coverage: every JSON-shape-checked protocol must have >=1 positive AND >=1 reject fixture
  for (const proto of jsonShapeProtocols) {
    const fs = fixturesByProto[proto] || [];
    const hasPos = fs.some((f) => !(f.expect && f.expect.reject) && f.detect !== "openapi") || fs.some((f) => f.detect === "openapi" && f.expect && f.expect.ok);
    const hasReject = fs.some((f) => f.expect && f.expect.reject) || fs.some((f) => f.detect === "openapi" && f.expect && f.expect.ok === false);
    if (!hasPos) v.push(`protocol '${proto}': no positive fixture (shape-checked protocols must have one)`);
    if (!hasReject) v.push(`protocol '${proto}': no reject fixture (shape-checked protocols must prove catch-alls are refused)`);
  }

  // 10. every fixture's protocol is known to the matrix (or a gbz alias)
  for (const f of fixtures) if (!matrix[f.protocol] && !(f.id.startsWith("gbz-185-4/") && matrix["gbz-185-4"])) v.push(`fixture '${f.id}': protocol '${f.protocol}' not in matrix`);

  return v;
}
