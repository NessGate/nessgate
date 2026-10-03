import { readFileSync, writeFileSync } from "node:fs";
let miss = 0;
const rep = (file, pairs) => {
  let s = readFileSync(file, "utf8");
  for (const [a, b, all] of pairs) {
    if (!s.includes(a)) { miss++; console.log("MISS:", file, "::", String(a).slice(0, 64).replace(/\n/g, "\\n")); continue; }
    s = all ? s.split(a).join(b) : s.replace(a, b);
  }
  writeFileSync(file, s);
};

/* ---- 7a. api.html: dual-era introspection + precise storage ---- */
{
  let s = readFileSync("public/api.html", "utf8");
  const a1 = "<code>initialize</code> and <code>tools/list</code> — nothing else, ever.";
  if (!s.includes(a1)) { miss++; console.log("MISS api introspection"); }
  s = s.replace(a1, "<code>initialize</code> (or, for revision-2026-07-28 stateless servers, the revision's required <code>server/discover</code>) and <code>tools/list</code> — nothing else, ever.");
  s = s.split("NessGate stores nothing; every answer is read on demand").join("NessGate stores no discovered domain or resource data; every answer is read on demand");
  s = s.split("<strong>NessGate runs no AI and stores nothing</strong>").join("<strong>NessGate runs no AI and stores no discovered domain or resource data</strong>");
  s = s.split("stores nothing, crawls nothing, guesses no").join("stores no discovered domain or resource data, crawls nothing, guesses no");
  writeFileSync("public/api.html", s);
}
rep("public/blog/state-of-ai-discovery-september-2026.html", [
["stores nothing.</p>", "stores no discovered domain or resource data.</p>"],
]);

/* ---- 7b. inspect package: 0.1.2, precise description, draft-accurate README ---- */
rep("packages/inspect/package.json", [
['"version": "0.1.1"', '"version": "0.1.2"'],
["Observation only: no trust, allow/deny, or scoring decisions; stores nothing; zero dependencies.",
 "Observation only: no trust, allow/deny, or scoring decisions; stores no request, credential, or key data; zero dependencies."],
]);
rep("packages/inspect/README.md", [
["| `cryptographically-verified` | an RFC 9421 (Web Bot Auth) signature validates against the caller's published Ed25519 key, binding this request's covered components. Both `Signature-Agent` forms are read: the current Structured Fields dictionary (`label=\"https://directory\"`, including `;key=` covered members) and the older bare string |",
 "| `cryptographically-verified` | an RFC 9421 signature validates per draft-ietf-webbotauth-httpsig-protocol-00 (verified against its Appendix E.2 test vectors): `Signature-Agent` as a Structured Fields dictionary with `type` semantics (`directory` origins resolved at the well-known path, `jwks_uri` direct; unsupported types ignored, never inferred), the covered `;key=` member driving discovery, keyid required to be the JWK thumbprint, `created`/`expires`/`tag=\"web-bot-auth\"`/`@authority`-or-`@target-uri` enforced, and no redirects followed during key discovery. The legacy bare-string form is accepted for migration |"],
["and verified against the caller's published key. A valid signature",
 "and verified against the caller's published key per the active WG protocol draft. A valid signature"],
]);

/* ---- 7c. sources.json: active WG draft replaces the expired architecture draft ---- */
rep("lab/sources.json", [
['{ "protocol": "web-bot-auth", "kind": "spec-draft", "url": "https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/", "note": "Web Bot Auth architecture draft (IETF); request-signature verification tracks it" }',
 '{ "protocol": "web-bot-auth", "kind": "spec-draft", "url": "https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/", "note": "Web Bot Auth protocol draft (IETF webbotauth WG; supersedes the expired meunier architecture draft); the inspect verifier implements revision -00 and its Appendix E.2 vectors" }'],
]);

/* ---- 4 + 7d. publish-inspect.yml: dispatch-only + drop the OIDC debug step ---- */
{
  let s = readFileSync(".github/workflows/publish-inspect.yml", "utf8");
  const trig = "on:\n  workflow_dispatch:\n  release:\n    types: [published]";
  if (!s.includes(trig)) { miss++; console.log("MISS inspect trigger"); }
  s = s.replace(trig, "# workflow_dispatch ONLY: a GitHub Release must never publish this package as a\n# side effect (releases are resolver-versioned; this already misfired once).\non:\n  workflow_dispatch:");
  const dbgStart = s.indexOf("      - name: Show the OIDC claims");
  const dbgEnd = s.indexOf("      - name: Publish (provenance");
  if (dbgStart < 0 || dbgEnd < 0) { miss++; console.log("MISS debug step"); }
  else s = s.slice(0, dbgStart) + s.slice(dbgEnd);
  writeFileSync(".github/workflows/publish-inspect.yml", s);
}

/* ---- 3. retire the IP-level live-traffic measurement tool ---- */
writeFileSync("lab/nessgate-inspect/validate-live-traffic.mjs",
`// RETIRED (2026-10-03) — do not revive in this form.
//
// This tool pulled (userAgent, clientIP) groups from zone analytics to measure
// Inspect against real traffic. The public privacy policy states that client IP
// addresses are not read or recorded for measurement; that stronger promise
// wins over the experiment, so the tool is disabled rather than the policy
// weakened. Any future validation must be opt-in traffic or non-identifying
// (e.g. User-Agent-only, with no per-IP dimension and no network attribution
// against real client addresses).
console.error("retired: this measurement read client IPs, which the privacy policy rules out; see the header comment");
process.exit(1);
`);

/* ---- 7e. changelog + versions 1.22.0 ---- */
rep("public/changelog.html", [
["<h3 id=\"dual-era-2026-10-03\">Dual-era MCP, library federation, inbound inspection, hardening (1.18.0 → 1.21.0)</h3>\n<ul>",
 `<h3 id="dual-era-2026-10-03">Dual-era MCP, library federation, inbound inspection, hardening (1.18.0 → 1.22.0)</h3>
<ul>
<li><strong>1.22.0 / @nessgate/inspect 0.1.2</strong> — Web Bot Auth verification now implements the IETF
WG protocol draft (draft-ietf-webbotauth-httpsig-protocol-00) and passes its Appendix E.2 test
vectors byte-exact: <code>Signature-Agent</code> parsed as a Structured Fields dictionary with
<code>type</code> semantics (<code>directory</code> origins at the well-known path, <code>jwks_uri</code>;
unsupported types ignored, never inferred), the covered <code>;key=</code> member drives key discovery,
<code>keyid</code> must be the JWK thumbprint, <code>created</code>/<code>expires</code>/<code>tag</code>/
<code>@authority</code>-or-<code>@target-uri</code> enforced before any verified verdict, redirects never
followed during discovery, multiple signatures handled without misattribution. MCP initialize-era
support extends to revision 2025-11-25. Package release triggers separated (a release can no longer
publish the other package as a side effect); an IP-level lab measurement retired in favor of the
privacy policy's stronger wording. (2026-10-03)</li>`],
]);
rep("packages/resolver/package.json", [['"version": "1.21.0"', '"version": "1.22.0"']]);
rep("public/openapi.json", [['"version": "1.21.0"', '"version": "1.22.0"']]);
rep("server.json", [['"version": "1.21.0"', '"version": "1.22.0"']]);
rep("src/worker.js", [['version: "1.21.0" };', 'version: "1.22.0" };']]);

console.log(miss ? miss + " MISSES" : "items 7/3/4 applied; versions 1.22.0 / 0.1.2");
process.exit(miss ? 1 : 0);
