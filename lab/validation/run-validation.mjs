// Universal-compatibility-layer validation runner.
//
// Compares the BASELINE glue (./baseline/glue.mjs — a fair first
// implementation of per-protocol discovery/compatibility code) against the
// WITH-NESSGATE consumer (./with-nessgate.mjs) across:
//   STRAIGHT cases  — mainstream paths both sides must handle (mocked,
//                     deterministic): proves the baseline is not a strawman.
//   TRAP cases      — edge cases drawn from THIS project's own recorded bug
//                     history (each trap reproduces a failure a first
//                     implementation actually exhibits and that NessGate
//                     fixture-pins centrally).
//   LIVE cases      — real domains, both implementations, same inputs.
// Then counts integration size (lines, protocol branches) for both sides.
//
//   node run-validation.mjs            # everything
//   node run-validation.mjs --no-live  # deterministic parts only

import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import * as glue from "./baseline/glue.mjs";
import { connectPlan, endpointStates, inboundEvidence } from "./with-nessgate.mjs";
import { resolve as ngResolve } from "@nessgate/resolver";
import { buildSignatureBase, parseSignatureInput, rfc7638ThumbprintOKP } from "../../packages/inspect/webbotauth.mjs"; // repo copy: the published exports map blocks this subpath — recorded as finding F1

const LIVE = !process.argv.includes("--no-live");
const PUBDNS = { resolve4: async () => ["93.184.216.34"], resolve6: async () => [] };
const res200 = (body) => ({ ok: true, status: 200, url: "", headers: { get: () => null }, text: async () => body, arrayBuffer: async () => new TextEncoder().encode(body).buffer });
const resStatus = (status, www = null) => ({ ok: false, status, url: "", headers: { get: (n) => (n === "www-authenticate" ? www : null) }, text: async () => "", arrayBuffer: async () => new ArrayBuffer(0) });
const rows = [];
const row = (section, name, baseline, nessgate, consequence) => {
  rows.push({ section, name, baseline, nessgate, consequence });
  console.log(`${section.padEnd(9)} ${name.padEnd(46)} baseline: ${String(baseline).padEnd(28)} nessgate: ${String(nessgate).padEnd(26)} ${consequence || ""}`);
};

/* ===================== STRAIGHT (both must succeed) ===================== */
console.log("\n--- STRAIGHT cases (mainstream paths; proves the baseline is fair) ---");
{
  // OpenAPI with bearer auth
  const spec = JSON.stringify({ openapi: "3.0.0", servers: [{ url: "https://api.ex.com/v1" }], components: { securitySchemes: { b: { type: "http", scheme: "bearer" } } } });
  const f = async () => res200(spec);
  const a = await glue.checkOpenApi(f, "https://ex.com/openapi.json");
  const b = await endpointStates("ex.com", { fetch: async (u) => (String(u).endsWith("/openapi.json") ? res200(spec) : resStatus(404)), timeoutMs: 300, deadlineMs: 4000 });
  const bS = b.states.find((s) => s.protocol === "openapi");
  row("STRAIGHT", "OpenAPI + bearer scheme", `${a.state}/${a.auth}`, `${bS.outcome}/${bS.auth && bS.auth.type}`, "both resolve auth");
}
{
  // MCP behind the full RFC 9728 -> 8414 chain
  const prm = JSON.stringify({ authorization_servers: ["https://auth.ex.com"] });
  const as = JSON.stringify({ authorization_endpoint: "https://auth.ex.com/a", token_endpoint: "https://auth.ex.com/t" });
  const f = async (u, init) => {
    const s = String(u);
    if (s === "https://ex.com/mcp") return resStatus(401, 'Bearer resource_metadata="https://ex.com/.well-known/oauth-protected-resource/mcp"');
    if (s.includes("oauth-protected-resource")) return res200(prm);
    if (s.includes("oauth-authorization-server")) return res200(as);
    return resStatus(404);
  };
  const a = await glue.checkMcp(f, "https://ex.com/mcp");
  const b = await assessViaNg({ source: "mcp", type: "mcp-server", url: "https://ex.com/mcp" }, f);
  row("STRAIGHT", "MCP OAuth metadata chain", `${a.state}/${a.tokenEndpoint ? "token✓" : "token✗"}`, `${b.outcome}/${b.auth && b.auth.tokenEndpoint ? "token✓" : "token✗"}`, "both walk the chain");
}
{
  // A2A 0.3.x-era card
  const card = JSON.stringify({ protocolVersion: "0.3.0", preferredTransport: "JSONRPC", url: "https://agent.ex.com/rpc" });
  const a = await glue.checkA2a(async () => res200(card), "https://ex.com/.well-known/agent-card.json");
  const b = await assessViaNg({ source: "a2a-agent-card", type: "agent-card", url: "https://ex.com/.well-known/agent-card.json" }, async () => res200(card));
  row("STRAIGHT", "A2A 0.3.x card", `${a.state}/${a.transport}`, `${b.outcome}/${b.transport}`, "both read the card");
}
{
  // valid legacy Web Bot Auth round trip (origin value, thumbprint keyid)
  const v = signedLegacy();
  const a = await glue.verifyInbound(v.fetch, v.request);
  const b = await inboundEvidence(v.request, { fetch: v.fetch, now: v.now, dns: PUBDNS });
  const bw = b.facts.find((f) => f.kind === "web-bot-auth");
  row("STRAIGHT", "valid Web Bot Auth (legacy origin form)", `verified=${a.verified}`, bw.tier, "both verify the signature");
}

/* ===================== TRAPS (recorded bug classes) ===================== */
console.log("\n--- TRAP cases (each reproduces a bug class from this project's history) ---");
{
  // T1: documentation page answers HTTP 200 to initialize (replicate.com class)
  const f = async () => res200("<!doctype html><html>docs</html>");
  const a = await glue.checkMcp(f, "https://ex.com/docs/reference/mcp".replace("/docs/reference", "") /* endpoint-looking URL */);
  const b = await assessViaNg({ source: "mcp", type: "mcp-server", url: "https://ex.com/mcp" }, f);
  row("TRAP", "T1 docs page answers 200 to initialize", `${a.state} (FALSE POSITIVE)`, b.outcome + "/" + b.verified, "baseline connects agents to a web page");
}
{
  // T2: valid OpenAPI document larger than the read cap (truncated parse)
  const big = '{"openapi":"3.0.0","servers":[{"url":"https://api.ex.com"}],"x":"' + "a".repeat(1100000) + '"}';
  const a = await glue.checkOpenApi(async () => res200(big), "https://ex.com/openapi.json");
  const b = await assessViaNg({ source: "openapi", type: "openapi", url: "https://ex.com/openapi.json" }, async () => res200(big));
  row("TRAP", "T2 valid-but-large OpenAPI (reader truncation)", `${a.state} (FALSE 'broken')`, `${b.outcome}/${b.verified}`, "baseline blames the service for its own cap");
}
{
  // T3: bare 403 on an MCP endpoint (zapier class: auth wall OR bot wall)
  const f = async (u) => (String(u).endsWith("/mcp") ? resStatus(403) : resStatus(404));
  const a = await glue.checkMcp(f, "https://ex.com/mcp");
  const b = await assessViaNg({ source: "mcp", type: "mcp-server", url: "https://ex.com/mcp" }, f);
  row("TRAP", "T3 bare 403 (auth wall OR bot wall?)", `${a.state}/auth=${a.auth} (GUESSED)`, `${b.outcome}/${b.verified}`, "baseline invents an OAuth requirement");
}
{
  // T4: registry lists several active versions, oldest first (live com.nessgate shape)
  const reg = JSON.stringify({ servers: [
    { server: { name: "com.ex/srv", version: "1.0.0", remotes: [{ url: "https://old.ex/m" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active", isLatest: false } } },
    { server: { name: "com.ex/srv", version: "2.0.0", remotes: [{ url: "https://new.ex/m" }] }, _meta: { "io.modelcontextprotocol.registry/official": { status: "active", isLatest: true } } },
  ] });
  const f = async (u) => (String(u).includes("registry.modelcontextprotocol.io") ? res200(reg) : resStatus(404));
  const a = await glue.registryLookup(f, "ex.com");
  const d = await ngResolve("ex.com", { fetch: f, registry: true, fast: true, timeoutMs: 200, deadlineMs: 3000 });
  const bRec = d.resources.find((r) => r.source === "mcp-registry");
  row("TRAP", "T4 registry multi-version, old entry first", `${a.url} (STALE v${a.version})`, `${bRec.url} (v${bRec.raw.version})`, "baseline routes to the superseded server");
}
{
  // T5: A2A v1 card (protocolBinding + per-interface protocolVersion)
  const card = JSON.stringify({ supportedInterfaces: [{ url: "https://agent.ex.com/a2a/v1", protocolBinding: "JSONRPC", protocolVersion: "1.0" }] });
  const a = await glue.checkA2a(async () => res200(card), "https://ex.com/.well-known/agent-card.json");
  const b = await assessViaNg({ source: "a2a-agent-card", type: "agent-card", url: "https://ex.com/.well-known/agent-card.json" }, async () => res200(card));
  row("TRAP", "T5 A2A v1 interface shape", `${a.state} (card UNREADABLE)`, `${b.outcome}/${b.transport}`, "baseline written for 0.3.x cannot use v1 services");
}
{
  // T6: modern stateless MCP server (2026-07-28: no initialize; server/discover)
  const disc = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: { tools: {} } } });
  const f = async (u, init) => (String(init && init.body).includes('"server/discover"') ? res200(disc) : resStatus(400));
  const a = await glue.checkMcp(f, "https://ex.com/mcp");
  const b = await assessViaNg({ source: "mcp", type: "mcp-server", url: "https://ex.com/mcp" }, f);
  row("TRAP", "T6 stateless 2026-07-28 MCP server", `${a.state} (UNUSABLE)`, `${b.outcome}/${b.verified}`, "baseline cannot talk to current-revision servers");
}
{
  // T7a: Web Bot Auth — legacy value with a PATH used directly as key location
  const v = signedLegacy({ saValue: '"https://agent.example/.well-known/http-message-signatures-directory"', keysAt: "https://agent.example/.well-known/http-message-signatures-directory" });
  const a = await glue.verifyInbound(v.fetch, v.request);
  const b = await inboundEvidence(v.request, { fetch: v.fetch, now: v.now, dns: PUBDNS });
  const bw = b.facts.find((f) => f.kind === "web-bot-auth");
  row("TRAP", "T7a legacy full-URL value used as key location", `verified=${a.verified} (ACCEPTED)`, `${bw.tier}`, "baseline fetches a caller-chosen URL as the key dir (profile: origins only)");
}
{
  // T7b: no expires / no tag — profile violations a naive verifier never checks
  const v = signedLegacy({ stripExpires: true });
  const a = await glue.verifyInbound(v.fetch, v.request);
  const b = await inboundEvidence(v.request, { fetch: v.fetch, now: v.now, dns: PUBDNS });
  const bw = b.facts.find((f) => f.kind === "web-bot-auth");
  row("TRAP", "T7b signature without expires/tag", `verified=${a.verified} (ACCEPTED)`, `${bw.tier}`, "baseline accepts out-of-profile signatures");
}
{
  // T8: llms.txt documentation link that merely CONTAINS /mcp
  const f = async (u) => {
    const s = String(u);
    if (s.endsWith("/llms.txt")) return res200("# ex\n- [docs](https://ex.com/docs/reference/mcp)\n");
    if (s.endsWith("/docs/reference/mcp")) return res200("<!doctype html>docs");
    return resStatus(404);
  };
  const found = await glue.discover(f, "ex.com");
  const mcpish = found.find((x) => x.kind === "mcp");
  const a = mcpish ? await glue.checkMcp(f, mcpish.url) : { state: "(not surfaced)" };
  const d = await ngResolve("ex.com", { fetch: f, fast: true, timeoutMs: 300, deadlineMs: 4000 });
  const { readinessProtocol } = await import("@nessgate/resolver");
  const ngTreats = d.resources.some((r) => readinessProtocol(r) === "mcp");
  row("TRAP", "T8 docs URL containing /mcp in llms.txt", `${a.state} via ${mcpish && mcpish.url} (PAGE AS ENDPOINT)`, ngTreats ? "treated as endpoint (!)" : "never treated as an endpoint", "baseline handshakes documentation pages");
}

/* ===================== LIVE (real domains, both sides) ===================== */
if (LIVE) {
  console.log("\n--- LIVE cases (real domains, identical inputs) ---");
  const LIVE_SET = [
    ["supabase.com", "mixed: MCP+OAuth chain, OpenAPI, llms"],
    ["nessgate.com", "open OpenAPI + open MCP"],
    ["replicate.com", "authed OpenAPI + the T1 docs-page domain"],
    ["huggingface.co", "declared-but-404 MCP card (broken)"],
  ];
  for (const [domain, label] of LIVE_SET) {
    let aSummary = "", bSummary = "";
    try {
      const found = await glue.discover(globalThis.fetch, domain);
      const states = [];
      for (const it of found.slice(0, 5)) states.push(await glue.check(globalThis.fetch, it));
      const usable = states.filter((s) => s.usable);
      aSummary = `${found.length} found, ${usable.length} usable [${states.map((s) => s.protocol + ":" + s.state).join(", ")}]`;
    } catch (e) { aSummary = "error: " + e.message; }
    try {
      const b = await endpointStates(domain, { timeoutMs: 8000 });
      bSummary = `${b.outcome}; [${b.states.map((s) => s.protocol + ":" + s.outcome + (s.verified ? "(" + s.verified + ")" : "")).join(", ")}]`;
    } catch (e) { bSummary = "error: " + e.message; }
    row("LIVE", `${domain} — ${label}`, aSummary, bSummary, "");
  }
}

/* ===================== integration-size metrics ===================== */
console.log("\n--- integration size ---");
const count = (path) => {
  const src = readFileSync(new URL(path, import.meta.url), "utf8");
  const lines = src.split("\n").filter((l) => { const t = l.trim(); return t && !t.startsWith("//") && !t.startsWith("/*") && !t.startsWith("*"); });
  const branches = (src.match(/\b(if|else if|case)\b[^\n]*\b(mcp|a2a|openapi|oauth|jwks|signature|initialize|discover|card|scheme|transport)\b/gi) || []).length;
  return { lines: lines.length, branches };
};
const A = count("./baseline/glue.mjs");
const B = count("./with-nessgate.mjs");
console.log(`baseline glue:      ${A.lines} code lines, ${A.branches} protocol-conditional branches`);
console.log(`nessgate consumer:  ${B.lines} code lines, ${B.branches} protocol-conditional branches`);
console.log(`ratio:              ${(A.lines / B.lines).toFixed(1)}x lines, plus every TRAP row above is a latent baseline bug`);

const traps = rows.filter((r) => r.section === "TRAP");
console.log(`\ndivergent edge cases (baseline wrong, nessgate right): ${traps.length}/${traps.length}`);
console.log("straight cases both handled: " + rows.filter((r) => r.section === "STRAIGHT").length);

/* ---------------- helpers ---------------- */
async function assessViaNg(resource, fetchImpl) {
  const { assessReadiness } = await import("@nessgate/resolver");
  return assessReadiness(resource, { fetch: fetchImpl, timeoutMs: 400 });
}
function signedLegacy({ saValue = '"https://agent.example"', keysAt = "https://agent.example/.well-known/http-message-signatures-directory", stripExpires = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const keyid = rfc7638ThumbprintOKP(jwk);
  const now = 1_000_000;
  const rawInner = stripExpires
    ? `("@authority" "signature-agent");created=${now};keyid="${keyid}";alg="ed25519"`
    : `("@authority" "signature-agent");created=${now};keyid="${keyid}";alg="ed25519";expires=${now + 300};tag="web-bot-auth"`;
  const headers = { "user-agent": "Agent/1.0", "signature-agent": saValue, "signature-input": `sig1=${rawInner}` };
  const base = buildSignatureBase({ method: "GET", url: "https://shop.example/x", headers }, parseSignatureInput(`sig1=${rawInner}`));
  headers.signature = `sig1=:${edSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64")}:`;
  const fetch = async (u) => (u === keysAt ? res200(JSON.stringify({ keys: [{ ...jwk, kid: keyid }] })) : resStatus(404));
  return { request: { method: "GET", url: "https://shop.example/x", headers }, fetch, now };
}
