// Deterministic tests for NessGate Inspect (no external network; a mock fetch
// serves the key directory). Covers: an independently-pinned RFC 9421 signature
// base, a real Ed25519 Web Bot Auth round-trip (verified), tamper + expiry
// (→ claimed), known real-world robot User-Agents (→ directory-attributed), and
// the no-decision/no-score invariant. Run: node test-inspect.mjs

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { inspect } from "./inspect.mjs";
import { buildSignatureBase, parseSignatureInput, rfc7638ThumbprintOKP } from "./webbotauth.mjs";

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) { pass++; } else { fail++; console.error("FAIL  " + n); } };
const eq = (n, a, b) => ok(n + (a === b ? "" : `  (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`), a === b);

/* --- 0. Pin the RFC 9421 base format INDEPENDENTLY of the signer --- */
{
  const req = { method: "GET", url: "https://example.com/a?b=1", headers: { "signature-agent": '"https://agent.example/dir"' } };
  const rawInner = '("@authority" "@method" "signature-agent");created=1000;keyid="kid1";alg="ed25519";expires=2000;tag="web-bot-auth"';
  const parsed = parseSignatureInput(`sig1=${rawInner}`);
  const base = buildSignatureBase(req, parsed);
  const expected =
    '"@authority": example.com\n' +
    '"@method": GET\n' +
    '"signature-agent": "https://agent.example/dir"\n' +
    '"@signature-params": ' + rawInner;
  eq("RFC 9421 signature base is exactly as specified", base, expected);
}

/* --- helper: produce a valid Web Bot Auth signed request + its directory --- */
function signedRequest({ now = 1_000_000, expiresIn = 300, method = "GET", url = "https://shop.example/checkout" } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }); // {kty:"OKP",crv:"Ed25519",x}
  const keyid = rfc7638ThumbprintOKP(jwk);
  const dir = "https://agent.example/.well-known/http-message-signatures-directory";
  const rawInner = `("@authority" "@method" "signature-agent");created=${now};keyid="${keyid}";alg="ed25519";expires=${now + expiresIn};tag="web-bot-auth"`;
  const headers = { "user-agent": "ExampleAgent/1.0", "signature-agent": `"${dir}"`, "signature-input": `sig1=${rawInner}` };
  const base = buildSignatureBase({ method, url, headers }, parseSignatureInput(`sig1=${rawInner}`));
  const b64 = edSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64");
  headers["signature"] = `sig1=:${b64}:`;
  const fetch = async (u) => (u === dir
    ? { ok: true, status: 200, text: async () => JSON.stringify({ keys: [{ ...jwk, kid: keyid }] }) }
    : { ok: false, status: 404, text: async () => "" });
  return { request: { method, url, headers }, fetch, now, keyid, dir };
}

/* --- 1. valid signature → cryptographically-verified --- */
{
  const { request, fetch, now, keyid } = signedRequest();
  const r = await inspect(request, { fetch, now });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("verified signature → tier cryptographically-verified", wba && wba.tier, "cryptographically-verified");
  eq("verified → bound components recorded", JSON.stringify(wba.boundComponents), JSON.stringify(["@authority", "@method", "signature-agent"]));
  eq("verified → keyid surfaced", wba.keyid, keyid);
  ok("verified → note disclaims operator identity & authorization", /does NOT establish who operates|authorization/i.test(wba.note));
  eq("summary counts the verified fact", r.summary["cryptographically-verified"], 1);
}

/* --- 2. tampered request (method changed after signing) → claimed --- */
{
  const { request, fetch, now } = signedRequest();
  request.method = "POST"; // the signature covered @method=GET
  const r = await inspect(request, { fetch, now });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("tampered request → tier claimed (not verified)", wba.tier, "claimed");
  ok("tampered → reason names the validation failure", /does not validate/i.test(wba.reason || ""));
  eq("tampered → nothing in the verified tier", r.summary["cryptographically-verified"], 0);
}

/* --- 3. cryptographically valid but EXPIRED → claimed, flagged expired --- */
{
  const { request, fetch, now } = signedRequest({ now: 1_000_000, expiresIn: 60 });
  const r = await inspect(request, { fetch, now: 1_000_000 + 3600 }); // an hour later
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("expired signature → tier claimed", wba.tier, "claimed");
  ok("expired → statement says EXPIRED", /EXPIRED/i.test(wba.statement));
}

/* --- 4. directory unreachable → claimed (never verified on a failed fetch) --- */
{
  const { request, now } = signedRequest();
  const r = await inspect(request, { fetch: async () => ({ ok: false, status: 503, text: async () => "" }), now });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("key directory 503 → tier claimed", wba.tier, "claimed");
  ok("directory failure → reason recorded", /directory/i.test(wba.reason || ""));
}

/* --- 5. known real-world robots, UA only → directory-attributed + claimed --- */
for (const [ua, operator] of [["Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "OpenAI"],
  ["Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://www.anthropic.com)", "Anthropic"],
  ["Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)", "Perplexity"]]) {
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "user-agent": ua } });
  const attr = r.facts.find((f) => f.kind === "public-attribution");
  ok(`${operator}: UA matched to operator`, attr && attr.operator.startsWith(operator));
  eq(`${operator}: attribution tier is directory-attributed`, attr && attr.tier, "directory-attributed");
  ok(`${operator}: attribution note flags the spoofable header`, /spoofable|does NOT bind/i.test(attr.note));
  eq(`${operator}: no cryptographic verification claimed`, r.summary["cryptographically-verified"], 0);
  ok(`${operator}: User-Agent itself is tier claimed`, r.facts.some((f) => f.kind === "user-agent" && f.tier === "claimed"));
}

/* --- 6. unknown caller (no UA match, no signature) → only a claimed UA --- */
{
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "user-agent": "RandomScraper/9" } });
  ok("unknown UA → no public attribution", !r.facts.some((f) => f.kind === "public-attribution"));
  ok("unknown UA → no verified facts", r.summary["cryptographically-verified"] === 0);
}

/* --- 6b. Agent card: served card → claimed facts + provenance --- */
{
  const card = { name: "Acme Agent", url: "https://api.acme.example/a2a", protocolVersion: "0.3.0", provider: { organization: "Acme Inc", url: "https://acme.example" } };
  const fetch = async (u) => (u === "https://agent.example/.well-known/agent-card.json"
    ? { ok: true, status: 200, url: u, text: async () => JSON.stringify(card) }
    : { ok: false, status: 404, url: u, text: async () => "" });
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "signature-agent": '"https://agent.example/dir"' } }, { fetch });
  const ac = r.facts.find((f) => f.kind === "agent-card");
  ok("agent card fetched from the declared host well-known", !!ac);
  eq("agent card is tier claimed (self-published doc)", ac && ac.tier, "claimed");
  eq("agent card endpoint normalized", ac.declared.endpoint, "https://api.acme.example/a2a");
  eq("agent card provider normalized", ac.declared.provider, "Acme Inc");
  ok("agent card provenance records served host", ac.provenance[0].servedByHost === "agent.example");
  ok("unsigned card note says unsigned", /unsigned/i.test(ac.note));
}

/* --- 6c. Signed card → signature PRESENCE surfaced, NOT asserted verified --- */
{
  const card = { name: "Signed Agent", url: "https://api.acme.example/a2a", protocolVersion: "0.3.0", signatures: [{ protected: "eyJ...", signature: "abc" }] };
  const fetch = async (u) => (u === "https://cards.example/card.json"
    ? { ok: true, status: 200, url: u, text: async () => JSON.stringify(card) }
    : { ok: false, status: 404, url: u, text: async () => "" });
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "agent-card": "https://cards.example/card.json" } }, { fetch });
  const ac = r.facts.find((f) => f.kind === "agent-card");
  ok("explicit Agent-Card header location fetched", !!ac);
  ok("signature presence surfaced", ac.signaturePresent === true);
  eq("signed card still tier claimed (verification not asserted)", ac.tier, "claimed");
  ok("note marks signed-card verification as pending", /pending|evolving/i.test(ac.note));
  eq("no cryptographically-verified fact from an unverified card", r.summary["cryptographically-verified"], 0);
}

/* --- 7. INVARIANT: never a trust/authorization/score decision --- */
{
  const { request, fetch, now } = signedRequest();
  const r = await inspect(request, { fetch, now });
  const s = JSON.stringify(r);
  ok("no allow/deny/trust/score/authorized field anywhere", !/"(score|trust|trusted|allow|deny|authorized|reputation|verdict)"\s*:/i.test(s));
  ok("top-level note disclaims any decision", /makes NO trust.*authorization.*decision|relying party decides/is.test(r.note));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
