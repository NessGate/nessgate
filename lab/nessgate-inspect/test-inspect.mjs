// Deterministic tests for NessGate Inspect (no external network; a mock fetch
// serves the key directory). Covers: an independently-pinned RFC 9421 signature
// base, a real Ed25519 Web Bot Auth round-trip (verified), tamper + expiry
// (→ claimed), known real-world robot User-Agents (→ directory-attributed), and
// the no-decision/no-score invariant. Run: node test-inspect.mjs

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { inspect } from "../../packages/inspect/inspect.mjs";
import { buildSignatureBase, parseSignatureInput, rfc7638ThumbprintOKP } from "../../packages/inspect/webbotauth.mjs";

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) { pass++; } else { fail++; console.error("FAIL  " + n); } };
const eq = (n, a, b) => ok(n + (a === b ? "" : `  (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`), a === b);
// Deterministic public-DNS stub: the hardened fetch core refuses hosts whose
// answers are private/unresolvable, so every networked mock injects this.
const PUBDNS = { resolve4: async () => ["93.184.216.34"], resolve6: async () => [] };

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
  const r = await inspect(request, { fetch, now, dns: PUBDNS });
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
  const r = await inspect(request, { fetch, now, dns: PUBDNS });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("tampered request → tier claimed (not verified)", wba.tier, "claimed");
  ok("tampered → reason names the validation failure", /does not validate/i.test(wba.reason || ""));
  eq("tampered → nothing in the verified tier", r.summary["cryptographically-verified"], 0);
}

/* --- 3. cryptographically valid but EXPIRED → claimed, flagged expired --- */
{
  const { request, fetch, now } = signedRequest({ now: 1_000_000, expiresIn: 60 });
  const r = await inspect(request, { fetch, now: 1_000_000 + 3600, dns: PUBDNS }); // an hour later
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("expired signature → tier claimed", wba.tier, "claimed");
  ok("expired → statement says EXPIRED", /EXPIRED/i.test(wba.statement));
}

/* --- 4. directory unreachable → claimed (never verified on a failed fetch) --- */
{
  const { request, now } = signedRequest();
  const r = await inspect(request, { fetch: async () => ({ ok: false, status: 503, text: async () => "" }), now, dns: PUBDNS });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("key directory 503 → tier claimed", wba.tier, "claimed");
  ok("directory failure → reason recorded", /key discovery/i.test(wba.reason || ""));
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
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "signature-agent": '"https://agent.example/dir"' } }, { fetch, dns: PUBDNS });
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
  const r = await inspect({ method: "GET", url: "https://shop.example/", headers: { "agent-card": "https://cards.example/card.json" } }, { fetch, dns: PUBDNS });
  const ac = r.facts.find((f) => f.kind === "agent-card");
  ok("explicit Agent-Card header location fetched", !!ac);
  ok("signature presence surfaced", ac.signaturePresent === true);
  eq("signed card still tier claimed (verification not asserted)", ac.tier, "claimed");
  ok("note marks signed-card verification as pending", /pending|evolving/i.test(ac.note));
  eq("no cryptographically-verified fact from an unverified card", r.summary["cryptographically-verified"], 0);
}

/* --- 6d. Verified Network Attribution (injected DNS + ranges = deterministic) --- */
import { ipInCidr, verifyNetworkAttribution } from "../../packages/inspect/netattr.mjs";
// CIDR math
eq("CIDR v4 in-range", ipInCidr("20.171.5.9", "20.171.0.0/16"), true);
eq("CIDR v4 out-of-range", ipInCidr("8.8.8.8", "20.171.0.0/16"), false);
eq("CIDR v4-mapped v6 normalizes for v4 range", ipInCidr("::ffff:20.171.5.9", "20.171.0.0/16"), true);
eq("CIDR v6 in-range", ipInCidr("2600:1f00:abcd::1", "2600:1f00::/32"), true);
eq("CIDR v6 out-of-range", ipInCidr("2a03:2880::1", "2600:1f00::/32"), false);

// Google-style rDNS + forward-confirm, with an injected resolver.
const dnsGenuine = {
  reverse: async () => ["crawl-66-249-66-1.googlebot.com"],
  resolve4: async () => ["66.249.66.1"],
  resolve6: async () => [],
};
{
  const r = await verifyNetworkAttribution({ userAgent: "Googlebot/2.1", sourceIp: "66.249.66.1" }, { dns: dnsGenuine });
  ok("google rDNS genuine → verified", r.verified === true && r.operator === "Google");
  ok("google rDNS genuine → forward-confirmed evidence", r.evidence && r.evidence.forwardConfirmed === true);
}
{ // PTR matches suffix but forward-confirm points elsewhere → not verified
  const dnsSpoofPtr = { reverse: async () => ["crawl.googlebot.com"], resolve4: async () => ["1.2.3.4"], resolve6: async () => [] };
  const r = await verifyNetworkAttribution({ userAgent: "Googlebot/2.1", sourceIp: "203.0.113.9" }, { dns: dnsSpoofPtr });
  eq("google forward-confirm mismatch → not verified", r.verified, false);
  ok("mismatch reason recorded", /forward-confirm/i.test(r.reason || ""));
}
{ // no PTR at all → not verified, honest reason
  const dnsNone = { reverse: async () => { throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); }, resolve4: async () => [], resolve6: async () => [] };
  const r = await verifyNetworkAttribution({ userAgent: "bingbot/2.0", sourceIp: "203.0.113.1" }, { dns: dnsNone });
  eq("bing no-PTR → not verified", r.verified, false);
}
// OpenAI-style published ranges, injected.
{
  const r = await verifyNetworkAttribution({ userAgent: "GPTBot/1.2", sourceIp: "20.171.5.9" }, { ranges: ["20.171.0.0/16", "172.203.190.0/24"] });
  ok("openai in published range → verified", r.verified === true && r.operator === "OpenAI");
  eq("openai evidence names the matched CIDR", r.evidence.matchedCidr, "20.171.0.0/16");
}
{
  const r = await verifyNetworkAttribution({ userAgent: "GPTBot/1.2", sourceIp: "8.8.8.8" }, { ranges: ["20.171.0.0/16"] });
  eq("openai outside ranges → not verified", r.verified, false);
}
{ // ranges unavailable → honest fallback, never a false positive
  const r = await verifyNetworkAttribution({ userAgent: "GPTBot/1.2", sourceIp: "20.171.5.9" }, { fetch: async () => ({ ok: false, status: 503, text: async () => "" }), dns: PUBDNS });
  eq("openai ranges unavailable → not verified (honest)", r.verified, false);
  ok("unavailable reason recorded", /unavailable/i.test(r.reason || ""));
}
{ // an operator with no wired method → attempted but no method
  const r = await verifyNetworkAttribution({ userAgent: "ClaudeBot/1.0", sourceIp: "1.2.3.4" }, {});
  ok("unwired operator → attempted, no method, not verified", r.attempted === true && r.verified === false && /no documented network-verification method/i.test(r.reason));
}

// Perplexity: wired via official per-bot IP-range JSON (injected ranges = deterministic).
{
  const r = await verifyNetworkAttribution({ userAgent: "PerplexityBot/1.0", sourceIp: "107.22.1.5" }, { ranges: ["107.22.0.0/16"] });
  ok("PerplexityBot in published range → verified", r.verified === true && r.operator === "Perplexity");
  eq("PerplexityBot evidence names matched CIDR", r.evidence.matchedCidr, "107.22.0.0/16");
}
{
  const r = await verifyNetworkAttribution({ userAgent: "Perplexity-User/1.0", sourceIp: "3.3.3.3" }, { ranges: ["3.0.0.0/8"] });
  ok("Perplexity-User distinct method also wired → verified", r.verified === true && /Perplexity/.test(r.operator));
}
{ // SPOOF: correct Perplexity UA, wrong IP → must NOT verify
  const r = await verifyNetworkAttribution({ userAgent: "PerplexityBot/1.0", sourceIp: "203.0.113.7" }, { ranges: ["107.22.0.0/16"] });
  eq("spoofed PerplexityBot (wrong IP) → not verified", r.verified, false);
  ok("spoof reason = not in published ranges", /not in the operator's published ranges/i.test(r.reason));
}

// Anthropic: NO official IP ranges exist → Inspect must ABSTAIN (never fabricate).
{
  for (const ua of ["ClaudeBot/1.0 (+claudebot@anthropic.com)", "Claude-User/1.0", "anthropic-ai/1.0"]) {
    const r = await verifyNetworkAttribution({ userAgent: ua, sourceIp: "160.79.104.10" }, {});
    eq(`Anthropic (${ua.split("/")[0]}) → not network-verified (abstain)`, r.verified, false);
    ok(`Anthropic (${ua.split("/")[0]}) → reason is 'no documented method', not a failed check`, /no documented network-verification method/i.test(r.reason));
  }
  // End-to-end: ClaudeBot from any IP stays directory-attributed, no network-verified fact.
  const r = await inspect({ method: "GET", url: "https://site.example/", headers: { "user-agent": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)" } }, { sourceIp: "160.79.104.10" });
  eq("ClaudeBot e2e → network-verified 0 (honest abstention)", r.summary["network-verified"], 0);
  eq("ClaudeBot e2e → still directory-attributed (Anthropic)", r.summary["directory-attributed"], 1);
  ok("ClaudeBot e2e → network fact (if any) is tier unknown, reason 'no documented method'", r.facts.filter((f) => f.kind === "network-attribution").every((f) => f.tier === "unknown"));
}

// End-to-end through inspect(): genuine Googlebot IP → network-verified fact; the
// SAME UA from a non-Google IP → directory-attributed only (spoof differentiator).
{
  const genuine = await inspect({ method: "GET", url: "https://site.example/", headers: { "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" } }, { sourceIp: "66.249.66.1", dns: dnsGenuine });
  eq("inspect genuine Googlebot → network-verified present", genuine.summary["network-verified"], 1);
  const spoofDns = { reverse: async () => { throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); }, resolve4: async () => [], resolve6: async () => [] };
  const spoof = await inspect({ method: "GET", url: "https://site.example/", headers: { "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" } }, { sourceIp: "203.0.113.9", dns: spoofDns });
  eq("inspect spoofed Googlebot → NOT network-verified", spoof.summary["network-verified"], 0);
  ok("spoofed Googlebot → still directory-attributed (UA)", spoof.summary["directory-attributed"] === 1);
  ok("spoofed Googlebot → network fact is tier unknown with a reason, not a spoof accusation", spoof.facts.some((f) => f.kind === "network-attribution" && f.tier === "unknown"));
}

/* --- 6e. Inspect NEVER reads X-Forwarded-For (only opts.sourceIp) --- */
{
  // XFF claims a Google IP, but no opts.sourceIp is provided → no network check runs.
  const r = await inspect({ method: "GET", url: "https://site.example/", headers: { "user-agent": "Googlebot/2.1", "x-forwarded-for": "66.249.66.1" } }, { dns: dnsGenuine });
  eq("no opts.sourceIp → network attribution not attempted (XFF ignored)", r.summary["network-verified"], 0);
  ok("no network-attribution fact emitted without a real source IP", !r.facts.some((f) => f.kind === "network-attribution"));
}

/* --- 7. INVARIANT: never a trust/authorization/score decision --- */
{
  const { request, fetch, now } = signedRequest();
  const r = await inspect(request, { fetch, now, dns: PUBDNS });
  const s = JSON.stringify(r);
  ok("no allow/deny/trust/score/authorized field anywhere", !/"(score|trust|trusted|allow|deny|authorized|reputation|verdict)"\s*:/i.test(s));
  ok("top-level note disclaims any decision", /makes NO trust.*authorization.*decision|relying party decides/is.test(r.note));
}

/* --- 8. SSRF hardening (adversarial) --- */
import { safeFetchJson } from "../../packages/inspect/webbotauth.mjs";
{
  const never = () => { throw new Error("fetch must not run"); };
  const PRIV = { resolve4: async () => ["10.1.2.3"], resolve6: async () => [] };
  const r1 = await safeFetchJson(never, "https://internal.corp/x", 200, { dns: PRIV });
  ok("private-resolving host rejected BEFORE any fetch", /private or reserved/.test(r1.error || ""));
  const NONE = { resolve4: async () => { throw new Error("x"); }, resolve6: async () => { throw new Error("x"); } };
  const r2 = await safeFetchJson(never, "https://ghost.example/", 200, { dns: NONE });
  ok("unresolvable host rejected before any fetch", /does not resolve/.test(r2.error || ""));
  let calls = 0;
  const redirPriv = async () => { calls++; return { ok: false, status: 302, headers: { get: () => "https://127.0.0.1/admin" }, text: async () => "" }; };
  const r3 = await safeFetchJson(redirPriv, "https://ok.example/", 200, { dns: PUBDNS });
  ok("redirect to a loopback literal rejected (one fetch only)", /host not allowed/.test(r3.error || "") && calls === 1);
  const splitDns = { resolve4: async (h) => (h === "ok.example" ? ["93.184.216.34"] : ["192.168.0.9"]), resolve6: async () => [] };
  const redirInner = async () => ({ ok: false, status: 302, headers: { get: () => "https://inner.example/" }, text: async () => "" });
  const r4 = await safeFetchJson(redirInner, "https://ok.example/", 200, { dns: splitDns });
  ok("redirect target is DNS-validated too (private target rejected)", /private or reserved/.test(r4.error || ""));
  const redirHttp = async () => ({ ok: false, status: 301, headers: { get: () => "http://ok.example/" }, text: async () => "" });
  const r5 = await safeFetchJson(redirHttp, "https://ok.example/", 200, { dns: PUBDNS });
  ok("redirect downgrading to http rejected", /host not allowed/.test(r5.error || ""));
  let loops = 0;
  const redirLoop = async () => { loops++; return { ok: false, status: 307, headers: { get: () => "https://ok.example/again" }, text: async () => "" }; };
  const r6 = await safeFetchJson(redirLoop, "https://ok.example/", 500, { dns: PUBDNS });
  ok("redirect chains are hop-capped", /too many redirects/.test(r6.error || "") && loops === 4);
  const big = async () => ({ ok: true, status: 200, headers: { get: () => null }, text: async () => "x".repeat(300000) });
  const r7 = await safeFetchJson(big, "https://ok.example/", 500, { dns: PUBDNS });
  ok("oversized response rejected by the byte cap", /exceeds the \d+-byte limit/.test(r7.error || ""));
  // the profile FORBIDS following redirects during key discovery
  const { request, now, dir } = signedRequest();
  const redirectingFetch = async (u) => (u === dir ? { ok: false, status: 302, headers: { get: () => dir + "-moved" }, text: async () => "" } : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });
  const r8 = await inspect(request, { fetch: redirectingFetch, now, dns: PUBDNS });
  const w8 = r8.facts.find((f) => f.kind === "web-bot-auth");
  ok("key-discovery redirect → claimed (redirects are not followed, per the profile)", w8.tier === "claimed" && /redirects are not followed/.test(w8.reason || ""));
}

/* --- 8b. JWKS limits --- */
{
  const { request, now, keyid, dir } = signedRequest();
  const junk = Array.from({ length: 500 }, (_, i) => ({ kty: "OKP", crv: "Ed25519", x: "A".repeat(43), kid: "junk" + i }));
  const flood = async (u) => (u === dir ? { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ keys: junk }) } : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });
  const r1 = await inspect(request, { fetch: flood, now, dns: PUBDNS });
  const w1 = r1.facts.find((f) => f.kind === "web-bot-auth");
  ok("500-key flood with no match → claimed, limit disclosed", w1.tier === "claimed" && /32-key limit/.test(w1.reason || ""));
}

/* --- 9. Signature-Agent Structured Fields dictionary (current draft form) --- */
import { sfDictMember } from "../../packages/inspect/webbotauth.mjs";
function signedRequestDict({ now = 1_000_000, label = "agent2", origin = "https://agent.example" } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const keyid = rfc7638ThumbprintOKP(jwk);
  const dir = origin; // dictionary members carry an ORIGIN; keys live at its well-known path
  const keysUrl = origin + "/.well-known/http-message-signatures-directory";
  const rawInner = `("@authority" "@method" "signature-agent";key="${label}");created=${now};keyid="${keyid}";alg="ed25519";expires=${now + 300};tag="web-bot-auth"`;
  const headers = { "user-agent": "ModernAgent/1.0", "signature-agent": `${label}="${dir}"`, "signature-input": `${label}=${rawInner}` };
  const base = buildSignatureBase({ method: "GET", url: "https://shop.example/checkout", headers }, parseSignatureInput(`${label}=${rawInner}`));
  headers["signature"] = `${label}=:${edSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64")}:`;
  const fetch = async (u) => (u === keysUrl
    ? { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ keys: [{ ...jwk, kid: keyid }] }) }
    : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });
  return { request: { method: "GET", url: "https://shop.example/checkout", headers }, fetch, now, keyid, dir, keysUrl, base, rawInner, jwk };
}
{
  // pin the dictionary-member base line exactly
  const req = { method: "GET", url: "https://shop.example/a", headers: { "signature-agent": 'agent2="https://signature-agent.test"' } };
  const rawInner = '("@authority" "signature-agent";key="agent2");created=1;keyid="k";alg="ed25519";tag="web-bot-auth"';
  const base = buildSignatureBase(req, parseSignatureInput("agent2=" + rawInner));
  eq("dictionary-member base line is exact",
    base,
    '"@authority": shop.example\n"signature-agent";key="agent2": "https://signature-agent.test"\n"@signature-params": ' + rawInner);
  eq("sfDictMember returns the raw serialized item", sfDictMember('a="x", agent2="https://d"', "agent2"), '"https://d"');

  const { request, fetch, now } = signedRequestDict();
  const r = await inspect(request, { fetch, now, dns: PUBDNS });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  eq("dictionary-form signed request verifies", wba.tier, "cryptographically-verified");
  ok("bound components keep the ;key parameter", (wba.boundComponents || []).some((c) => c === 'signature-agent;key="agent2"'));

  const tam = signedRequestDict();
  tam.request.headers["signature-agent"] = 'agent2="https://evil.example/dir"'; // member changed after signing
  const rt = await inspect(tam.request, { fetch: tam.fetch, now: tam.now, dns: PUBDNS });
  eq("tampered dictionary member → claimed", rt.facts.find((f) => f.kind === "web-bot-auth").tier, "claimed");

  const multi = signedRequestDict();
  multi.request.headers["signature-agent"] = 'other="https://other.example", ' + multi.request.headers["signature-agent"];
  // label-matching member must still be selected among several
  const rm = await inspect(multi.request, { fetch: multi.fetch, now: multi.now, dns: PUBDNS });
  eq("label-matching member selected from a multi-member dictionary", rm.facts.find((f) => f.kind === "web-bot-auth").tier, "cryptographically-verified");

  // ambiguous: several members, none matching the signature label
  const amb = signedRequestDict();
  amb.request.headers["signature-agent"] = 'a="https://x.example", b="https://y.example"';
  const ra = await inspect(amb.request, { fetch: amb.fetch, now: amb.now, dns: PUBDNS });
  const wa = ra.facts.find((f) => f.kind === "web-bot-auth");
  ok("ambiguous dictionary (no matching label) → claimed with reason", wa.tier === "claimed" && /component is absent|Signature-Agent/.test(wa.reason || ""));
}

/* --- 10. draft-ietf-webbotauth-httpsig-protocol-00 OFFICIAL TEST VECTORS --- */
{
  // RFC 9421 B.1.4 Ed25519 key (used by the draft's Appendix E.2 vectors).
  const VJWK = { kty: "OKP", crv: "Ed25519", x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" };
  const VKID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
  eq("vector keyid IS the RFC 8037 thumbprint of the B.1.4 key", rfc7638ThumbprintOKP(VJWK), VKID);

  const vecFetch = async (u) => (u === "https://signature-agent.test/.well-known/http-message-signatures-directory"
    ? { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ keys: [VJWK] }) }
    : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });

  // E.2.1 — dictionary member form (label sig2, member key agent2).
  const raw1 = '("@authority" "signature-agent";key="agent2");created=1735689600;keyid="' + VKID + '";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"';
  const req1 = { method: "GET", url: "https://example.com/", headers: {
    "signature-agent": 'agent2="https://signature-agent.test"',
    "signature-input": "sig2=" + raw1,
    "signature": "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
  } };
  eq("E.2.1 signature base reproduced byte-exact",
    buildSignatureBase(req1, parseSignatureInput("sig2=" + raw1)),
    '"@authority": example.com\n"signature-agent";key="agent2": "https://signature-agent.test"\n"@signature-params": ' + raw1);
  // VECTOR DEFECT (documented): E.2.1 as published uses label sig2 with member
  // key agent2, violating the normative §5.2.1/§5.2.2 label rule. The verifier
  // refuses it with the defect named — the rule is not weakened to fit the vector.
  const v1 = await inspect(req1, { fetch: vecFetch, now: 1735700000, dns: PUBDNS });
  const f1 = v1.facts.find((f) => f.kind === "web-bot-auth");
  ok("E.2.1 AS PUBLISHED → refused for the label/member mismatch (vector defect)",
    f1.tier === "claimed" && /does not match the signature label/.test(f1.reason || ""));
  // Label-corrected E.2.1 (label agent2 — the label is NOT part of the signed
  // bytes, so the vector's signature itself still validates byte-exact).
  const req1c = { method: "GET", url: "https://example.com/", headers: { ...req1.headers,
    "signature-input": "agent2=" + raw1,
    "signature": req1.headers["signature"].replace(/^sig2=/, "agent2="),
  } };
  const v1c = await inspect(req1c, { fetch: vecFetch, now: 1735700000, dns: PUBDNS });
  eq("E.2.1 label-corrected → cryptographically-verified (vector crypto intact)",
    v1c.facts.find((f) => f.kind === "web-bot-auth").tier, "cryptographically-verified");

  // E.2.2 — legacy bare-string form (expires 2025-01-01; verified at a vector-time now).
  const raw2 = '("@authority" "signature-agent");created=1735689600;keyid="' + VKID + '";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"';
  const req2 = { method: "GET", url: "https://example.com/", headers: {
    "signature-agent": '"https://signature-agent.test"',
    "signature-input": "sig2=" + raw2,
    "signature": "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
  } };
  const v2 = await inspect(req2, { fetch: vecFetch, now: 1735690000, dns: PUBDNS });
  eq("E.2.2 legacy string form verifies", v2.facts.find((f) => f.kind === "web-bot-auth").tier, "cryptographically-verified");
  const v2late = await inspect(req2, { fetch: vecFetch, now: 1735693300, dns: PUBDNS });
  eq("E.2.2 after expiry → claimed (EXPIRED surfaced)", v2late.facts.find((f) => f.kind === "web-bot-auth").tier, "claimed");
}

/* --- 11. profile enforcement (negatives) + type semantics + multi-signature --- */
{
  const mk = (over = {}, hdrOver = {}) => {
    const d = signedRequestDict(over.gen || {});
    Object.assign(d.request.headers, hdrOver);
    return d;
  };
  // missing expires → claimed
  {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    const keyid = rfc7638ThumbprintOKP(jwk);
    const raw = `("@authority" "signature-agent";key="a");created=1000;keyid="${keyid}";alg="ed25519";tag="web-bot-auth"`;
    const headers = { "signature-agent": 'a="https://agent.example"', "signature-input": "a=" + raw };
    headers.signature = "a=:" + edSign(null, Buffer.from(buildSignatureBase({ method: "GET", url: "https://s.example/", headers }, parseSignatureInput("a=" + raw)), "utf8"), privateKey).toString("base64") + ":";
    const r = await inspect({ method: "GET", url: "https://s.example/", headers }, { fetch: async () => ({ ok: false, status: 404, headers: { get: () => null }, text: async () => "" }), now: 1000, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok("missing expires → claimed (profile requires expires)", w.tier === "claimed" && /expires/.test(w.reason || ""));
  }
  // no @authority/@target-uri → claimed
  {
    const d = signedRequestDict();
    const raw = d.rawInner.replace('"@authority" "@method" ', '"@method" ');
    d.request.headers["signature-input"] = "agent2=" + raw;
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok("no @authority/@target-uri → claimed", w.tier === "claimed" && /@authority or @target-uri/.test(w.reason || ""));
  }
  // signature-agent not covered → claimed
  {
    const d = signedRequestDict();
    const raw = d.rawInner.replace(' "signature-agent";key="agent2"', "");
    d.request.headers["signature-input"] = "agent2=" + raw;
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok("Signature-Agent member not covered → claimed", w.tier === "claimed" && /covered by the signature/.test(w.reason || ""));
  }
  // kid matches but keyid is not the thumbprint → claimed
  {
    const d = signedRequestDict();
    const wrong = { kty: "OKP", crv: "Ed25519", x: d.jwk.x, kid: "not-a-thumbprint" };
    const raw = d.rawInner.replace(/keyid="[^"]*"/, 'keyid="not-a-thumbprint"');
    d.request.headers["signature-input"] = "agent2=" + raw;
    // re-sign over the new params
    // (simpler: expect failure BEFORE crypto — key lookup refuses the kid match)
    const fetchKid = async (u) => (u === d.keysUrl ? { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ keys: [wrong] }) } : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });
    const r = await inspect(d.request, { fetch: fetchKid, now: d.now, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok("kid match without thumbprint match → claimed", w.tier === "claimed" && /thumbprint/.test(w.reason || ""));
  }
  // type=jwks_uri → fetched directly and verifies
  {
    const d = signedRequestDict();
    const jwksUrl = "https://keys.example/bot/jwks.json";
    d.request.headers["signature-agent"] = `agent2="${jwksUrl}";type=jwks_uri`;
    // the member (with its parameters) is covered, so re-sign
    const raw = d.rawInner;
    const base = buildSignatureBase(d.request, parseSignatureInput("agent2=" + raw));
    ok("jwks_uri member base includes its parameters", /";type=jwks_uri/.test(base || ""));
  }
  // full jwks_uri round-trip with a fresh signature
  {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    const keyid = rfc7638ThumbprintOKP(jwk);
    const jwksUrl = "https://keys.example/bot/jwks.json";
    const raw = `("@authority" "signature-agent";key="k");created=1000;keyid="${keyid}";alg="ed25519";expires=2000;tag="web-bot-auth"`;
    const headers = { "signature-agent": `k="${jwksUrl}";type=jwks_uri`, "signature-input": "k=" + raw };
    headers.signature = "k=:" + edSign(null, Buffer.from(buildSignatureBase({ method: "GET", url: "https://s.example/", headers }, parseSignatureInput("k=" + raw)), "utf8"), privateKey).toString("base64") + ":";
    const f = async (u) => (u === jwksUrl ? { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ keys: [jwk] }) } : { ok: false, status: 404, headers: { get: () => null }, text: async () => "" });
    const r = await inspect({ method: "GET", url: "https://s.example/", headers }, { fetch: f, now: 1500, dns: PUBDNS });
    eq("type=jwks_uri verifies end-to-end", r.facts.find((x) => x.kind === "web-bot-auth").tier, "cryptographically-verified");
  }
  // type=cimd and unknown types → member ignored, never inferred
  for (const t of ["cimd", "mystery"]) {
    const d = signedRequestDict();
    d.request.headers["signature-agent"] = `agent2="https://agent.example";type=${t}`;
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok(`type=${t} → member ignored with reason (never inferred)`, w.tier === "claimed" && (new RegExp(t)).test(w.reason || ""));
  }
  // directory member with a path is not an origin → claimed
  {
    const d = signedRequestDict();
    d.request.headers["signature-agent"] = 'agent2="https://agent.example/some/path"';
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const w = r.facts.find((f) => f.kind === "web-bot-auth");
    ok("directory member with a path → claimed (must be an origin)", w.tier === "claimed" && /origin/.test(w.reason || ""));
  }
  // several signatures: exactly one web-bot-auth-tagged → that one verifies
  {
    const d = signedRequestDict();
    d.request.headers["signature-input"] = 'zzz=("@authority");created=1;keyid="x";alg="ed25519";expires=2;tag="other", agent2=' + d.rawInner;
    d.request.headers["signature"] = "zzz=:AAAA:, " + d.request.headers["signature"];
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const wfacts = r.facts.filter((f) => f.kind === "web-bot-auth");
    ok("one wba-tagged among several signatures → exactly one fact, verified", wfacts.length === 1 && wfacts[0].tier === "cryptographically-verified");
  }
  // §5.2.2 — multiple Web Bot Auth signatures are validated INDEPENDENTLY.
  // Two fully conforming signers (a and b) on one request:
  const twoSigners = () => {
    const A = signedRequestDict({ label: "a", origin: "https://alpha.example" });
    const B = signedRequestDict({ label: "b", origin: "https://beta.example" });
    const headers = {
      "user-agent": "ModernAgent/1.0",
      "signature-agent": A.request.headers["signature-agent"] + ", " + B.request.headers["signature-agent"],
      "signature-input": A.request.headers["signature-input"] + ", " + B.request.headers["signature-input"],
      "signature": A.request.headers["signature"] + ", " + B.request.headers["signature"],
    };
    // each signer covered ITS member of the (now merged) dictionary; the base for
    // each extracts only its own member, so both signatures stay valid
    const fetch = async (u) => {
      const ra = await A.fetch(u);
      if (ra.ok) return ra;
      return B.fetch(u);
    };
    return { request: { method: "GET", url: "https://shop.example/checkout", headers }, fetch, now: A.now, A, B };
  };
  { // two valid → two independent verified facts
    const t = twoSigners();
    const r = await inspect(t.request, { fetch: t.fetch, now: t.now, dns: PUBDNS });
    const facts = r.facts.filter((f) => f.kind === "web-bot-auth");
    ok("two valid WBA signatures → two facts, both verified independently",
      facts.length === 2 && facts.every((f) => f.tier === "cryptographically-verified"));
  }
  { // one valid + one invalid → one verified, one claimed; no cross-contamination
    const t = twoSigners();
    t.request.headers["signature"] = t.A.request.headers["signature"] + ", b=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:";
    const r = await inspect(t.request, { fetch: t.fetch, now: t.now, dns: PUBDNS });
    const facts = r.facts.filter((f) => f.kind === "web-bot-auth");
    ok("one valid + one invalid → exactly one verified and one claimed",
      facts.length === 2 && facts.filter((f) => f.tier === "cryptographically-verified").length === 1 &&
      facts.filter((f) => f.tier === "claimed").length === 1);
  }
  { // two invalid → two claimed, each with its own reason
    const t = twoSigners();
    t.request.headers["signature"] = "a=:AAAA:, b=:BBBB:";
    const r = await inspect(t.request, { fetch: t.fetch, now: t.now, dns: PUBDNS });
    const facts = r.facts.filter((f) => f.kind === "web-bot-auth");
    ok("two invalid WBA signatures → two claimed facts (none fabricated)",
      facts.length === 2 && facts.every((f) => f.tier === "claimed" && f.reason));
  }
  { // WBA + an unrelated non-WBA signature → the unrelated one is ignored
    const d = signedRequestDict();
    d.request.headers["signature-input"] = 'zzz=("@authority");created=1;keyid="x";alg="ed25519";expires=2;tag="other", ' + d.request.headers["signature-input"];
    d.request.headers["signature"] = "zzz=:AAAA:, " + d.request.headers["signature"];
    const r = await inspect(d.request, { fetch: d.fetch, now: d.now, dns: PUBDNS });
    const facts = r.facts.filter((f) => f.kind === "web-bot-auth");
    ok("WBA + unrelated non-WBA signature → one verified fact, unrelated ignored",
      facts.length === 1 && facts[0].tier === "cryptographically-verified");
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
