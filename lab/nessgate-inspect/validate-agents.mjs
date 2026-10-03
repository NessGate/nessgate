// Real-world validation of NessGate Inspect (lab-only).
//
// Cohort: User-Agent strings built around the REAL, published identifying tokens
// of ~40 known AI agents/robots (plus deliberate controls: real bots NOT in the
// directory, and generic clients). Real crawler/agent requests in the wild today
// carry a User-Agent and little else — no RFC 9421 signature, no agent-card
// pointer — so the main cohort exercises exactly what domain owners actually
// receive. A separate, clearly-labeled SYNTHETIC section exercises the verified
// tier (Web Bot Auth) and the agent-card signal, which the ecosystem has barely
// deployed yet.
//
// For each: what Inspect identifies, the tier reached, provenance, what's unknown,
// and what the RAW request alone reveals. Run: node validate-agents.mjs

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { inspect } from "./inspect.mjs";
import { buildSignatureBase, parseSignatureInput, rfc7638ThumbprintOKP } from "./webbotauth.mjs";

// label, UA. Tokens are the operators' real published identifiers.
const COHORT = [
  ["OpenAI GPTBot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"],
  ["OpenAI ChatGPT-User", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)"],
  ["OpenAI OAI-SearchBot", "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)"],
  ["Anthropic ClaudeBot", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"],
  ["Anthropic Claude-User", "Claude-User/1.0 (+Claude-User@anthropic.com)"],
  ["Anthropic anthropic-ai", "anthropic-ai/1.0"],
  ["Perplexity PerplexityBot", "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"],
  ["Perplexity Perplexity-User", "Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)"],
  ["Google Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"],
  ["Google Google-Extended", "Mozilla/5.0 (compatible; Google-Extended/1.0)"],
  ["Microsoft bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"],
  ["Apple Applebot", "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)"],
  ["Apple Applebot-Extended", "Mozilla/5.0 (compatible; Applebot-Extended/1.0)"],
  ["Amazon Amazonbot", "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)"],
  ["ByteDance Bytespider", "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"],
  ["Meta meta-externalagent", "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"],
  ["Meta FacebookBot", "facebookexternalhit/1.1; FacebookBot"],
  ["Common Crawl CCBot", "CCBot/2.0 (https://commoncrawl.org/faq/)"],
  ["Cohere cohere-ai", "cohere-ai/1.0"],
  ["Cohere training crawler", "cohere-training-data-crawler/1.0"],
  ["DuckDuckGo DuckAssistBot", "Mozilla/5.0 (compatible; DuckAssistBot/1.0; +http://duckduckgo.com/duckassistbot.html)"],
  ["You.com YouBot", "Mozilla/5.0 (compatible; YouBot (+http://www.you.com))"],
  // --- real bots NOT in the directory (controls: should be claimed-only, no attribution) ---
  ["[control] Yandex YandexBot", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"],
  ["[control] Baidu Baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"],
  ["[control] Diffbot", "Mozilla/5.0 (compatible; Diffbot/0.1; +http://www.diffbot.com)"],
  ["[control] Huawei PetalBot", "Mozilla/5.0 (compatible; PetalBot; +https://webmaster.petalsearch.com/site/petalbot)"],
  ["[control] AllenAI AI2Bot", "Mozilla/5.0 (compatible; AI2Bot; +https://www.allenai.org/crawler)"],
  ["[control] Mistral user", "MistralAI-User/1.0"],
  ["[control] Timpibot", "Mozilla/5.0 (compatible; Timpibot/0.9; +http://www.timpi.io)"],
  ["[control] ImagesiftBot", "Mozilla/5.0 (compatible; ImagesiftBot; +https://imagesift.com/about)"],
  // --- generic clients (controls: no bot identity at all) ---
  ["[control] curl", "curl/8.4.0"],
  ["[control] python-requests", "python-requests/2.31.0"],
  ["[control] Scrapy", "Scrapy/2.11 (+https://scrapy.org)"],
  ["[control] headless Chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"],
  ["[control] empty UA", ""],
  ["[control] spoofed Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"], // identical to real — illustrates the spoof problem
];

function rawReveals(ua) {
  // What a domain owner sees from the raw request alone: the bytes. No structure,
  // no operator resolution, no provenance, no spoofability signal.
  return ua ? `User-Agent: ${ua.slice(0, 48)}${ua.length > 48 ? "…" : ""}` : "(no User-Agent header)";
}

const rows = [];
console.log("agent".padEnd(30), "tier".padEnd(22), "operator / note");
console.log("-".repeat(90));
for (const [label, ua] of COHORT) {
  const r = await inspect({ method: "GET", url: "https://example-site.com/page", headers: ua ? { "user-agent": ua } : {} });
  const attr = r.facts.find((f) => f.kind === "public-attribution");
  const topTier = attr ? "directory-attributed" : (r.facts.length ? "claimed" : "unknown");
  const operator = attr ? attr.operator : (r.facts.length ? "(no directory match)" : "(nothing declared)");
  rows.push({ label, ua, topTier, operator, attributed: !!attr, facts: r.facts.length, summary: r.summary });
  console.log(label.padEnd(30), topTier.padEnd(22), operator);
}

// --- SYNTHETIC capability section (clearly labeled; excluded from the real tally) ---
console.log("\n--- SYNTHETIC (illustrates the verified tier the ecosystem has barely deployed) ---");
function signedRequest() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const keyid = rfc7638ThumbprintOKP(jwk);
  const dir = "https://agent.example/.well-known/http-message-signatures-directory";
  const now = Math.floor(Date.now() / 1000);
  const rawInner = `("@authority" "@method" "signature-agent");created=${now};keyid="${keyid}";alg="ed25519";expires=${now + 300};tag="web-bot-auth"`;
  const headers = { "user-agent": "AcmeAgent/1.0", "signature-agent": `"${dir}"`, "signature-input": `sig1=${rawInner}` };
  headers.signature = `sig1=:${edSign(null, Buffer.from(buildSignatureBase({ method: "GET", url: "https://example-site.com/page", headers }, parseSignatureInput(`sig1=${rawInner}`)), "utf8"), privateKey).toString("base64")}:`;
  const fetch = async (u) => (u === dir ? { ok: true, status: 200, text: async () => JSON.stringify({ keys: [{ ...jwk, kid: keyid }] }) } : { ok: false, status: 404, text: async () => "" });
  return { request: { method: "GET", url: "https://example-site.com/page", headers }, fetch, now };
}
{
  const { request, fetch, now } = signedRequest();
  const r = await inspect(request, { fetch, now });
  const wba = r.facts.find((f) => f.kind === "web-bot-auth");
  console.log("Web Bot Auth signed ".padEnd(30), (wba.tier).padEnd(22), `key ${wba.keyid.slice(0, 12)}… bound ${JSON.stringify(wba.boundComponents)}`);
}

// --- aggregate ---
const real = rows.filter((r) => !r.label.includes("[control]"));
const controls = rows.filter((r) => r.label.includes("[control]"));
const attributed = rows.filter((r) => r.attributed).length;
const realAttributed = real.filter((r) => r.attributed).length;
const controlBotsNotInDir = controls.filter((r) => /Bot|spider|Diffbot|Mistral/i.test(r.label) && !r.attributed).length;
console.log("\n================ AGGREGATE ================");
console.log(`cohort: ${rows.length} (${real.length} known-agent entries, ${controls.length} controls)`);
console.log(`directory-attributed:         ${attributed}/${rows.length}  (known-agent entries: ${realAttributed}/${real.length})`);
console.log(`cryptographically-verified (real UA-only requests): 0/${rows.length}  — no request carried a signature`);
console.log(`real bots absent from the directory (coverage gap): ${controlBotsNotInDir}`);
console.log(`generic/empty clients → correctly no attribution: ${controls.filter((r) => !r.attributed && !/Bot|spider|Diffbot|Mistral/i.test(r.label)).length}`);
console.log(`\nNOTE: the two identical "Googlebot" entries (real + spoofed) return IDENTICAL output — Inspect cannot and does not claim to tell them apart from the UA alone; both are directory-attributed + flagged spoofable. Distinguishing them needs verified reverse-DNS or a signature (not yet present in the wild).`);
