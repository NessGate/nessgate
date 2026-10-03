// Reproducible demonstration of what NessGate Inspect exposes beyond raw headers.
// Prints the normalized description for (1) a Web Bot Auth signed request and
// (2) a GPTBot User-Agent request. No external network — a mock directory is used
// for the signed case. Run: node demo.mjs
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { inspect } from "../../packages/inspect/inspect.mjs";
import { buildSignatureBase, parseSignatureInput, rfc7638ThumbprintOKP } from "../../packages/inspect/webbotauth.mjs";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" });
const keyid = rfc7638ThumbprintOKP(jwk);
const dir = "https://agent.example/.well-known/http-message-signatures-directory";
const now = Math.floor(Date.now() / 1000);
const rawInner = `("@authority" "@method" "signature-agent");created=${now};keyid="${keyid}";alg="ed25519";expires=${now + 300};tag="web-bot-auth"`;
const signed = { method: "POST", url: "https://shop.example/api/order", headers: { "user-agent": "AcmeShopper/2.1", "signature-agent": `"${dir}"`, "signature-input": `sig1=${rawInner}` } };
signed.headers.signature = `sig1=:${edSign(null, Buffer.from(buildSignatureBase(signed, parseSignatureInput(`sig1=${rawInner}`)), "utf8"), privateKey).toString("base64")}:`;
const fetch = async (u) => (u === dir ? { ok: true, status: 200, text: async () => JSON.stringify({ keys: [{ ...jwk, kid: keyid }] }) } : { ok: false, status: 404, text: async () => "" });

console.log("=== (1) Web Bot Auth signed request ===");
console.log(JSON.stringify(await inspect(signed, { fetch, now }), null, 2));
console.log("\n=== (2) GPTBot User-Agent only ===");
console.log(JSON.stringify(await inspect({ method: "GET", url: "https://shop.example/", headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)" } }), null, 2));
