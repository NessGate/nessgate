// OpenAPI size-handling tests (the weakness the unseen benchmark found), with
// the hardening pass: Fix 1 (a body that COMPLETES within the cap must be valid
// JSON — a complete-but-malformed doc is rejected even with a marker; only a
// cap-TRUNCATED body may use head-marker detection) and Fix 2 (LITERAL byte cap:
// at most maxBytes of body data are retained). Mock streaming fetch. No network.
import { resolve, detectOpenApi, fetchBounded } from "../packages/resolver/index.mjs";

let failed = 0;
const is = (a, e, n) => { const ok = JSON.stringify(a) === JSON.stringify(e); console[ok ? "log" : "error"](`${ok ? "  ok " : "FAIL"}  ${n}`); if (!ok) { failed++; console.error(`      got ${JSON.stringify(a)} want ${JSON.stringify(e)}`); } };

// Streaming mock: /openapi.json emits `head` then filler up to totalBytes in
// 64KB chunks; records bytes produced. Other paths 404; DoH empty.
function makeFetch(head, totalBytes, contentType) {
  const tracker = { produced: 0, canceled: false };
  const mk = () => {
    const enc = new TextEncoder();
    const headBytes = enc.encode(head);
    let produced = 0;
    const body = new ReadableStream({
      pull(c) {
        if (produced === 0) { c.enqueue(headBytes); produced += headBytes.length; tracker.produced = produced; return; }
        if (produced >= totalBytes) { c.close(); return; }
        const n = Math.min(65536, totalBytes - produced);
        c.enqueue(new Uint8Array(n).fill(120)); produced += n; tracker.produced = produced;
      },
      cancel() { tracker.canceled = true; },
    });
    return { ok: true, status: 200, url: "https://x.com/openapi.json", headers: { get: (h) => (h.toLowerCase() === "content-type" ? contentType : null) }, body };
  };
  const fetch = async (url) => {
    const u = String(url);
    if (u.startsWith("https://cloudflare-dns.com/")) return { ok: true, status: 200, url: u, headers: { get: () => "application/dns-json" }, text: async () => JSON.stringify({ Answer: [] }) };
    if (u === "https://x.com/openapi.json") return mk();
    return { ok: false, status: 404, url: u, headers: { get: () => "" }, text: async () => "" };
  };
  return { fetch, tracker };
}
const oaRes = async (fetch) => ((await resolve("x.com", { fetch, timeoutMs: 4000, maxBytes: 1_000_000 })).resources || []).find((x) => x.source === "openapi");

// single-chunk mock for the literal-cap unit test
const oneChunk = (n) => async () => ({ ok: true, status: 200, url: "x", headers: { get: () => "application/json" }, body: { getReader() { let s = false; return { read: async () => (s ? { done: true } : (s = true, { done: false, value: new Uint8Array(n).fill(120) })), cancel: async () => {} }; } } });

console.log("--- Fix 2: literal byte cap (at most maxBytes retained)");
{
  const r = await fetchBounded(oneChunk(10_000_000), "x", 2000, 65536);
  is(r.text.length, 65536, "10MB single chunk → retains EXACTLY the cap");
  is(r.truncated, true, "flagged truncated (more bytes existed)");
  const c = await fetchBounded(oneChunk(65536), "x", 2000, 65536);
  is(c.truncated, false, "a body ending exactly at the cap is complete, not truncated");
  const u = await fetchBounded(oneChunk(1000), "x", 2000, 65536);
  is(u.truncated === false && u.text.length === 1000, true, "under-cap body read in full, not truncated");
}

console.log("--- Fix 1: complete-within-cap requires valid JSON");
is(detectOpenApi('{"openapi":"3.0.0", ...invalid...}', false).ok, false, "complete malformed + marker → REJECT (not truncated)");
is(detectOpenApi('{"openapi":"3.0.0", ...invalid...}', true).ok, true, "same body but cap-truncated → accept (head marker)");
is(detectOpenApi(JSON.stringify({ openapi: "3.0.0", info: { title: "S" } }), false).ok, true, "small complete valid → accept");

console.log("--- end-to-end via resolve() + streaming mock");
// 1. valid LARGE (10MB): found; read bounded (produced far below 10MB); truncated path.
{
  const head = '{"openapi":"3.0.0","info":{"title":"Big Co API","version":"1"},"paths":{';
  const { fetch, tracker } = makeFetch(head, 10_000_000, "application/json");
  const res = await oaRes(fetch);
  is(!!res && res.name === "Big Co API", true, "large 10MB OpenAPI found, title from head");
  is(tracker.produced < 300_000, true, `stream read bounded (${tracker.produced} bytes, not 10MB)`);
  is(tracker.canceled, true, "stream canceled after the prefix");
}
// 2. oversized / absurd, NO marker → rejected + bounded.
{
  const { fetch, tracker } = makeFetch('{"junk":"', 50_000_000, "application/json");
  is(await oaRes(fetch), undefined, "oversized non-OpenAPI payload not reported");
  is(tracker.produced < 300_000, true, `hostile payload bounded (${tracker.produced} bytes)`);
}
// 3. redirect (post-redirect body) → detected.
{
  const head = '{"openapi":"3.1.0","info":{"title":"Redirected API"}}';
  const fetch = async (url) => {
    const u = String(url);
    if (u.startsWith("https://cloudflare-dns.com/")) return { ok: true, status: 200, headers: { get: () => "application/dns-json" }, text: async () => JSON.stringify({ Answer: [] }) };
    if (u === "https://x.com/openapi.json") return { ok: true, status: 200, url: "https://cdn.x.com/v2/openapi.json", headers: { get: () => "application/json" }, text: async () => head };
    return { ok: false, status: 404, headers: { get: () => "" }, text: async () => "" };
  };
  is((await oaRes(fetch))?.name, "Redirected API", "OpenAPI behind a followed redirect detected");
}
// 4. wrong content type (HTML at /openapi.json, complete) → rejected.
{
  const { fetch } = makeFetch("<!DOCTYPE html><html><head><title>App</title></head></html>", 5000, "text/html");
  is(await oaRes(fetch), undefined, "complete HTML at /openapi.json rejected");
}
// 5. complete malformed JSON UNDER the cap (stream ends) → rejected (Fix 1).
{
  const { fetch } = makeFetch('{"openapi":"3.0.0","info":{"title":"X"} OOPS not json', 0, "application/json");
  is(await oaRes(fetch), undefined, "complete-but-malformed sub-cap body rejected (not truncated)");
}
// 6. normal SMALL OpenAPI → unchanged.
{
  const body = '{"openapi":"3.0.0","info":{"title":"Small API"},"paths":{}}';
  const fetch = async (url) => {
    const u = String(url);
    if (u.startsWith("https://cloudflare-dns.com/")) return { ok: true, status: 200, headers: { get: () => "application/dns-json" }, text: async () => JSON.stringify({ Answer: [] }) };
    if (u === "https://x.com/openapi.json") return { ok: true, status: 200, url: u, headers: { get: () => "application/json" }, text: async () => body };
    return { ok: false, status: 404, headers: { get: () => "" }, text: async () => "" };
  };
  is((await oaRes(fetch))?.name, "Small API", "small OpenAPI unchanged");
}

is(detectOpenApi('{"swagger":"2.0","info":{"title":"V2"}}', false).ok, true, "swagger 2.0 detected");
is(detectOpenApi("", false).ok, false, "empty rejected");

console.log(failed ? `\n${failed} FAILURES` : "\nAll OpenAPI size-handling tests passed.");
process.exit(failed ? 1 : 0);
