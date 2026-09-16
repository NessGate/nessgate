// OpenAPI size-handling tests (the weakness the unseen benchmark found). Uses a
// mock STREAMING fetch to prove the resolver reads only a bounded prefix and
// detects large specs from the head — while rejecting hostile/oversized/wrong
// bodies and leaving small specs unchanged. Run with `npm run test:openapi`.
import { resolve, detectOpenApi } from "../packages/resolver/index.mjs";

let failed = 0;
const is = (a, e, n) => { const ok = JSON.stringify(a) === JSON.stringify(e); console[ok ? "log" : "error"](`${ok ? "  ok " : "FAIL"}  ${n}`); if (!ok) { failed++; console.error(`      got ${JSON.stringify(a)} want ${JSON.stringify(e)}`); } };

// A mock fetch: streams /openapi.json with a controllable head + total size and
// records how many bytes were actually pulled (to prove bounded reads). Every
// other path 404s; DoH returns empty.
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

async function openapiResource(fetch) {
  const r = await resolve("x.com", { fetch, timeoutMs: 4000, maxBytes: 1_000_000 });
  return (r.resources || []).find((x) => x.source === "openapi");
}

console.log("--- OpenAPI size handling (bounded-prefix reads)");

// 1. valid LARGE OpenAPI (10 MB): found, and read is bounded (not the whole doc).
{
  const head = '{"openapi":"3.0.0","info":{"title":"Big Co API","version":"1"},"paths":{';
  const { fetch, tracker } = makeFetch(head, 10_000_000, "application/json");
  const res = await openapiResource(fetch);
  is(!!res && res.type === "openapi", true, "large 10MB OpenAPI is found");
  is(res && res.name, "Big Co API", "title recovered from the head");
  is(tracker.produced < 300_000, true, `read is bounded (${tracker.produced} bytes pulled, not 10MB)`);
  is(tracker.canceled, true, "stream was canceled after the prefix");
}

// 2. oversized / absurd payload (50 MB, NO marker): rejected, still bounded.
{
  const { fetch, tracker } = makeFetch('{"junk":"', 50_000_000, "application/json");
  const res = await openapiResource(fetch);
  is(res, undefined, "oversized non-OpenAPI payload is not reported");
  is(tracker.produced < 300_000, true, `hostile payload read stays bounded (${tracker.produced} bytes)`);
}

// 3. redirect: the underlying fetch follows redirects; a post-redirect OpenAPI
//    body (res.url differs) is still detected.
{
  const head = '{"openapi":"3.1.0","info":{"title":"Redirected API"}}';
  const fetch = async (url) => {
    const u = String(url);
    if (u.startsWith("https://cloudflare-dns.com/")) return { ok: true, status: 200, headers: { get: () => "application/dns-json" }, text: async () => JSON.stringify({ Answer: [] }) };
    if (u === "https://x.com/openapi.json") return { ok: true, status: 200, url: "https://cdn.x.com/v2/openapi.json", headers: { get: () => "application/json" }, text: async () => head };
    return { ok: false, status: 404, headers: { get: () => "" }, text: async () => "" };
  };
  const res = await openapiResource(fetch);
  is(!!res && res.name === "Redirected API", true, "OpenAPI behind a followed redirect is detected");
}

// 4. wrong content type (HTML shell served at /openapi.json): rejected.
{
  const { fetch } = makeFetch("<!DOCTYPE html><html><head><title>App</title></head></html>", 5000, "text/html");
  is(await openapiResource(fetch), undefined, "HTML at /openapi.json is rejected (wrong content)");
}

// 5. truncated document (stream ends mid-object, but the marker is in the head).
{
  const head = '{"openapi":"3.0.2","info":{"title":"Truncated API","version":"9"},"paths":{"/a":{"ge';
  const { fetch } = makeFetch(head, head.length, "application/json"); // ends exactly at head → truncated JSON
  const res = await openapiResource(fetch);
  is(!!res && res.type === "openapi" && res.name === "Truncated API", true, "truncated spec with a head marker is still detected");
}

// 6. normal SMALL OpenAPI: unchanged behavior.
{
  const { fetch } = (() => {
    const body = '{"openapi":"3.0.0","info":{"title":"Small API"},"paths":{}}';
    return { fetch: async (url) => {
      const u = String(url);
      if (u.startsWith("https://cloudflare-dns.com/")) return { ok: true, status: 200, headers: { get: () => "application/dns-json" }, text: async () => JSON.stringify({ Answer: [] }) };
      if (u === "https://x.com/openapi.json") return { ok: true, status: 200, url: u, headers: { get: () => "application/json" }, text: async () => body };
      return { ok: false, status: 404, headers: { get: () => "" }, text: async () => "" };
    } };
  })();
  const res = await openapiResource(fetch);
  is(!!res && res.name === "Small API", true, "small OpenAPI unchanged (found, title intact)");
}

// 7. detectOpenApi units (pure) — swagger 2.0 legacy + empty.
is(detectOpenApi('{"swagger":"2.0","info":{"title":"V2"}}').ok, true, "swagger 2.0 detected");
is(detectOpenApi("").ok, false, "empty rejected");

console.log(failed ? `\n${failed} FAILURES` : "\nAll OpenAPI size-handling tests passed.");
process.exit(failed ? 1 : 0);
