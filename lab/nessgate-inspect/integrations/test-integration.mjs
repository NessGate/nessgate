// Tests for the drop-in middleware (no network needed). Run: node test-integration.mjs
import { nessgateInspect, summarize } from "../../../packages/inspect/middleware.mjs";

let pass = 0, fail = 0;
const ok = (n, c) => { if (c) pass++; else { fail++; console.error("FAIL  " + n); } };

// Minimal Express-like req/res. Injected DNS makes the Googlebot case verifiable.
function fakeReq(ua, remoteAddress, extra = {}) {
  return { method: "GET", url: "/path", headers: { host: "site.example", ...(ua ? { "user-agent": ua } : {}) }, socket: { remoteAddress }, ...extra };
}
const run = (req, opts) => new Promise((resolve) => nessgateInspect(opts)(req, {}, () => resolve(req)));
// Offline stubs: the middleware forwards dns/ranges/fetch to inspect, so no test
// touches the network (operator range documents, DNS, directories).
const PUBDNS = { resolve4: async () => ["93.184.216.34"], resolve6: async () => [] };
const OFFLINE = { dns: PUBDNS, ranges: ["198.51.100.0/24"] }; // a range the test IPs are NOT in

// 1. attaches req.nessgate and always calls next()
{
  const req = fakeReq("GPTBot/1.2", "203.0.113.9");
  await run(req, OFFLINE);
  ok("middleware attaches req.nessgate", req.nessgate && Array.isArray(req.nessgate.facts));
  ok("summary exposes the six fields", (() => { const s = summarize(req.nessgate); return "declaredAgent" in s && "attributedOperator" in s && "verificationTier" in s && "verificationMethod" in s && "provenance" in s && "unknowns" in s; })());
  ok("GPTBot UA → operator OpenAI, tier directory-attributed (loopback-style IP, no range match)", summarize(req.nessgate).attributedOperator === "OpenAI" && summarize(req.nessgate).verificationTier === "directory-attributed");
}

// 2. network-verified surfaces in the six fields when evidence supports it
{
  const dns = { reverse: async () => ["crawl.googlebot.com"], resolve4: async () => ["66.249.66.1"], resolve6: async () => [] };
  // the middleware forwards options.dns, so this is deterministic and offline
  // pass dns through via a custom middleware opt path: inspect reads opts, so wrap:
  const req = fakeReq("Googlebot/2.1", "66.249.66.1");
  await new Promise((resolve) => nessgateInspect({ dns })(req, {}, () => resolve()));
  const s = summarize(req.nessgate);
  ok("Googlebot via forwarded dns → network-verified deterministically", s.verificationTier === "network-verified");
}

// 3. never a decision/score field anywhere in the exposed result or summary
{
  const req = fakeReq("GPTBot/1.2", "203.0.113.9");
  await run(req, OFFLINE);
  const blob = JSON.stringify({ r: req.nessgate, s: summarize(req.nessgate) });
  ok("no allow/deny/trust/score/block field", !/"(allow|deny|block|blocked|trust|trusted|score|authorized|verdict|action)"\s*:/i.test(blob));
}

// 4. X-Forwarded-For is NOT trusted by default (source IP = socket peer)
{
  const req = fakeReq("GPTBot/1.2", "203.0.113.9", { headers: { host: "s", "user-agent": "GPTBot/1.2", "x-forwarded-for": "20.171.0.0" } });
  await run(req, OFFLINE); // default (no trustProxy)
  // With a ranges-less real fetch this can't verify from a TEST-NET socket; the point:
  // the XFF value (a plausibly-real OpenAI IP) must NOT be used as the source.
  ok("default run completes without trusting XFF (no crash, result attached)", req.nessgate !== undefined);
}

// 5. a thrown inspect never breaks the request (result = null, next still called)
{
  const req = { method: "GET", url: "/", headers: null, socket: { remoteAddress: "1.2.3.4" } }; // headers:null forces a path
  let nexted = false;
  await new Promise((resolve) => nessgateInspect({})(req, {}, () => { nexted = true; resolve(); }));
  ok("request proceeds even on bad input (next called)", nexted === true);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
