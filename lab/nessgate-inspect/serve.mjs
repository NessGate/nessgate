// Lab-only inbound demo server — run Inspect over REAL incoming requests.
//
// A standalone node:http server (NOT the production worker — nothing in src/ is
// touched). Point an agent, bot, or curl at it and it returns the neutral,
// normalized description of what that caller declared and could prove. This is
// how a domain owner would experience Inspect on real traffic.
//
//   node serve.mjs            # listens on http://localhost:8799
//   curl -s localhost:8799/anything -H 'user-agent: GPTBot/1.2' | jq
//
// For HTTPS/Web Bot Auth key-directory fetches it uses the global fetch. It still
// stores nothing and holds no credential. Env PORT overrides the port.

import { createServer } from "node:http";
import { inspect } from "./inspect.mjs";

const PORT = Number(process.env.PORT || 8799);

const server = createServer(async (req, res) => {
  // Collect headers as a plain {name:value} object (node lowercases names).
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(", ") : v;
  const authority = headers.host || "localhost";
  const request = { method: req.method, url: `http://${authority}${req.url}`, headers };
  // Inspect needs the request's own authority; for Web Bot Auth the signed
  // @authority must match, so we present the Host the caller sent.
  try {
    const result = await inspect(request, {});
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(result, null, 2));
  } catch (e) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: String(e && e.message || e) }));
  }
});

server.listen(PORT, () => {
  console.log(`NessGate Inspect demo server on http://localhost:${PORT}`);
  console.log(`try: curl -s localhost:${PORT}/ -H 'user-agent: Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://www.anthropic.com)'`);
});
