// Inspect incoming callers in a Fastify server.
//
//   npm i fastify @nessgate/inspect
//   node inspect.mjs
//   curl -s localhost:8799/ -H 'user-agent: Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)'
//
// Attaches request.nessgate (the neutral evidence record) to every request.
// It reports evidence only — no allow/deny, no score. Your handlers decide what
// to do with it (usually: log it).

import Fastify from "fastify";
import { inspect } from "@nessgate/inspect";

// trustProxy only when you run behind a proxy you control. Fastify then derives
// request.ip from the forwarded headers it is configured to trust. Without it,
// request.ip is the direct socket peer. Network verification depends on this IP
// being the real connection source, so do not enable trustProxy unless a trusted
// platform sets the forwarding header.
const app = Fastify({ trustProxy: process.env.TRUST_PROXY === "1" });

app.addHook("onRequest", async (request) => {
  const headers = request.headers;
  const url = `http://${headers.host || "localhost"}${request.url}`;
  request.nessgate = await inspect(
    { method: request.method, url, headers },
    { sourceIp: request.ip }
  ).catch(() => null);
});

// Demo route: return the evidence. A real app reads request.nessgate and
// continues with its own logic.
app.get("/*", async (request) => request.nessgate);

app.listen({ port: Number(process.env.PORT || 8799), host: "0.0.0.0" })
  .then((addr) => console.log(`inspect on ${addr}`));
