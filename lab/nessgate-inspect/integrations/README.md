# NessGate Inspect — drop-in integration (EXPERIMENTAL, lab-only)

Run Inspect on incoming requests and get the neutral normalized result on
`req.nessgate`. It **observes only** — no allow/deny, no trust score, no blocking,
no policy. Your app reads the facts and does whatever it wants (usually: log them).

## Express / Connect — the whole integration is 2 lines

```js
import { nessgateInspect } from "@nessgate/inspect/middleware";   // 1
app.use(nessgateInspect({ log: true }));               // 2
// now every handler has req.nessgate (+ req.nessgate.summary2: the six fields)
```

No account, no API key, no config object required (`{ log: true }` is optional).

## Plain node:http (zero dependencies) — see `example.mjs`

```js
const mw = nessgateInspect();
createServer((req, res) => mw(req, res, () => {
  res.end(JSON.stringify(req.nessgate));   // req.nessgate is populated
})).listen(8798);
```

## Cloudflare Worker (edge) — ~5 lines

```js
import { inspect } from "../inspect.mjs";
export default {
  async fetch(req) {
    const headers = Object.fromEntries(req.headers);
    const sourceIp = req.headers.get("cf-connecting-ip");           // trusted peer at the edge
    const result = await inspect({ method: req.method, url: req.url, headers }, { sourceIp });
    return Response.json(result);
  },
};
```

At the edge, `cf-connecting-ip` is the platform-provided true peer — use it instead
of parsing `X-Forwarded-For` yourself.

## The six fields a site owner logs (from `summarize(req.nessgate)`)

```
declaredAgent        the caller's User-Agent (claimed, spoofable)
attributedOperator   operator resolved from the UA directory / network attribution
verificationTier     claimed | directory-attributed | network-verified | cryptographically-verified | unknown
verificationMethod   e.g. rdns-forward-confirm, ip-ranges, rfc9421-web-bot-auth (when verified)
provenance           where each fact came from (header, directory doc URL, matched CIDR, rDNS host…)
unknowns             what could not be established, with the reason (never a guess)
```

## Measured cost to adopt

| | |
|---|---|
| Lines of code (Express) | **2** (import + `app.use`) |
| Required config / options | **0** (all optional) |
| Account / API key / signup | **none** |
| Inbound/web-server changes | **none** (standard middleware) |
| New stored data | **none** (Inspect stores nothing) |

## Infrastructure assumptions

- **Outbound HTTPS + DNS from the request path.** Verification fetches a key
  directory (Web Bot Auth) or an operator's published IP-range JSON, and may do a
  reverse-DNS + forward-confirm. IP-range JSON is cached (bounded TTL); rDNS adds a
  lookup. A host with no outbound network still gets `claimed`/`directory-attributed`
  honestly — verification simply degrades to `unknown`, never a false result.
- **Latency.** The verified tiers add network round-trips. For latency-sensitive
  paths, run Inspect out-of-band (e.g. from logs/a queue) rather than inline; the
  middleware is inline for simplicity, not a requirement.
- **A correct source IP.** Direct servers: `req.socket.remoteAddress` (automatic).
  Behind a load balancer/proxy: pass `{ trustProxy: true }` **and** ensure only a
  trusted proxy can set `X-Forwarded-For` (off by default — the safe default).

## Not a policy engine

The middleware never blocks, rate-limits, scores, or decides. If you want to act on
a result (e.g. serve richer content to a `network-verified` operator), that logic is
yours and lives in your handler — Inspect only tells you, honestly, what is and isn't
established.
