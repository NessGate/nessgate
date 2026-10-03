# @nessgate/inspect

**Experimental (0.x).** Given an incoming automated/agent HTTP request, return a
neutral, normalized description of **what the caller declares and what evidence
exists** — and nothing more. Zero dependencies (Node built-ins only), Node ≥ 18.

The counterpart to [`@nessgate/resolver`](https://www.npmjs.com/package/@nessgate/resolver):
the resolver describes what a *domain* publishes and how to connect to it; this
package describes what an *incoming caller* presents.

## It never decides

No trust, reputation, authorization, allow/deny, or scoring decision — the output
contains no `trust`, `score`, `allow`, `deny`, or `authorized` field (test-enforced).
It reports tiered, provenanced facts; the relying party decides. It stores no
request, credential, or key data (operator IP-range documents are cached in
memory for at most ten minutes).

## Install and use

```bash
npm install @nessgate/inspect
```

**Express / Connect — two lines:**

```js
import { nessgateInspect } from "@nessgate/inspect/middleware";
app.use(nessgateInspect({ log: true }));
// every handler now has req.nessgate (facts, summary) — observation only
```

**Direct (any runtime with `fetch`):**

```js
import { inspect } from "@nessgate/inspect";

const result = await inspect(
  { method: req.method, url: req.url, headers },   // the incoming request
  { sourceIp }                                     // the REAL connection peer (optional)
);
// result.facts — each { kind, tier, statement, provenance, note, … }
// result.summary — counts per tier
```

**Cloudflare Worker:** pass `req.headers.get("cf-connecting-ip")` as `sourceIp`.
**Behind a proxy:** forwarded headers are never read by this package; supply the
peer address yourself from the socket or an explicitly trusted proxy.

## Evidence tiers

Every fact is placed in exactly one tier and carries provenance:

| Tier | Meaning |
|---|---|
| `claimed` | asserted by the caller, unverified (e.g. the `User-Agent`; an unverifiable or expired signature) |
| `cryptographically-verified` | an RFC 9421 (Web Bot Auth) signature validates against the caller's published Ed25519 key, binding this request's covered components. Both `Signature-Agent` forms are read: the current Structured Fields dictionary (`label="https://directory"`, including `;key=` covered members) and the older bare string |
| `network-verified` | the source IP belongs to infrastructure the operator documents for its bot, by that operator's own method — reverse-DNS + forward-confirm (Google, Bing, Apple) or published IP ranges (OpenAI, Perplexity; fetched live, bounded cache) |
| `directory-attributed` | a public directory recognizes a declared identifier (~18 operators' published User-Agent patterns); binds nothing |
| `unknown` | absent or indeterminate — a check that ran and did not conclude says why |

Every verified fact also states what it does **not** establish (operator identity,
authorization). Failures fall back to the weaker tier with the reason; a failed
network check is never presented as proof of spoofing, and operators that publish
no verification method are never given a fabricated one.

Measured on real production traffic (7 days, 1,222 distinct callers): the
no-network path costs well under a millisecond per request; when a network check
runs (callers matching a wired operator, ~5% of distinct callers), median ~20 ms.
For strict hot paths, run inspection out-of-band from logs instead of inline.

## API

- `inspect(request, opts)` → `{ request, facts[], summary, note }`
- `nessgateInspect(options)` (from `./middleware`) → Express/Connect middleware;
  `summarize(result)` extracts the six fields most sites log (declared agent,
  attributed operator, tier, method, provenance, unknowns)
- Lower-level, importable individually: `verifyWebBotAuth`, `matchUserAgent`,
  `verifyNetworkAttribution`, `inspectAgentCard`

Shapes follow the NessGate data model
([`docs/data-model.md`](https://github.com/NessGate/nessgate/blob/main/docs/data-model.md)).

## Fetch hardening

Every URL this package fetches comes from attacker-influenceable request data,
so the fetch core enforces: HTTPS only; hostname guards; a DNS pre-check that
rejects hosts resolving to private, loopback, link-local, or reserved space;
manual redirects with every hop re-validated (scheme, host, DNS); a 256 KB
response cap; a redirect-hop cap; and a 32-key JWKS processing limit. The DNS
pre-check narrows the DNS-rebinding window; full immunity requires a
pinned-address dispatcher, which a portable library cannot impose — integrate
one at your fetch layer if you need it.

## Status

Experimental. The Web Bot Auth and related IETF drafts are still evolving; field
names may change in 0.x releases. The classification principles — tiers kept
separate, provenance always, no decisions, no scores — will not.
