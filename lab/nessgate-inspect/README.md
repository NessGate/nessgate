# NessGate Inspect (EXPERIMENTAL — lab-only)

The domain-owner side of a two-sided, neutral observation layer:

> **Agent → NessGate** — understand what a *domain* publishes and how to connect.
> **Domain owner → NessGate Inspect** — understand what an *incoming agent* declares and can prove.

Given a description of an incoming automated/agent HTTP request, Inspect returns a
**neutral, normalized description of what the caller declares and what evidence
exists** — and nothing more.

## It never decides

Inspect makes **no trust, reputation, authorization, allow/deny, or scoring
decision**. It reports every fact and leaves the decision to the relying party.
This is the same stance as the rest of NessGate: observe and normalize, never act
as an authority. There is no `trust`, `score`, `allow`, `deny`, or `authorized`
field anywhere in the output (enforced by a test).

## Four evidence tiers, kept strictly separate

Every fact is placed in exactly one tier, and each fact carries **provenance**:

| Tier | Meaning | Example |
|---|---|---|
| `claimed` | Asserted by the caller, unverified | the `User-Agent` string; an unverifiable signature header |
| `cryptographically-verified` | A signature/key cryptographically bound to **this** request | a validated RFC 9421 Web Bot Auth signature |
| `network-verified` | The request's **origin infrastructure** is the operator's, via the operator's own documented method | source IP forward-confirms to `*.googlebot.com`, or is in OpenAI's published ranges |
| `directory-attributed` | A public directory recognizes a **declared** identifier | the `User-Agent` matches a published operator pattern |
| `unknown` | Absent / indeterminate | no signature, no recognized identifier; a network check that didn't confirm |

The two verified tiers verify **different things** and neither dominates: `network-verified`
attributes the *origin* (which defeats User-Agent spoofing); `cryptographically-verified`
attributes *this exact request* to a key holder. Both carry the explicit limit that they are
attribution, not trust/authorization.

## Signals, first cut

- **Web Bot Auth (`webbotauth.mjs`)** — real verification: parses RFC 9421
  `Signature-Input` / `Signature`, reconstructs the signature base exactly, fetches
  the caller's declared Ed25519 key from the `Signature-Agent` directory (JWKS,
  key matched by RFC 7638 thumbprint or `kid`), and verifies. A valid signature
  becomes `cryptographically-verified`; a present-but-unverifiable or **expired**
  signature stays `claimed`, with the precise reason.
- **Public attribution (`agents.mjs`)** — the `User-Agent` is matched against a
  directory of ~18 well-known operators' *published* UA patterns (GPTBot, ClaudeBot,
  PerplexityBot, Googlebot, …). A match is `directory-attributed`; the UA value
  itself is `claimed`.
- **Agent Card / published metadata (`agentcard.mjs`)** — if the caller declares where
  its A2A card lives (an explicit `Agent-Card` header, or the A2A well-known path on the
  host its `Signature-Agent` directory names), Inspect fetches and normalizes what the
  card *declares* (name, service endpoint, provider, version). A served card is a
  self-published document → tier `claimed` (served over HTTPS by host H means "H served
  this"). A cryptographic `signatures[]` field is surfaced as **present**, but never
  asserted verified — the A2A signed-card profile is still evolving, and Inspect does not
  claim a verification it did not actually perform. Only locations the caller itself named
  are fetched; no card path is guessed.

- **Verified Network Attribution (`netattr.mjs`)** — confirms a request's **source IP**
  belongs to infrastructure the operator officially attributes to its bot, using *that
  operator's documented method*: reverse-DNS + forward-confirm for **Google / Bing / Apple**
  (PTR ends with the documented host suffix AND forward-resolves back to the source IP);
  membership in **OpenAI's** and **Perplexity's** officially published IP/CIDR ranges
  (`gptbot.json`; Perplexity's separate per-bot `perplexitybot.json` / `perplexity-user.json`),
  fetched dynamically with bounded TTL caching (nothing hardcoded). **Anthropic is deliberately
  NOT wired** — its official docs state it does not publish bot IP ranges, so ClaudeBot/Claude-User
  stay `directory-attributed` rather than fabricate a method. A match
  ⇒ `network-verified`; it means **only** "originated from operator X's infrastructure," never
  trusted/authorized/safe/allowed. The **source IP must be the real connection peer** —
  `X-Forwarded-For` and other forwarded headers are **never trusted** (Inspect reads only a
  caller-supplied `opts.sourceIp`; the integrator sets it from the socket or an explicitly
  trusted proxy). A non-match or unavailable check falls back honestly to
  `directory-attributed`/`claimed` and is **never** asserted as proof of spoofing.

Standards are **reused, not invented**: RFC 9421, RFC 7638, the Web Bot Auth profile,
and operators' own published UA documentation. There is no NessGate identity standard.

## What Inspect exposes that raw request headers alone cannot

Run `node demo.mjs` to reproduce. For a Web Bot Auth signed request, raw headers
only show that a `Signature` header *is present*. Inspect adds:

1. **Verified binding, not mere presence.** It fetches the declared key directory,
   reconstructs the RFC 9421 base, and cryptographically verifies — turning
   "a signature header exists" into "the holder of key `<thumbprint>` demonstrably
   signed *this exact* request (`@authority`, `@method`, `signature-agent`)." Raw
   headers can't do the fetch + base-reconstruction + verification.
2. **Tier separation.** It cleanly splits "the UA *claims* GPTBot" (spoofable) from
   "a signature *proves* a binding" — raw headers present both as indistinguishable
   strings.
3. **Explicit limits.** Every verified result states what it does **not** prove —
   operator identity and authorization — exactly the gap the Web Bot Auth spec calls
   out. Raw headers imply nothing about their own meaning.
4. **Tamper/expiry honesty.** A request altered after signing, or a stale signature,
   is reported as `claimed` with the reason — never silently accepted.
5. **Normalization across mechanisms.** Web Bot Auth, public attribution, (and next,
   agent cards) arrive in one shape with consistent tiers and provenance.

## Isolation & safety

- Lives entirely under `lab/`; the production resolver imports nothing from it and no
  current NessGate behavior changes (`npm run test:lab` enforces this).
- **Stores nothing; holds no credential.** It verifies a signature against a *public*
  key and discards everything.
- The key-directory fetch targets a caller-declared URL, so it is **https-only and
  host-guarded** (no IP literals, localhost, or reserved ranges) — the same SSRF
  posture as the resolver. Bring your own `fetch` via `opts.fetch`.

## Files

| File | What |
|---|---|
| `inspect.mjs` | `inspect(request, opts)` → the normalized description. Orchestration only. |
| `webbotauth.mjs` | RFC 9421 parse + signature-base reconstruction + Ed25519 verification against the directory. |
| `agents.mjs` | Public operator UA directory + `matchUserAgent`. |
| `netattr.mjs` | Verified Network Attribution — rDNS forward-confirm (Google/Bing/Apple) + published IP ranges (OpenAI); CIDR math; connection-IP only. |
| `validate-agents.mjs` | Real-world cohort (~22 agents + controls) + live network-attribution validation. |
| `agentcard.mjs` | Fetch + normalize a caller-declared A2A agent card (served → `claimed`; signature-presence surfaced, not asserted verified). |
| `test-inspect.mjs` | 43 deterministic checks: pinned base, real Ed25519 round-trip, tamper, expiry, directory failure, served/signed agent cards, real robots, invariants. |
| `demo.mjs` | Reproducible exposure-delta demonstration (signed request vs GPTBot UA). |
| `serve.mjs` | Standalone `node:http` demo server (`node serve.mjs`) — run Inspect over REAL inbound requests. Not the production worker; `src/` is untouched. |

## Status & next

First cut; interop validated against self-generated signatures, real robot UA strings,
served/signed agent cards, and a live inbound `node:http` server (`serve.mjs`). Remaining:
validate against live Web Bot Auth traffic (e.g. Cloudflare's directory) once stable;
actually verify A2A signed-card JWS provenance (once the profile settles); add verified
reverse-DNS as a second corroboration path for public attribution. The Web Bot Auth and
IETF WIMSE drafts are still evolving — this stays in the lab until they settle.
