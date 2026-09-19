# Design: MCP `tools/list` Introspection (NOT YET IMPLEMENTED)

Status: **design for review — no code exists**. Approved direction (2026-09-19):
investigate only; read-only; no tool execution; no credentials; bounded requests;
opt-in if needed. This document is the pre-implementation design that decision asked for.

## What it is

When resolution finds a resource declaring an MCP endpoint (an `mcp`-typed entry in an
ARD catalog, an AWP `mcp` protocol key, an AID TXT record with `p=mcp`, …), NessGate can
optionally ask that endpoint **what the server itself declares**, using the protocol's own
introspection handshake:

1. `initialize` (protocol version + client info, no auth)
2. `tools/list`
3. close — nothing else, ever

The declared tools (`name`, `description`, `inputSchema`) are surfaced verbatim in the
existing `capabilities` envelope on that resource, exactly like OpenAPI operations and A2A
skills. This is **publisher-authoritative** — the server answers for itself; NessGate
invents nothing.

## Why it clears the honesty bar

The other capability sources are static files the domain hosts. An MCP endpoint's
self-description is the same class of evidence, obtained through the standard mechanism
the protocol itself defines for exactly this question. `tools/list` is metadata
enumeration, not use: no tool is invoked, no argument is sent, no state changes.

## Hard constraints (all machine-enforceable)

- **Read-only, closed method set.** Only `initialize`, `notifications/initialized`, and
  `tools/list` are ever sent. `tools/call` and every other method are structurally
  unreachable (allowlist in the transport layer, negative-tested like lab isolation).
- **No credentials.** Anonymous requests only. A 401/403/auth-challenge is recorded as
  `introspection: "auth-required"` — an honest observation, not an error and not retried
  with credentials. The library embeds no secrets and accepts none for this feature.
- **Bounded.** Reuses the existing budgets: 8 s timeout, 1 MB response cap,
  private-IP/DoH guard, HTTPS only. At most N=3 declared MCP endpoints introspected per
  resolution; at most 2 POSTs each (initialize + tools/list; the initialized notification
  rides with the second request where the transport allows).
- **Domain discipline (hosted).** The hosted worker introspects only endpoints on the
  queried registrable domain (same rule as every other fetch). The library follows its
  existing model (caller is responsible for untrusted input — documented in README
  Security, same as today).
- **Opt-in and labeled.** Off by default: `resolve(domain, { mcp: true })` /
  `GET /discover/{d}?mcp=1`, response carries `introspected: ["mcp"]`. Rationale: it is
  the first time NessGate *speaks* a protocol rather than reading published files, it
  adds POST requests to third-party servers, and default request counts must not grow
  silently. Cached under a separate key like `?fast=1`.

## Protocol variance to handle (the actual compatibility work)

- Streamable HTTP (2025+ spec): single endpoint, POST JSON-RPC, optional SSE-framed
  responses (`text/event-stream` must be parsed for the JSON-RPC frame).
- Session headers: `Mcp-Session-Id` returned by initialize must be echoed on
  `tools/list`.
- Legacy HTTP+SSE (pre-2025) servers: `GET /sse` + separate POST endpoint — detect and
  either support or record `introspection: "legacy-transport"` honestly; do not guess.
- Protocol-version negotiation: send the newest version we implement; accept the
  server's downgrade per spec.
- Broken servers (the A2A-cards lesson says these will be common): wrong content types,
  non-JSON-RPC bodies, hangs. Every failure mode becomes a compat fixture per the
  standing rule ("never fix a compatibility problem only in code").

## Security notes

- **Tool descriptions are attacker-controlled text.** They are returned verbatim as
  data, never rendered as HTML unescaped (existing escaping rules apply on /check), and
  never fed to any model by NessGate. Documented so downstream agents know to treat
  them as untrusted input (prompt-injection surface lives with the consumer).
- **SSRF**: same DoH public-IP pre-check and HTTPS-only rules as every fetch; POST
  bodies are fixed JSON-RPC frames with no caller-controlled content beyond the
  endpoint URL, which passes the same host checks as GET probes today.
- **Politeness**: one introspection per endpoint per cache window (10 min); the
  User-Agent identifies NessGate with a contact URL, as the verifier/discover UAs do.

## What it must never become

No ranking of servers, no health scoring, no conformance badges, no stored index of
tools, no auto-invocation, no credentialed access. Introspection results are a live
observation with provenance (`sourceUrl` = the MCP endpoint), cached briefly, stored
nowhere — the same contract as /discover itself.

## Rollout order

1. Library first (`opts.mcp`), behind the flag, with transport-level allowlist test +
   fixtures for streamable-http happy path, SSE framing, session echo, auth-required,
   and a malformed server.
2. Hosted `?mcp=1` after the library ships and the gate has the fixtures.
3. Measure (existing edge analytics + the anonymous outcome metric): does anyone use
   it? Demand evidence gates any deepening (resources/list, prompts/list are further
   read-only surfaces — NOT in scope until asked for).

## Open questions for review

- Cap N=3 introspected endpoints: right number?
- Should `auth-required` distinguish 401 vs 403? (Lean: no — one honest label,
  less fingerprinting surface.)
- Worker CPU limits: SSE parsing under the free-tier budget needs a spike before
  committing to hosted support.
