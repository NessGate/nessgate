// NessGate Inspect (EXPERIMENTAL, lab-only) — the domain-owner side.
//
// Two-sided model:
//   Agent → NessGate         : understand what a DOMAIN publishes and how to connect.
//   Domain owner → Inspect   : understand what an INCOMING agent declares and can prove.
//
// Given a description of an incoming automated/agent HTTP request, return a
// NEUTRAL NORMALIZED description of what the caller declares and what evidence
// exists — nothing more. Inspect is an observation/normalization layer, never a
// trust authority:
//
//   - It makes NO trust, reputation, authorization, or allow/deny decision, and
//     assigns NO score. Every fact is reported; the relying party decides.
//   - Each fact is placed in exactly one evidence tier, kept strictly separate:
//       claimed                    — asserted by the caller, unverified (e.g. User-Agent)
//       cryptographically-verified — proven by a signature/key bound to THIS request
//       directory-attributed       — a public directory recognizes a declared identifier
//       unknown                    — absent / indeterminate
//   - Every fact carries provenance (where it came from).
//   - It reuses existing standards (RFC 9421 / Web Bot Auth, RFC 7638, published
//     agent directories) and invents no NessGate identity standard.
//   - It stores nothing and holds no credential.
//
// Isolated under lab/; imports nothing from the production resolver and changes
// no current NessGate behavior.

import { verifyWebBotAuth } from "./webbotauth.mjs";
import { matchUserAgent } from "./agents.mjs";
import { inspectAgentCard } from "./agentcard.mjs";

const TIERS = ["claimed", "cryptographically-verified", "directory-attributed", "unknown"];

const header = (headers, name) => {
  for (const k in headers || {}) if (k.toLowerCase() === name.toLowerCase()) return headers[k];
  return undefined;
};

// Given {method, url, headers}, produce the normalized description. Read-only;
// opts.fetch is used only to retrieve a caller-declared public key directory.
export async function inspect(request, opts = {}) {
  const headers = request.headers || {};
  let authority = null, path = null;
  try { const u = new URL(request.url); authority = u.host.toLowerCase(); path = u.pathname; } catch {}
  const facts = [];
  const add = (f) => facts.push(f);

  /* --- 1. User-Agent: a CLAIMED identifier (spoofable) --- */
  const ua = header(headers, "user-agent");
  if (typeof ua === "string" && ua.trim()) {
    add({
      kind: "user-agent",
      tier: "claimed",
      statement: `the caller's User-Agent is ${JSON.stringify(ua)}`,
      value: ua,
      provenance: [{ source: "request-header", header: "user-agent" }],
      note: "a request header asserted by the caller; trivially spoofable and bound to nothing — not evidence of identity on its own.",
    });

    /* --- 2. Public attribution: a DIRECTORY recognizes that declared string --- */
    const m = matchUserAgent(ua);
    if (m) {
      add({
        kind: "public-attribution",
        tier: "directory-attributed",
        statement: `the declared User-Agent matches a published pattern operated by ${m.operator}`,
        operator: m.operator,
        provenance: [
          { source: "request-header", header: "user-agent" },
          { source: "public-agent-directory", pattern: m.pattern, documentation: m.info },
        ],
        note: "attribution of a self-declared, spoofable string against a public directory — it does NOT bind this request to that operator. Corroborate with a verified signature or verified reverse-DNS for binding.",
      });
    }
  }

  /* --- 3. Web Bot Auth: a signature CRYPTOGRAPHICALLY BOUND to this request --- */
  const wba = await verifyWebBotAuth(request, opts).catch((e) => ({ present: true, verified: false, reason: "inspect error: " + (e && e.message) }));
  if (wba.present) {
    const sigAgent = header(headers, "signature-agent");
    if (wba.verified && !wba.expired) {
      add({
        kind: "web-bot-auth",
        tier: "cryptographically-verified",
        statement: `an RFC 9421 HTTP Message Signature validates: the holder of key ${JSON.stringify(wba.keyid)} signed this request`,
        boundComponents: wba.components,
        keyid: wba.keyid, algorithm: wba.algorithm, created: wba.created, expires: wba.expires, directory: wba.directory, keyMatchedBy: wba.matchedBy,
        provenance: [
          { source: "request-header", header: "signature-input" },
          { source: "request-header", header: "signature" },
          { source: "key-directory", url: wba.directory, keyid: wba.keyid, matchedBy: wba.matchedBy },
        ],
        note: "proves ONLY that the holder of this key signed this exact request, binding the listed components. Per the Web Bot Auth specification this does NOT establish who operates the agent, its organization, or any authorization for the requested action — those remain the relying party's decision.",
      });
    } else {
      // A signature is PRESENT but not a current cryptographic binding → it stays
      // claimed, with the precise reason. (Also covers expired-but-valid: the
      // crypto held, but it is not a fresh binding.)
      add({
        kind: "web-bot-auth",
        tier: "claimed",
        statement: wba.expired
          ? `an RFC 9421 signature is cryptographically valid but EXPIRED (expires=${wba.expires}); not a current binding`
          : `the caller presents an RFC 9421 signature that could not be verified`,
        keyid: wba.keyid, directory: wba.directory,
        reason: wba.reason || (wba.expired ? "expired" : "unverified"),
        provenance: [
          { source: "request-header", header: "signature-input" },
          ...(sigAgent ? [{ source: "request-header", header: "signature-agent" }] : []),
        ],
        note: "a signature header is present but is not a verified, current binding to this request — so it is treated as claimed, not proven.",
      });
    }
  }

  /* --- 4. Agent Card / published metadata (self-published → claimed) --- */
  const card = await inspectAgentCard(request, opts).catch(() => null);
  if (card) add(card);

  const summary = Object.fromEntries(TIERS.map((t) => [t, facts.filter((f) => f.tier === t).length]));
  return {
    request: { method: String(request.method || "GET").toUpperCase(), authority, path },
    facts,
    summary,
    note: "NessGate Inspect normalizes what the caller declares and what evidence exists, separated by how strongly it is established. It makes NO trust, reputation, authorization, allow/deny, or scoring decision — the relying party decides. Nothing is stored; no credential is retained.",
  };
}

export { TIERS };
