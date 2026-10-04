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
//   - It stores no request, credential, or key data.
//
// Isolated under lab/; imports nothing from the production resolver and changes
// no current NessGate behavior.

import { verifyWebBotAuth } from "./webbotauth.mjs";
import { matchUserAgent } from "./agents.mjs";
import { inspectAgentCard } from "./agentcard.mjs";
import { verifyNetworkAttribution } from "./netattr.mjs";

// Two "verified" tiers verify DIFFERENT things and neither dominates the other:
//   network-verified          — this request's ORIGIN infrastructure is the operator's
//   cryptographically-verified — THIS request was signed by the holder of a key
const TIERS = ["claimed", "cryptographically-verified", "network-verified", "directory-attributed", "unknown"];

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
  const wbaAll = await verifyWebBotAuth(request, opts).catch((e) => ({ present: true, verified: false, signatures: [{ verified: false, reason: "inspect error: " + (e && e.message) }] }));
  // §5.2.2: each web-bot-auth signature is validated independently — one fact
  // per signature, each with its own verdict and provenance; a request-level
  // failure (no tag / unparseable) yields a single claimed fact with the reason.
  const wbaResults = wbaAll.present
    ? (wbaAll.signatures && wbaAll.signatures.length ? wbaAll.signatures : [{ verified: false, reason: wbaAll.reason }])
    : [];
  for (const wba of wbaResults) {
    wba.present = true;
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

  }

  /* --- 4. Agent Card / published metadata (self-published → claimed) --- */
  const card = await inspectAgentCard(request, opts).catch(() => null);
  if (card) add(card);

  /* --- 5. Verified Network Attribution (origin infrastructure) --- */
  // Runs only when the caller passes opts.sourceIp — the REAL connection peer.
  // Inspect never reads X-Forwarded-For or any forwarded header; deciding the
  // trustworthy source IP (direct socket, or an explicitly trusted proxy) is the
  // integrator's responsibility (see serve.mjs).
  if (opts.sourceIp) {
    const na = await verifyNetworkAttribution({ userAgent: ua, sourceIp: opts.sourceIp }, opts).catch((e) => ({ attempted: true, verified: false, reason: "inspect error: " + (e && e.message) }));
    if (na.attempted && na.verified) {
      add({
        kind: "network-attribution",
        tier: "network-verified",
        statement: `the source IP ${na.sourceIp} is within infrastructure ${na.operator} officially attributes to its bot (method: ${na.method})`,
        operator: na.operator,
        method: na.method,
        provenance: [
          { source: "connection", sourceIp: na.sourceIp, note: "the real connection peer; forwarded headers were NOT trusted" },
          na.method === "rdns-forward-confirm"
            ? { source: "reverse-dns-forward-confirmed", hostname: na.evidence.reverseDns, documentation: na.documentation }
            : { source: "operator-published-ip-ranges", url: na.evidence.rangesUrl, matchedCidr: na.evidence.matchedCidr, documentation: na.documentation },
        ],
        note: `means ONLY that this request originated from ${na.operator}'s documented infrastructure — it does NOT mean the caller is trusted, authorized, safe, or allowed. That decision is the relying party's.`,
      });
    } else if (na.attempted) {
      add({
        kind: "network-attribution",
        tier: "unknown",
        statement: `network origin did NOT confirm ${na.operator || "the claimed operator"}${na.method ? ` (method: ${na.method})` : ""}`,
        reason: na.reason,
        provenance: [{ source: "connection", sourceIp: na.sourceIp }],
        note: "the stronger network-verified tier is withheld. This is NOT proof of spoofing — a new, proxied, or newly-rotated IP can also fail — so attribution falls back to whatever the directory/claimed tiers established.",
      });
    }
  }

  const summary = Object.fromEntries(TIERS.map((t) => [t, facts.filter((f) => f.tier === t).length]));
  return {
    request: { method: String(request.method || "GET").toUpperCase(), authority, path },
    facts,
    summary,
    note: "NessGate Inspect normalizes what the caller declares and what evidence exists, separated by how strongly it is established. It makes NO trust, reputation, authorization, allow/deny, or scoring decision — the relying party decides. Nothing is stored; no credential is retained.",
  };
}

export { TIERS };
