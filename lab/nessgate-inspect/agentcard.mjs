// Agent Card / published-metadata signal (lab-only) for NessGate Inspect.
//
// If the caller declares where its A2A agent card lives — either an explicit
// Agent-Card header (a URL it supplies) or, failing that, the registrable host of
// its Web Bot Auth `Signature-Agent` directory — Inspect fetches the card from
// that caller-NAMED location (never a guessed one beyond the standard A2A
// well-known path on a host the caller itself named) and normalizes what it
// DECLARES.
//
// Honesty: a served card is a SELF-PUBLISHED document. Being served over HTTPS by
// host H establishes only "H served this description" — not operator identity, not
// authorization. So card contents are tier `claimed`. A cryptographic `signatures`
// field is surfaced as present, but NOT asserted verified: the A2A signed-card
// profile is still evolving, and Inspect never claims a verification it did not
// actually perform to a settled standard. (Web Bot Auth remains the verified tier.)

import { safeFetchJson } from "./webbotauth.mjs";

const headerGet = (headers, name) => { for (const k in headers || {}) if (k.toLowerCase() === name.toLowerCase()) return headers[k]; return undefined; };
const str = (v) => (typeof v === "string" ? v : undefined);

// Caller-declared candidate card locations, in priority order. Only locations the
// caller itself named (explicit header, or the A2A well-known on its declared host).
export function cardCandidates(request) {
  const headers = request.headers || {};
  const out = [];
  const explicit = headerGet(headers, "agent-card") || headerGet(headers, "x-agent-card");
  if (typeof explicit === "string" && /^https:\/\//i.test(explicit.trim())) out.push({ url: explicit.trim().replace(/^"|"$/g, ""), origin: "caller-declared header" });
  let sigAgent = headerGet(headers, "signature-agent");
  if (typeof sigAgent === "string") {
    sigAgent = sigAgent.trim().replace(/^"|"$/g, "");
    let host = null;
    try { host = new URL(/^https:\/\//i.test(sigAgent) ? sigAgent : "https://" + sigAgent).host; } catch {}
    if (host) for (const p of ["/.well-known/agent-card.json", "/.well-known/agent.json"]) out.push({ url: `https://${host}${p}`, origin: "A2A well-known on the declared Signature-Agent host" });
  }
  return out;
}

// Pure: normalize a parsed A2A card into claimed facts + a signature-presence note.
export function normalizeCard(card, servedUrl, origin) {
  if (!card || typeof card !== "object") return null;
  const provider = card.provider && typeof card.provider === "object" ? card.provider : {};
  const signed = Array.isArray(card.signatures) && card.signatures.length > 0;
  let host = null; try { host = new URL(servedUrl).host; } catch {}
  return {
    kind: "agent-card",
    tier: "claimed",
    statement: `the caller points to an A2A agent card${card.name ? ` for ${JSON.stringify(str(card.name))}` : ""} served by ${host || "the declared host"}`,
    declared: {
      name: str(card.name),
      endpoint: str(card.url),
      protocolVersion: str(card.protocolVersion) || str(card.version),
      provider: str(provider.organization),
      providerUrl: str(provider.url),
    },
    signaturePresent: signed,
    provenance: [{ source: "agent-card", url: servedUrl, via: origin, servedByHost: host }],
    note:
      "a self-published document served over HTTPS by the declared host; it describes the agent but does not by itself prove operator identity or authorization." +
      (signed
        ? " The card carries a cryptographic signature (signatures[]); verifying A2A signed-card provenance is a pending signal — the profile is still evolving, so Inspect surfaces its presence without asserting it verified."
        : " The card is unsigned."),
  };
}

// IO: try each caller-declared location until one yields a parseable card.
export async function inspectAgentCard(request, opts = {}) {
  const fetchImpl = opts.fetch || globalThis.fetch;
  for (const cand of cardCandidates(request)) {
    const r = await safeFetchJson(fetchImpl, cand.url, opts.timeoutMs).catch(() => ({ error: "fetch error" }));
    if (r && r.json) {
      const fact = normalizeCard(r.json, r.finalUrl || cand.url, cand.origin);
      if (fact) return fact;
    }
  }
  return null;
}
