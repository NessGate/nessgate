// WITH NessGate: the ENTIRE integration a developer writes for the same jobs —
// outbound (what does this domain speak, is it usable, how do I connect?) and
// inbound (what does this caller present, what is proven?). Everything below
// the two imports is application choice, not protocol glue.

import { resolve, plan, assessReadiness, readinessProtocol } from "@nessgate/resolver";
import { inspect } from "@nessgate/inspect";

// Outbound: one call answers protocol, endpoint, transport, version, auth
// metadata, and usability for EVERY supported protocol at once.
export async function connectPlan(domain, clientCaps, opts = {}) {
  return plan(domain, clientCaps, opts);
}

// Per-resource readiness (when the application wants the raw per-endpoint view).
export async function endpointStates(domain, opts = {}) {
  const d = await resolve(domain, { ...opts, registry: true, delegate: true });
  const out = [];
  const seen = new Set();
  for (const r of d.resources) {
    if (!readinessProtocol(r) || seen.has(r.url)) continue;
    seen.add(r.url);
    out.push(await assessReadiness(r, opts));
  }
  return { outcome: d.outcome, states: out };
}

// Inbound: one call returns tiered, provenanced evidence for any mechanism the
// caller used (User-Agent, Web Bot Auth, network attribution).
export async function inboundEvidence(request, opts = {}) {
  return inspect(request, opts);
}
