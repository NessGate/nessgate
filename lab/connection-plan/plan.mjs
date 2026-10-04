// NessGate — Connection-Plan prototype (EXPERIMENTAL, lab-only).
//
// ⚠ ISOLATION: this module lives under lab/ and is NOT part of the published
// product, the charter, or any hosted API. Production never imports it
// (test-lab-isolation.mjs enforces this). It reads the resolver's OWN output and
// adds one layer on top — it defines no protocol and stores no discovered domain or resource data.
//
// WHAT IT DOES (and only this): given the answer NessGate already produces for a
// domain (discovery) plus the CLIENT's declared capabilities, it computes one or
// more "connection plans" — the compatible {protocol, version, transport, auth}
// combinations, each carrying the source that proves it. It does NOT proxy,
// translate, or connect. Discovery → comparison → selection → plan.
//
// NEUTRALITY (mirrors the live charter, adapted to matching):
//  - No scores, ever. Every judgment is an enum, never a number.
//  - Capability matching is deterministic SET INTERSECTION — a fact, not a rank.
//  - ALL compatible plans are returned in a documented, stable order.
//  - A single winner (selectedPlan) is named ONLY when the CLIENT supplied a
//    preference order. NessGate never expresses a preference of its own.
//  - It asserts only what the domain declared: auth/transport it did not observe
//    are marked "undeclared", never guessed. This is the honesty lever.

/* --------------------------- label vocabulary ---------------------------- */
// Reuse each protocol's OWN labels — NessGate invents no taxonomy. These are the
// same source/type labels /discover already emits, plus a couple of well-known
// aliases so a client saying "a2a" matches a card labelled "a2a-agent-card".
const PROTOCOL_ALIASES = new Map([
  ["a2a", "a2a-agent-card"],
  ["agent-card", "a2a-agent-card"],
  ["rest", "openapi"],
  ["gbz-185.4", "gbz-185-4"],
]);
const canonProtocol = (p) => PROTOCOL_ALIASES.get(String(p || "").toLowerCase()) || String(p || "").toLowerCase();

// OpenAPI securityScheme → a single auth label, using OpenAPI's OWN vocab:
// type, or type:scheme for the "http" family (http:bearer, http:basic, …).
function openApiAuthLabel(s) {
  if (!s || typeof s !== "object") return undefined;
  const t = typeof s.type === "string" ? s.type : undefined;
  if (!t) return undefined;
  if (t === "http" && typeof s.scheme === "string") return "http:" + s.scheme.toLowerCase();
  return t; // apiKey | oauth2 | openIdConnect | mutualTLS
}

const isLevel1 = (evidence) =>
  typeof evidence === "string" &&
  (evidence.startsWith("publisher") || evidence === "namespace-verified" || evidence === "registered" ||
   evidence === "verified-publisher-location");

/* ---------------------- fact extraction (per resource) -------------------- */
// Turn one normalized NessGate resource into zero or more "service methods":
// a concrete way the service says it can be reached. Everything is read from the
// resource's real fields; anything the resource does not carry is left null /
// "undeclared" (never inferred).

const undeclaredAuth = () => ({ required: null, methods: [], detail: "undeclared" });

function methodBase(r, protocol) {
  return {
    protocol,
    version: null,
    transport: null,
    endpoint: typeof r.url === "string" ? r.url : r.sourceUrl,
    auth: undeclaredAuth(),
    evidence: typeof r.class === "string" ? r.class : "publisher-hosted",
    sourceUrl: r.sourceUrl,
    provenance: Array.isArray(r.provenance) ? r.provenance : r.provenance ? [r.provenance] : [{ sourceUrl: r.sourceUrl, via: r.source }],
  };
}

function openapiMethod(r) {
  const m = methodBase(r, "openapi");
  m.transport = "https"; // OpenAPI over HTTP(S) is intrinsic to the format
  // The resolver keeps info.title but discards the openapi version string, so we
  // honestly cannot confirm a version here → version-unconfirmed downstream.
  const schemes = Array.isArray(r.security) ? r.security : [];
  const labels = schemes.map(openApiAuthLabel).filter(Boolean);
  if (labels.length) {
    m.auth = { required: true, methods: labels.map((label) => ({ label, declared: true })), detail: "declared" };
  } // else: no securitySchemes in the (complete) doc → truly undeclared, leave as-is
  return [m];
}

function a2aMethods(r) {
  const raw = r.raw || {};
  const version = typeof raw.protocolVersion === "string" ? raw.protocolVersion : typeof raw.version === "string" ? raw.version : null;
  const ifaces = [
    ...(Array.isArray(raw.additionalInterfaces) ? raw.additionalInterfaces : []),
    ...(Array.isArray(raw.supportedInterfaces) ? raw.supportedInterfaces : []),
  ].filter((i) => i && typeof i === "object");
  const mk = (transport, endpoint) => {
    const m = methodBase(r, "a2a-agent-card");
    m.version = version;
    m.transport = transport || null;
    if (endpoint) m.endpoint = endpoint;
    // The readiness layer re-fetches the card to read securitySchemes; from the
    // compatibility record alone, auth stays undeclared (honest, not a guess).
    return m;
  };
  if (typeof raw.preferredTransport === "string") return [mk(raw.preferredTransport.toLowerCase(), typeof raw.url === "string" ? raw.url : null)];
  if (ifaces.length) return ifaces.map((i) => mk(typeof i.transport === "string" ? i.transport.toLowerCase() : null, typeof i.url === "string" ? i.url : null));
  return [mk(null, null)];
}

function aidMethod(r) {
  const raw = r.raw || {};
  // AID's p= names the DOWNSTREAM protocol (mcp/a2a/openapi/…). If present, the
  // AID record is effectively that protocol's endpoint declaration.
  const protocol = canonProtocol(raw.proto || r.type || "aid");
  const m = methodBase(r, protocol);
  // raw.version is the AID record version ("aid1"), NOT the downstream protocol's
  // version — do not present it as such.
  if (typeof raw.auth === "string" && raw.auth) {
    const required = raw.auth.toLowerCase() !== "none";
    m.auth = { required, methods: required ? [{ label: raw.auth.toLowerCase(), declared: true }] : [], detail: "declared" };
  }
  return [m];
}

function ucpMethod(r) {
  const raw = r.raw || {};
  const m = methodBase(r, "ucp");
  if (typeof raw.ucp_version === "string") m.version = raw.ucp_version;
  // r.type here is UCP's own transport/capability type label.
  if (typeof r.type === "string" && r.type !== "ucp") m.transport = r.type.toLowerCase();
  return [m];
}

function mcpMethod(r) {
  const m = methodBase(r, "mcp");
  const intro = r.introspection;
  if (intro && typeof intro === "object") {
    const legacy = intro.status === "legacy-transport" || intro.legacy === true;
    m.transport = legacy ? "sse-legacy" : "streamable-http";
    if (typeof intro.protocolVersion === "string") m.version = intro.protocolVersion;
    if (intro.status === "auth-required") {
      // Observed behaviorally (a 401/403 to the handshake), not declared in a doc.
      m.auth = { required: true, methods: [], detail: "inferred" };
    } else if (intro.ok === true) {
      m.auth = { required: false, methods: [{ label: "none", declared: false }], detail: "inferred" };
    }
  }
  // No introspection → transport/version/auth stay undeclared (we won't assume
  // "streamable-http" just because it's the current default).
  return [m];
}

const MCP_TYPE_LABELS = new Set(["mcp", "application/mcp-server-card+json"]);

// POINTER surfaces are how a client FINDS endpoints, not endpoints it connects to:
// an llms.txt / api-catalog / host-meta / ORD / bare ARD catalog points AT the
// real services. Phase-1 does NOT follow them (that is /explore's delegation), so
// they are reported as "leads", never scored as connection methods and never
// counted as a no-match. Treating them as connectable would have manufactured
// false negatives (a domain that only publishes a catalog is not "incompatible").
const POINTER_PROTOCOLS = new Set([
  "llms.txt", "api-catalog", "ai-info.json", "host-meta", "ord",
  "ard-catalog", "ard-entry", "ard-link", "ard-agentmap",
]);
export const isPointer = (protocol) => POINTER_PROTOCOLS.has(canonProtocol(protocol));

function methodsFromResource(r) {
  if (!r || typeof r !== "object") return [];
  // A genuine MCP handshake result always wins — it is live protocol evidence.
  if (r.introspection) return mcpMethod(r);
  // Source-specific extraction beats the generic type-label fallback, so an AID
  // record whose p=mcp (source "aid", type "mcp") keeps AID's DECLARED auth
  // instead of being flattened into a bare, detail-less MCP endpoint.
  switch (r.source) {
    case "openapi": return openapiMethod(r);
    case "a2a-agent-card": return a2aMethods(r);
    case "aid": return aidMethod(r);
    case "ucp": return ucpMethod(r);
    // An ARD catalog carries ENTRIES whose own `type` names the downstream
    // protocol (openapi/mcp/a2a/…). Use that type, not the catalog label.
    case "ard-catalog": return [methodBase(r, canonProtocol(r.type))];
  }
  // A resource DECLARED as MCP by any other source (AWP protocol key, self-label).
  if (MCP_TYPE_LABELS.has(r.type)) return mcpMethod(r);
  return [methodBase(r, canonProtocol(r.source || r.type))];
}

export function serviceMethods(discovery) {
  const resources = discovery && Array.isArray(discovery.resources) ? discovery.resources : [];
  return resources.flatMap(methodsFromResource);
}

/* ------------------------------- matching -------------------------------- */
// TRI-STATE per dimension: true (client specified & service declared & they
// intersect), false (both known & they CONFLICT → hard fail), "any" (client
// accepts anything), "unknown" (service did not declare it → cannot confirm).

function dimMatch(clientList, serviceValue) {
  if (!Array.isArray(clientList) || clientList.length === 0) return "any";
  if (serviceValue == null) return "unknown";
  return clientList.map((x) => String(x).toLowerCase()).includes(String(serviceValue).toLowerCase()) ? true : false;
}

function authMatch(clientAuth, methodAuth) {
  if (!Array.isArray(clientAuth) || clientAuth.length === 0) return "any";
  if (methodAuth.detail === "undeclared") return "unknown";
  if (methodAuth.required === false) return true; // no auth needed → client can always connect
  const client = clientAuth.map((x) => String(x).toLowerCase());
  if (methodAuth.methods.length === 0) return "unknown"; // required but which method is unknown
  return methodAuth.methods.some((m) => client.includes(String(m.label).toLowerCase())) ? true : false;
}

const COMPLETENESS_RANK = { complete: 0, "version-unconfirmed": 1, "connection-undeclared": 2 };

function completenessOf(method) {
  const authResolved = method.auth.detail !== "undeclared";
  const transportResolved = method.transport != null;
  const versionResolved = method.version != null;
  if (authResolved && transportResolved && versionResolved) return "complete";
  if (authResolved && transportResolved) return "version-unconfirmed";
  return "connection-undeclared";
}

// Build a plan for one service method against one client support entry, or return
// { reason } if the client hard-conflicts with a declared service value.
function planForEntry(method, entry) {
  const v = dimMatch(entry.versions, method.version);
  const t = dimMatch(entry.transports, method.transport);
  const a = authMatch(entry.auth, method.auth);
  const hardFail =
    (v === false && "version") || (t === false && "transport") || (a === false && "auth") || null;
  if (hardFail) return { reason: `client and service both declare ${hardFail}, and they do not intersect` };
  return {
    plan: {
      protocol: method.protocol,
      version: method.version,
      transport: method.transport,
      endpoint: method.endpoint,
      auth: method.auth,
      completeness: completenessOf(method),
      matchedOn: { protocol: true, version: v, transport: t, auth: a },
      evidence: method.evidence,
      sourceUrl: method.sourceUrl,
      provenance: method.provenance,
    },
  };
}

/* ------------------------------ the planner ------------------------------ */

export function buildConnectionPlan(discovery, clientCaps) {
  const caps = clientCaps && typeof clientCaps === "object" ? clientCaps.client || clientCaps : {};
  const supports = Array.isArray(caps.supports) ? caps.supports : [];
  const prefer = Array.isArray(caps.prefer) ? caps.prefer.map(canonProtocol) : [];
  const supportsByProto = new Map();
  for (const s of supports) supportsByProto.set(canonProtocol(s.protocol), s);

  const allMethods = serviceMethods(discovery);
  // Split connectable endpoints from pointer/catalog leads (see POINTER_PROTOCOLS).
  const methods = allMethods.filter((m) => !isPointer(m.protocol));
  const leadMethods = allMethods.filter((m) => isPointer(m.protocol));
  const leads = [...new Set(leadMethods.map((m) => canonProtocol(m.protocol)))].map((protocol) => ({
    protocol,
    endpoint: (leadMethods.find((m) => canonProtocol(m.protocol) === protocol) || {}).endpoint,
    reason: "pointer/catalog surface — follow it (delegation) to reach endpoints; phase-1 does not",
  }));
  const serviceProtocols = new Set(methods.map((m) => canonProtocol(m.protocol)));

  const plans = [];
  const rejected = []; // service methods the client can't use, with a reason

  for (const method of methods) {
    const proto = canonProtocol(method.protocol);
    const entry = supportsByProto.get(proto);
    if (!entry) {
      rejected.push({ protocol: proto, endpoint: method.endpoint, reason: "client does not support protocol" });
      continue;
    }
    const res = planForEntry(method, entry);
    if (res.plan) plans.push(res.plan);
    else rejected.push({ protocol: proto, endpoint: method.endpoint, reason: res.reason });
  }

  // Deterministic order (documented, no scoring):
  // 1) client prefer index  2) completeness  3) evidence level (1 before 2)
  // 4) protocol name  5) endpoint  — stable for identical inputs, every time.
  const preferIndex = (p) => { const i = prefer.indexOf(canonProtocol(p)); return i === -1 ? prefer.length : i; };
  plans.sort((x, y) =>
    preferIndex(x.protocol) - preferIndex(y.protocol) ||
    COMPLETENESS_RANK[x.completeness] - COMPLETENESS_RANK[y.completeness] ||
    (isLevel1(y.evidence) - isLevel1(x.evidence)) ||
    String(x.protocol).localeCompare(String(y.protocol)) ||
    String(x.endpoint).localeCompare(String(y.endpoint))
  );

  const anyComplete = plans.some((p) => p.completeness === "complete");
  const emptyDiscovery =
    (!discovery.resources || discovery.resources.length === 0) &&
    (!discovery.discovered || discovery.discovered.length === 0);

  let outcome;
  if (emptyDiscovery) outcome = "none-found";
  else if (anyComplete) outcome = "direct-match";
  else if (plans.length) outcome = "protocol-only";
  // Distinguish "only catalogs published, we didn't follow them" from a genuine
  // "your client can't speak anything this service offers".
  else if (methods.length === 0 && leads.length) outcome = "pointers-only";
  else outcome = "no-match";

  // selectedPlan: named ONLY when the client supplied a preference order.
  // No prefer → null (the client chooses; NessGate expresses no preference).
  const selectedPlan =
    prefer.length && plans.length
      ? { protocol: plans[0].protocol, version: plans[0].version, transport: plans[0].transport, reason: "client preference order" }
      : null;

  const clientOnly = [];
  for (const s of supports) {
    const p = canonProtocol(s.protocol);
    if (!serviceProtocols.has(p)) clientOnly.push({ protocol: p, reason: `service publishes no ${p} surface` });
  }
  // De-dupe rejected service protocols the client simply doesn't speak.
  const seenRej = new Set();
  const serviceOffered = rejected.filter((x) => { const k = x.protocol + "|" + x.reason; if (seenRej.has(k)) return false; seenRej.add(k); return true; });

  return {
    domain: discovery.domain,
    discovery, // the /discover answer, verbatim — strictly additive
    match: {
      outcome,
      summary: summarize(outcome, plans, methods, supports),
      clientMethods: supports.length,
      serviceMethods: methods.length,
      compatibleMethods: plans.length,
    },
    connectionPlans: plans,
    selectedPlan,
    unmatched: { serviceOffered, clientOnly },
    leads, // pointer/catalog surfaces a delegating resolver (/explore) could follow
    notes: buildNotes(plans, leads),
  };
}

function summarize(outcome, plans, methods, supports) {
  switch (outcome) {
    case "none-found": return "The domain publishes no machine-readable surfaces.";
    case "pointers-only": return "The domain publishes only pointer/catalog surfaces (e.g. llms.txt, api-catalog); following them (delegation) would be needed to reach connectable endpoints.";
    case "no-match": return `The service offers ${methods.length} connectable method(s), but none use a protocol this client supports.`;
    case "protocol-only": return `${plans.length} compatible protocol(s) found, but connection details (transport/auth/version) are not fully declared — the developer must still consult the source.`;
    case "direct-match": return `${plans.filter((p) => p.completeness === "complete").length} directly usable connection(s) of ${plans.length} compatible; ${methods.length} service method(s) vs ${supports.length} client method(s).`;
    default: return "";
  }
}

function buildNotes(plans, leads = []) {
  const notes = [];
  if (leads.length) notes.push(`${leads.length} pointer/catalog surface(s) (${leads.map((l) => l.protocol).join(", ")}) not followed — phase-1 does not delegate; /explore would.`);
  for (const p of plans) {
    if (p.completeness === "connection-undeclared")
      notes.push(`${p.protocol} @ ${p.endpoint}: protocol matched, but the service does not declare transport/auth — consult ${p.sourceUrl}.`);
    else if (p.completeness === "version-unconfirmed")
      notes.push(`${p.protocol} @ ${p.endpoint}: usable, but the exact protocol version is not asserted by ${p.sourceUrl}.`);
    if (p.auth && p.auth.detail === "inferred")
      notes.push(`${p.protocol} @ ${p.endpoint}: auth requirement was OBSERVED (behavioral probe), not declared in a document.`);
  }
  return notes;
}
