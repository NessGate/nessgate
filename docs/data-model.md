# NessGate data model

One reference for the shapes shared by `GET /discover`, `GET /explore` (including
`?readiness=1`), `POST /connect`, the `@nessgate/resolver` library, and the
experimental inbound-inspection module under `lab/nessgate-inspect/`. Frameworks
that consume NessGate should read this once and handle every surface the same way.

Three contract rules hold everywhere:

1. **Additive only.** Existing fields and enum values keep their meaning; new
   optional fields and new enum values may appear. Clients must ignore unknown
   fields and treat unknown enum values as the weakest nearby meaning
   (an unknown outcome value reads as `incomplete`/`unknown`, never as success).
2. **No numeric scores.** Every judgment is an enum. There is no confidence,
   rating, or ranking field anywhere, and none will be added.
3. **Absence is labeled.** When something could not be checked, the response says
   so with a specific field or value (see [Disclosure vocabulary](#disclosure-vocabulary));
   an empty result is never silently indistinguishable from an unchecked one.

## The observation record

Every NessGate statement, on either side of an interaction, has the same anatomy:

| Part | Meaning |
|---|---|
| subject | what the statement is about — a resource/endpoint a domain publishes, or an identifier/credential an incoming caller presents |
| assertion | what is stated about it, using the source's own labels (NessGate invents no taxonomy) |
| strength | how well the assertion is established, from a small per-axis enum (below) |
| provenance | the reproducible path to the evidence — always present, so any consumer can re-check |
| disclosure | anything that could not be established, stated explicitly |

## Three questions, three axes

NessGate keeps three questions separate and never merges them. A statement can be
strong on one axis and weak on another; no axis upgrades another.

**1. Relationship — why is this associated with the subject?**
The `evidence` field on `/explore` (and on library records produced by the
`registry`/`delegate` options):

| value | meaning |
|---|---|
| `publisher-hosted` | the served document itself, fetched from the domain |
| `publisher-declared` | named inside a document the domain serves |
| `namespace-verified` | attested by a registry that domain-authenticates its namespace; always carries `attribution` naming the registry — NessGate did not verify it itself |
| `same-domain-host` | found on another host of the same registrable domain (`?org=1`); the organizational relationship is not independently verified |
| `candidate` | a caller-supplied URL that NessGate fetched and confirmed is machine-readable; its relationship to the domain is unverified |

Cross-registrable-domain entries live in a separate `related[]` array
(`publisher-declared-related` / `registry-verified-related` /
`infrastructure-correlated-candidate`) and are never merged into `resources[]`.

**2. Verification — did NessGate directly check it?**
The `class` field on library records:

| value | meaning |
|---|---|
| `verified-publisher-location` | fetched and validated on the domain's own registrable domain |
| `verified-external-location` | fetched and validated, but the final URL (after redirects) is on a different registrable domain — library only |
| `publisher-declared` | declared in a fetched catalog, same registrable domain, target not fetched |
| `declared-external-pointer` | declared, different registrable domain, not fetched |
| `unsupported` | no usable URL |

With `?verify=1`, records additionally carry `reachability`
(`ok` / `auth-required` / `rate-limited` / `blocked` / `not-found` /
`unreachable` / `unknown`), `checkedAt`, and an `evidence` object
(`{status, signal, retryAfterSeconds}` — response content is never stored).
`ok` means the endpoint answered a safe request, never that operations succeed.

A record may carry **both** `class` and `evidence` — they answer different
questions and both are kept.

**3. Usability — can a client act on it now?**
The `readiness` block (per connectable resource, with `?readiness=1` /
`opts.readiness`) and the `/connect` / `plan()` outcome:

| value | meaning |
|---|---|
| `ready` | connectable now, no credentials; requires protocol-level evidence appropriate to the transport (e.g. a valid MCP initialize result), never HTTP success alone |
| `credentials-required` | endpoint, transport, auth method and its metadata are all known; only the caller's own secret is missing (it never passes through NessGate) |
| `incomplete` | a connection element the protocol itself defines is not published, or could not be checked; `missing[]` names each item |
| `broken` | the declared location answered and the answer contradicts the declaration (404/410/5xx, or 200 with an unparseable document); claimed only on positive evidence — denials and network failures never read as broken |
| `no-compatible-method` | (`/connect` only) connectable methods exist, but none the client declared support for |

`readiness.verified` records how the check concluded: `ok`, `auth-required`,
`http-200-not-mcp`, `denied:403`, `error:<status>`, `unreachable`,
`skipped:capacity`. `/connect` adds `matchedOn` per dimension with the tri-state
`true` / `false` / `"any"` (client unconstrained) / `"unknown"` (service did not
declare it) — only a declared-vs-declared conflict (`false`) is a hard
incompatibility — and `clientAssumed: true` when no client capabilities were
declared and a broad default was used.

## The caller side (experimental)

The inbound-inspection module (`lab/nessgate-inspect/`) applies the same anatomy
to what an incoming caller presents. Each fact carries one tier:

| tier | meaning | resolver-side analogue |
|---|---|---|
| `claimed` | asserted by the caller, unverified (e.g. a User-Agent) | `publisher-declared` / `declared-external-pointer` (named, not checked) |
| `directory-attributed` | a public directory recognizes a declared identifier; binds nothing | `namespace-verified` (third party attests; NessGate did not verify) — note the registry case is domain-authenticated and therefore stronger |
| `cryptographically-verified` | a signature validates against the caller's published key, binding this request | `verified-publisher-location` / readiness `verified: ok` (direct observation) |
| `network-verified` | the source IP belongs to infrastructure the operator documents for its bot, by that operator's own method | same band as above; verifies origin rather than the message |
| `unknown` | absent or indeterminate | `unknown` / disclosed-unavailable states |

The same rules apply: provenance on every fact, no scores, explicit notes for
what a verification does **not** establish, failures fall back to the weaker
tier rather than fabricating either success or an accusation. This module is
experimental; its field names may still change, the principles will not.

## Auth descriptor

Wherever authentication metadata appears (readiness, `/connect`, `plan()`), the
same object shape is used, populated only from what the service published:

```
auth: {
  required: boolean,
  type,                       // the source's own label: "oauth2", "http:bearer", "apiKey", …
  authorizationEndpoint?, tokenEndpoint?,   // from RFC 8414 / OpenAPI flows
  scopes?, grantTypes?,
  dynamicClientRegistration?, registrationEndpoint?
}
```

## Provenance forms

Provenance is a breadcrumb trail for re-checking, not a schema. Consumers must
treat entries as opaque. Forms in use:

- an array of URLs — the fetch chain, every hop (`/explore`, delegated records);
- prefixed markers — `"mcp-registry:<namespace>"`, `"org:<host>"`,
  `"ai-candidate"`, `"dns:_agent.<domain>"`;
- an array of objects — `{source, header}` / `{source, url, keyid}` /
  `{source, sourceIp}` (inbound-inspection facts).

## Disclosure vocabulary

Every "could not check" state and where it appears:

| field / value | surface | meaning |
|---|---|---|
| `outcome: "blocked"` | discover, explore, library | refusals were at least as common as clean answers; absence is unknown |
| `outcome: "incomplete"` | explore, library | budgets or the deadline cut the walk short |
| `blockedProbes: n` | all resolver surfaces | count of refused probes, disclosed even under `none-found` |
| `federatedUnavailable: ["mcp-registry"]` | explore, library | the registry could not be checked; absence of registry results is not checked-and-empty |
| `delegation.truncated: true` | library (`delegate`) | the pointer walk hit a depth/request/host/byte limit |
| `readiness.verified: "skipped:capacity"` | hosted readiness | the platform request budget was exhausted before assessment; a capacity condition of the request, not a fact about the service |
| `missing[]` | readiness, connect | each connection element that is not published or could not be established, named individually |
| `orgBlocked` | explore `?org=1` | org-check hosts that refused every probe; absence there is unknown |
| tier `unknown` + `reason` | inbound inspection | a check ran and did not conclude; the reason is stated |

## Consuming the model (one pattern)

For any record from any surface:

1. **Strength:** take the strongest applicable axis value — a verification-axis
   value (`verified-*`, `ok`, a verified tier) outranks an attribution
   (`namespace-verified`, `directory-attributed`), which outranks a bare
   declaration (`publisher-declared`, `claimed`). Never sum or score across axes.
2. **Usability:** act only on `ready` / `credentials-required`; surface
   `missing[]` for `incomplete`; treat `broken` as a service-side defect report;
   treat any unknown enum value as `incomplete`.
3. **Re-check:** every claim carries provenance; a consumer that needs certainty
   follows it to the source rather than trusting the summary.
4. **Honor disclosures:** before concluding "nothing exists", check the
   disclosure fields above — an unavailable source or truncated walk means
   "unknown", not "absent".
