# Readiness verification — observation semantics (DRAFT)

Status: **PROPOSAL — nothing implemented, nothing active.** Date: 2026-09-27.
Status: this document is a published specification draft for observation semantics. A hosted
standing verdict would require persistence and scheduled re-verification, which the active
charter does not permit — so everything here describes how such observations WOULD be
classified, and the only shipped implementation is the client-side self-test below.

Grounding: a verdict-stability experiment (2026-09-27; repeated identical observations of the same endpoints from one vantage). Its findings are the reason every rule below
exists; none of this is speculative design.

## 1. What a verified-readiness result would mean — and what it never means

A domain's connectable surface is **verified ready** when a published, versioned, machine-verifiable
predicate passes under the observation semantics below. It is a **reproducible measurement, not an
endorsement**: no safety claim, no quality claim, no ownership claim, no ranking among Ready
services. It is never purchasable, never subjective, and never a score.

The verdict is a claim of the form:

> Under predicate version `P`, from vantage class `V`, over observation window `W`,
> the majority of independent observations satisfied the requirements for `<protocol>`.

Every element (`P`, `V`, `W`, the per-observation evidence) is recorded and republishable, so any
independent party running the open checker from a comparable vantage over a comparable window
reaches the same verdict class. Trust derives from reproducibility, not from the issuer: NessGate is the reference
implementation of a public predicate, not an authority.

## 2. Why single observations can never ground a verdict (measured, not argued)

The stability experiment measured the readiness pipeline over repeated runs and vantages:

| Finding | Data | Rule it forces |
|---|---|---|
| Service-side variance | one measured service, identical frozen discovery: handshake `ok` 2/3, rejected 1/3 | **N-of-M majority** (§4) |
| One dropped hop flips a verdict | a single failed RFC 8414 fetch turned `credentials-required` into `incomplete` | **per-hop retries** (§5) |
| Verdicts are vantage-relative | two measured services: OpenAPI fetch fails 3/3 from one vantage, differs at the edge | **named vantage class** (§3) |
| The observer can be the flaky part | 6 `fetch failed` errors from the experiment machine — including to nessgate.com | vantage quality requirements (§3) |
| Denials are ambiguous | bare 403: authorization OR bot-wall — undecidable from a safe probe | **`undetermined` never counts as failure evidence** (§6) |
| Stable when the network cooperates | two measured OAuth chains: 3/3 byte-identical verdicts | the predicate itself is certifiable, given these semantics |

## 3. Vantage (`V`)

- Every observation names its **vantage class**: e.g. `edge:<provider>` (production-grade egress) or
  `local:<unspecified>`. Verification observations MUST come from a vantage class with a published
  reliability baseline (the vantage must first pass a self-check: N consecutive successful control
  fetches of a known-good reference endpoint). A vantage that fails its control is disqualified for
  that window — its observations are discarded, not counted as service failures.
- A verdict is scoped to its vantage class. "Ready from `edge:*`" makes no claim about reachability
  from inside a corporate network, and says so.

## 4. Observations and the majority rule (`W`, N-of-M)

- One **observation** = one full readiness assessment (discovery evidence → protocol requirements →
  safe handshake / metadata chain) executed to completion under §5.
- Reference defaults (spec values, tunable per predicate version, never per customer):
  **M = 5 observations**, spaced **≥ 30 minutes** apart, within a window **W = 48 hours**, from
  **≥ 2 distinct egress points** of the vantage class. Spacing decorrelates caches, deploys, and
  transient conditions; multiple egress points decorrelate per-IP walls.
- Verdict: **Ready requires ≥ 4 of 5 observations to pass.** 3/5 or a quorum failure (fewer than 4
  valid observations after vantage disqualification) yields **`undetermined` — never Ready and
  never Broken.** `undetermined` is a first-class published result; a service can be honestly
  unmeasurable.
- **Broken requires the same bar in reverse**: ≥ 4 of 5 observations with *positive* failure
  evidence (the service answered and the answer contradicts the declaration — the
  `assessFetchFailure` rule already shipped in 1.16.0). Mixed results are `unstable`, reported as
  such — a mixed-observation endpoint under this predicate is `unstable`, which is the truthful description.

## 5. Per-hop semantics within one observation

- Every metadata hop (protected-resource metadata, authorization-server metadata, spec fetch, card
  fetch) gets **K = 2 retries** (3 attempts total, bounded backoff) before the hop counts as failed
  *within that observation*. This absorbs a single-dropped-hop flip without masking a dead
  endpoint (which fails all attempts, in all observations).
- All existing bounds carry over unchanged: read-only, HTTPS-only, SSRF-guarded, byte/time-capped,
  no credentials ever sent. Retries respect `Retry-After` and never tighten the request rate beyond
  the published per-observation budget.

## 6. Evidence classification (unchanged from the shipped resolver — restated as predicate law)

- `broken` only on positive evidence (answered 404/410/5xx, or 200-unparseable). **Denials (401/403
  without protocol evidence) and network failures are `undetermined` inputs**: they can prevent
  Ready, but can never establish Broken. NessGate identifies walls; it never evades them and never
  blames the service for them.
- The verification/relationship split is preserved: verification reads the **readiness axis only**.
  Evidence classes (`publisher-hosted` / `publisher-declared` / `namespace-verified`) are reported
  alongside, never merged into the verdict (the two-axis rule: verification never upgrades relationship).

## 7. Per-protocol requirements (the predicate content, `P`)

Machine-verifiable, versioned, published before use. Initial sketch — each item is checkable by the
already-shipped assessors:

- **MCP**: the declared endpoint completes `initialize` (Ready-open), OR returns an auth challenge
  whose RFC 9728 → RFC 8414 chain resolves to `authorization_endpoint` + `token_endpoint`
  (Ready-with-credentials). Version string negotiable pre-auth is recorded when available, required
  when the server exposes it.
- **OpenAPI**: reachable, parseable document declaring `servers[]`, at least one `securitySchemes`
  entry (or explicitly none), and the `openapi`/`swagger` version string.
- **A2A**: reachable, parseable card declaring transport (`preferredTransport`/interfaces/usable
  `url`) and `protocolVersion`; security schemes present or legitimately absent.

`Ready` sub-labels stay honest: `ready-open` (no credentials) vs `ready-with-credentials`
(everything known except the caller's secret) — mirroring the shipped outcomes.

## 8. Verdict lifecycle

- A verdict carries `predicateVersion`, `vantageClass`, `window`, per-observation evidence digests,
  and an **expiry** (reference: 7 days). Expiry without re-verification demotes to `stale`, never
  silently retained — the v2 principle that a past attestation never keeps a dead resource
  "official."
- Publishers can trigger re-verification at any time (rate-limited); there is no fee, no queue
  priority for anyone, and no path to a verdict other than passing the predicate.

## 8b. Shipped already: the self-test profile

A **CI profile** of this predicate ships as an open tool in `@nessgate/resolver` (bin
`nessgate-ready`): back-to-back observations (default 3), unanimity required (the strict small-N
mapping of §4's ≥80% rule), client-side execution on the publisher's own compute — so it needs no
persistence and no hosted verdict. It implements the self-check today: publishers get pass/fail plus the exact missing field in CI, and anyone can re-run the same predicate. The hosted standing verdict described in this document is not shipped.

## 9. Out of scope, explicitly

Badges/logos programs, any storage or scheduling implementation, any
subjective review, any ranking among Ready services, and any change to the shipped
resolver behavior. This document is the *semantics*; implementation is a later, separately gated
stage.

## 10. Open questions for review

1. Is 4-of-5 over 48h the right reference strictness, or should Ready require passing in **two**
   consecutive windows before first issuance?
2. Should `unstable` (mixed observations) be published as its own verdict, or fold into `undetermined`?
   (Draft position: publish it — it is the most actionable signal a flaky service can receive.)
3. Minimum distinct egress points: 2 (draft) or 3?
4. Does the charter v2 draft's read-scope language cover scheduled re-verification fetches, or does
   it need one clarifying sentence before stage-4 work begins?
