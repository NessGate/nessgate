# Related Discovery — evidence and promotion rules

Rules for the cross-registrable-domain "related" layer of `/explore` (opt-in, `?related=1`).
Exact-host results stay authoritative and are never mixed with this layer: related results are
returned in a separate `related[]` array, each entry carrying its evidence class, the full
provenance for that class, and any corroborating signals — cited, never promoted.

## The three classes (exhaustive)

### `publisher-declared-related` — strong
The **queried domain itself serves a purpose-built, machine-readable declaration** naming the
candidate registrable domain. Qualifying surfaces:

- A Related Website Set file at `/.well-known/related-website-set.json` listing the candidate
  (`associatedSites`, `serviceSites`, or ccTLD variants). **Legacy:** Chrome retired RWS in its
  October 2025 Privacy Sandbox wind-down, so this is treated as a live publisher declaration —
  which it literally remains, served by the domain — not as an active browser standard. Where the
  candidate serves a reciprocal file naming the queried domain as `primary`, the entry is marked
  `mutual: true` (verified with one additional bounded fetch).
- A Digital Asset Links `web`-namespace statement at `/.well-known/assetlinks.json` targeting the
  candidate site.

**Not qualifying, ever:** hyperlinks. An `<a href>` on a homepage, a markdown link in a document,
or any incidental URL reference — even when mutual — is navigation, not a relationship
declaration, and is never proof of common ownership. (Pointers inside `llms.txt`/ARD catalogs
continue to yield `publisher-declared` *resources* in the main list, as today; they do not create
*relationship* claims about the target host.)

### `registry-verified-related` — strong, attributed
An **external registry that verified control of a namespace names the specific candidate**.
Today that is the official MCP Registry: a domain-authenticated `com.<domain>/*` entry whose
remote URL lives on a cross-registrable-domain host. Always attributed ("the registry reports…");
NessGate never restates the registry's verification as its own. A registry signal that does not
name the specific domain (for example GitHub's `is_verified` boolean, which does not disclose
*which* domains were verified) does **not** qualify.

### `infrastructure-correlated-candidate` — corroborating only
Technical co-control signals, **singly or in any combination**, never establish "official" or
"same organization." They may annotate an entry of any class, and on their own they produce at
most this class. Signals, each cited precisely in `signals[]`:

- **NS containment** — the candidate's authoritative nameservers are hosts under the queried
  domain (e.g. `youtube.com` served by `ns1–4.google.com`). Caveat: inverts for DNS providers.
- **Certificate SAN co-occurrence** — the candidate's TLS certificate includes names under the
  queried domain. Proves a shared certificate holder, which can be shared hosting infrastructure.
  (Not implementable from Workers, which cannot inspect peer certificates; available to Node-side
  tooling only — documented for parity, unused in the hosted resolver.)
- **GitHub organization verification** — `is_verified` plus an org-declared website. Boolean
  only; the verified-domain list is not exposed by the public API.
- **Homepage or document links** — enumeration hints only.

## Promotion rules

1. `publisher-declared-related` ⟺ a qualifying declaration served by the queried domain names
   the candidate. Nothing else reaches this class.
2. `registry-verified-related` ⟺ a domain-verifying registry names the specific candidate;
   attributed.
3. Corroborating signals never create or upgrade a class — not alone, not combined. They are
   recorded in `signals[]` wherever observed.
4. Anything reachable only through hints (links, caller suggestions) with at least one verified
   machine-readable resource but no qualifying declaration is `infrastructure-correlated-candidate`
   (with signals) or remains plain `candidate` (without).
5. Related entries never appear in `resources[]` and exact-host results never appear in
   `related[]`. Wording never asserts ownership: even the strong classes state what was declared
   or reported, by whom, with the source URL.

## Bounds (per request, shared with the existing budget)

Enumeration only from: the queried domain's own RWS/assetlinks files (2 fetches), already-fetched
registry records, and caller-supplied candidates. At most 5 related hosts examined; per host: one
reciprocal-declaration fetch, two resource probes (`/llms.txt`, `/.well-known/ard.json`), one DoH
NS lookup. Global request/host/byte/deadline budgets apply unchanged. No crawling, no search
engines, no guessed hosts.

## Worked examples (verified live, 2026-09-14)

**google.com** — serves a legacy RWS file declaring `youtube.com`, `android.com` (associated) and
`googleusercontent.com` (service); all three serve reciprocal files naming `google.com` as
primary. Expected: three `publisher-declared-related` entries, `mutual: true`, with NS-containment
recorded in `signals[]` (`ns1–4.google.com`), plus any resources verified on those hosts. What a
user learns: Google's declared related sites — without knowing them in advance.
`googleapis.com` / `google.dev`: no declaration names them; if supplied as candidates they can
gain NS/SAN signals → at most `infrastructure-correlated-candidate`, never "official".

**microsoft.com** — no RWS file (404), no `com.microsoft` MCP-registry namespace. Expected:
`related[]` empty by default. A caller-supplied `microsoft.github.io` has no qualifying
declaration and no NS containment (NS1-hosted) → remains plain `candidate`; GitHub's `is_verified`
may be cited as a signal where available. Honest gap: only Microsoft publishing a declaration can
change this.

**openai.com** — no RWS file (404), no `com.openai` registry namespace. Expected: `related[]`
empty; the same-domain layer (`?org=1`) already covers `developers.openai.com` separately as
`same-domain-host`.

These examples avoid overclaiming by construction: strong classes only restate a declaration or an
attributed registry record; every technical signal is quoted, labeled corroborating, and never
promoted.
