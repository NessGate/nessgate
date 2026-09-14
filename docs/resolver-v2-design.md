# NessGate Resolver v2 — bounded evidence resolution (design)

Status: **implemented** (the `/explore` endpoint). This document records the design rationale and
constraints behind evidence-based resolution — why it exists, what it deliberately is not, and the
limits and evidence model it was built with from day one. `/discover` is unchanged.

## The problem

NessGate today is an **exact-host resolver**: given `example.com`, it checks standard locations on
`example.com`. But real machine-readable resources often live elsewhere the domain *leads to*:

- OpenAI's `developers.openai.com/llms.txt` is an **index** pointing to many more machine-readable
  files (API, Codex, commerce, agents, Cookbook…).
- Microsoft's Teams SDK `llms.txt` is at `microsoft.github.io/teams-sdk/llms_docs/llms.txt` — a
  *different registrable domain* (`github.io`), buried several path levels deep.

So the honest problem is not "find files on a host." It is: **given a domain, resolve the
machine-readable capabilities it *verifiably leads to* — and show exactly why each was included.**

## The hard constraint (what v2 must NOT become)

NessGate's trust rests on being a **live, stateless, auditable primitive**, not a crawler or a
stored directory. ARD registries, AGNTCY, NANDA and the MCP Registry already play the
crawl/index/directory role. If NessGate stores a global capability map, it (a) breaks its
no-storage/no-index red line, (b) invites "why is our data in your catalog," and (c) enters a
crowded, high-kill-risk space. **Decision: v2 is a bounded evidence resolver. No persistent map, no
global crawl, no brute-force subdomain scanning, no AI deciding ownership. Everything is computed per
request and discarded with the edge cache.**

## Model: an evidence *tree*, not a knowledge graph

"Knowledge graph" implies NessGate *knows* Microsoft owns X. It doesn't, and shouldn't claim to. v2
builds a per-request **evidence tree**: each node is a host / catalog / registry entry / resource;
each edge records **why** NessGate followed it and **how strong** that evidence is. NessGate reports
what the evidence says — it makes no ownership judgment.

```
microsoft.com
├── exact-host            → (nothing found)
├── registry (MCP)        → com.microsoft/...   [namespace-verified: registry authenticated the namespace against microsoft.com]
└── publisher-declared    → (declared cross-host pointers, if any)
```

### Evidence classes (replaces any single "verified" flag)

Every resource carries exactly one class — no vague numeric scores:

1. **publisher-hosted** — served directly by the entered host. (Strongest; what v1 does today.)
2. **publisher-declared** — the host explicitly pointed to this resource/other host (ARD entry,
   `rel="ard"`, Agentmap, api-catalog link, an `llms.txt` link, a declared cross-host catalog). The
   evidence is: *the domain named it.* Not proof of ownership of the target, only of reference.
3. **namespace-verified** — an external registry independently verified control of the namespace
   (e.g. MCP Registry domain-authenticated reverse-DNS). Attributed to the registry.
4. **registry-reported** — an external registry lists it, with attribution; weaker than (3).
5. **candidate** — inferred by search/AI; **never** treated as authoritative.

## Layers (each deterministic except the last)

1. **Exact-host** — unchanged v1. Fast, stateless, auditable.
2. **Publisher-declared pointers** — follow *explicit* machine-readable pointers the host published,
   including **standards-authorized cross-host delegation** (if `example.com`'s `ard.json` names
   `cdn.com/x.json`, that is evidence the domain supplied, not a guess). **Exploit `llms.txt` as a
   discovery index**, not just a resource: once a trusted `llms.txt` is found, parse its links and
   report them as `publisher-declared`.
3. **Attributed registries** — query registries that already verify namespaces (MCP Registry read
   API first). Report as `namespace-verified` / `registry-reported`, **attributed to the registry**
   — NessGate never re-claims the registry's verification as its own.
4. **Candidates (optional, out of the deterministic core)** — an opt-in layer where an agent may
   inspect docs/sitemaps/search to *suggest* resources. Output is always class `candidate`, clearly
   unverified; **AI never establishes ownership.** Kept out of the free hosted deterministic core so
   nessgate.com stays fast, free, and auditable.

5. **Organization Discovery (opt-in, `?org=1`)** — probes a *bounded* set of plausible
   same-registrable-domain hosts: subdomains the homepage itself links to, plus a small fixed
   conventional shortlist (`developers`, `docs`, `api`, …; at most 4 hosts × 2 paths). Only
   resources that actually verify are reported, as evidence class **`same-org-host`** — shared DNS
   control implies the organizational relationship; it is not independently verified. This solves
   the "resources live on `developers.example.com`" case. It deliberately does **not** solve
   cross-registrable-domain cases (`github.io` ≠ `microsoft.com`) — those need caller-supplied
   candidates (layer 4). **No brute-force subdomain scanning** — the probe set is small, fixed, and
   verified-only, and off by default.

## Hard limits (designed in from day one)

Once a publisher can tell NessGate where to fetch next, that is an amplification/SSRF surface.
Enforced per request:

- max depth: **2**
- max distinct external hosts: **5–10**
- max total requests: **20–30**
- max **global** bytes (not only per-response)
- HTTPS only; **public-IP check on every hop** (not just the entered host)
- redirects bounded **and revalidated** at each hop (still HTTPS + public IP + on allowed host)
- no arbitrary content proxying (NessGate returns records + provenance, never rehosts bodies)
- cycle / duplicate detection
- per-IP rate limits (as today)

## ARD status (verified against ard-spec, 2026-09)

ARD v0.91 §5.1 lists five publication surfaces but its **only normative MUSTs are: fetch
`/.well-known/ard.json` and honour `rel="ard"`.** NessGate already meets both, plus Agentmap.

- **In-page JSON-LD** — found only via general web crawling, which NessGate deliberately does not do.
  **Out of scope** (would make NessGate a crawler).
- **DNS Service Binding** — §5.1 gives example names (`_entries._agents…`, `_search._agents…`) but
  **no record type and no SvcParam keys** — non-normative and underspecified. **Not implementable
  without guessing** (= fake conformance). Revisit when ARD formalizes it.

## Output shape (v2)

Separate **exact-host** from **related**, and attach an evidence class + provenance edge to every
record, so an empty exact-host result never reads as "this company has nothing." Provenance chains
(e.g. `microsoft.com → MCP Registry → com.microsoft/…`) become a first-class feature.

## Positioning

Evolve from "domain → machine-readable resources" toward **"one domain — every AI capability it
*verifiably* leads to, with the evidence for each,"** where *verifiably* = publisher-declared or
registry-verified, computed live, stored nowhere. Harder to reproduce than "check N URLs"; still the
smallest neutral primitive, not a directory.

## Implementation status

All deterministic layers are live in `/explore`: bounded delegated discovery of publisher-declared
pointers, the evidence classes and provenance chains, attributed MCP-Registry federation, and the
opt-in candidate-verification POST. Exact-host empty results say "no supported resources found on
this exact host" (related hosts or registries may publish more). The design's hard "no"s remain
binding: no persistent map, no global crawl, no brute-force subdomain scanning, no AI-established
ownership. Organization Discovery (`?org=1`) is live as the opt-in bounded related-host layer.
