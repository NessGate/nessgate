# Launch post — draft

Positioning to hold throughout: NessGate is the smallest neutral primitive, it *reads* standards
rather than defining one, the domain is always the authority, nothing is stored or crawled, and it
is interoperable with (never a competitor to) ARD / AI-Catalog / DNS-AID / MCP / A2A. No "first",
no adoption numbers we can't back, no ranking, no fee.

---

## Show HN title

Show HN: NessGate – one call to find what a domain publishes for AI agents

(Alternate: "Show HN: A universal resolver for the agentic web (reads ARD, A2A, llms.txt, MCP…)")

## Show HN body

**NessGate is a zero-registration, domain-native universal discovery resolver for the agentic web.**

An agent that lands on a domain has to guess where the machine-readable stuff is: `llms.txt`?
`/.well-known/ai-catalog.json`? an A2A agent card? an OpenAPI file? an api-catalog linkset? a DNS
record? Every standard put it somewhere different, and more keep appearing.

NessGate is that resolver. Give it a domain and it reads whatever the domain already
publishes — across ARD (all three surfaces: well-known, `rel="ard"`, robots `Agentmap:`), A2A,
`llms.txt`, RFC 9727 api-catalog, OpenAPI, Open Resource Discovery, RFC 6415 host-meta, ANP, UCP,
DNS-AID and more — and returns one normalized answer, with a link back to each source so the agent
can verify against the domain itself.

    company.com → { resources: [
      { source: "ard-catalog", type: "application/json",
        url: "https://company.com/ai-info.json",
        sourceUrl: "https://company.com/.well-known/ard.json" }, … ] }

One call instead of ten. It reads these standards; it doesn't define or replace them — a new
standard is just a new adapter, never a competitor. The domain is always the authority; NessGate
normalizes what the domain already serves, reads it on demand, and stores nothing. No accounts,
no crawling, no index, no ranking, no fee, and it makes no ownership or safety claim.

Three ways to use it, all no-auth:

- Library: `npm i @nessgate/resolver` → `const { resources } = await resolve("example.com")`
  (dependency-free; runs anywhere with `fetch` — Node, Deno, Workers, agent runtimes; fetches the
  domain directly, so no runtime dependency on nessgate.com).
- HTTP: `curl https://nessgate.com/discover/example.com` (open CORS — use this from a browser).
- MCP: the same lookup as a `discover_domain` tool at `https://nessgate.com/mcp`, listed in the
  official MCP Registry as `com.nessgate/nessgate`.

The spec is open and the reference implementation is Apache-2.0 — anyone can run their own
resolver, and if nessgate.com went away every domain's files would still stand on the domain.
Neutrality is written down in a Charter (never charge to use or be read, never sell placement,
keep no accounts, store no domain data).

Code: https://github.com/NessGate/nessgate · Live: https://nessgate.com ·
Spec: https://nessgate.com/spec · Charter: https://nessgate.com/charter

Honest about limits: ANP and UCP are emerging and DNS-AID/AWP are drafts (read as-is, labeled as
such). China's GB/Z 185.4/185.5 is deliberately **not** implemented — the discovery mechanism is
only in the paywalled national standard and looks federated rather than domain-native, so there's
no concrete surface to probe yet. The adapter architecture is ready to host it once the endpoint
is verifiable; until then NessGate makes no GB/Z claim.

Feedback especially wanted on: which discovery standards to add next, and whether the normalized
record shape (`{ source, type, url, sourceUrl }`) is the right lowest common denominator.

---

## First comment (post immediately, from the author account)

A few things I deliberately left out and why:

- No storage or crawling. Every answer is computed live from the domain and cached at the edge for
  ~10 minutes; nothing is retained. That means NessGate can't rank or "own" anything — by design.
- No new format. If your domain already publishes `llms.txt` or an ARD catalog, you're already
  discoverable; NessGate just reads it. If you publish nothing, the honest answer is "nothing
  found," with the list of locations checked.
- SSRF was the main thing to get right for a service that fetches arbitrary domains: HTTPS-only,
  on-domain redirects only (≤3), 1 MB / 8 s caps, and a DoH pre-check against private/reserved IPs.
  Notes are in `src/worker.js`.

Happy to add adapters — a standard with a concrete, domain-native discovery path is a small PR.
