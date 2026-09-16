# Contributing to NessGate

Thanks for your interest. NessGate aims to be a small, neutral, open
specification for a compatibility resolver — see the
[Charter](https://nessgate.com/charter) for the commitments that govern it and
the [specification](https://nessgate.com/spec) for the technical contract.

## Two versioned lines
NessGate separates two things, versioned independently under
[Semantic Versioning](https://semver.org/):

- **NessGate Resolver Specification** — the open specification (which standards
  are read, resolution, the normalized response shape). Evolves slowly and
  deliberately.
- **Reference implementation** — the software in this repository. May change
  often without changing the specification.

**Compatibility promise:** a declaration valid under one **major** specification
version keeps working across every later release in that version. A breaking
change would only ever arrive as a new major specification version (e.g. `/v2/`),
with the previous version supported through a long transition.

## How to contribute
- Open an issue to discuss a change before large work.
- Submit changes as pull requests against `main`. `main` is protected; changes
  require review and passing tests (`npm test`) before merging.
- Specification changes (anything touching the resolution contract or response
  shape) must be additive within the current major version, and are called out
  explicitly in the PR and the [changelog](https://nessgate.com/changelog).
- Keep the honesty and neutrality invariants intact: NessGate never ranks,
  never charges to participate, never favors a provider, never stores resource
  content, and never claims adoption it does not have.

## Adding an adapter (support a new standard)

Each standard NessGate reads is a small, independent **adapter** on one of four discovery
**channels**: `well-known` (a fixed path), `link-rel` (a `<link rel>` on the homepage), `robots`
(a `robots.txt` directive), or `dns` (a DoH TXT lookup). Adding support is usually a small PR:

1. **Confirm a concrete, domain-native discovery surface first.** NessGate only reads a location a
   domain itself publishes at a verifiable path. If the discovery mechanism is federated,
   undocumented, or paywalled (so a path would be *guessed*), it does **not** get an adapter — a
   guessed path is fake conformance. This is a firm honesty rule (see the GB/Z note in `README.md`).
2. Add an entry to the `ADAPTERS` array in `src/worker.js` (`id`, `channel`, and the channel's
   locator — e.g. `paths` for `well-known`).
3. If the document has a shape not already covered, extend `probeShapeOk` (reject a generic `{}`
   from being a false-positive discovery) and add a `case` to `normalizeResources` that maps the
   document into `{ source, type, url, sourceUrl }` records — **reuse the source's own type labels;
   invent no taxonomy**.
4. Mirror the exact same pure logic into `public/resolver.mjs`, then copy it to
   `packages/resolver/index.mjs` (the npm package is a single self-contained file). A parity test
   keeps all three byte-identical — run it.
5. Add a conformance test (a sample document → expected records) and update the docs that list the
   supported set: `README.md`, the spec/api pages under `public/`, `public/openapi.json`
   (`checked[]`), `public/llms.txt`, and `public/ai-info.json`.
6. **Add compatibility corpus entries** in `compat/`: an adapter manifest (`compat/adapters/<id>.json`),
   a matrix entry (`compat/matrix.json`), and at least one `positive` and one `reject` fixture under
   `compat/fixtures/`. See `compat/README.md`.
7. `npm run check` must pass (regression + v2 + compatibility corpus + matrix consistency + smoke).

New standards are **outputs of the architecture, never competitors** — a new adapter, not a new
format NessGate defines.

## The compatibility rule (non-negotiable)

> **Never fix a compatibility problem only in code. Every real compatibility fix MUST add a
> permanent regression fixture in `compat/fixtures/`.** A code fix without a fixture fails review.

This is what makes the corpus a durable moat rather than a pile of one-off patches. If an unseen
domain (see `benchmarks/holdout-unseen.json`) teaches a fix, turn it into a fixture and replace it
in the holdout with a fresh unseen domain — never tune against the holdout.

## Independent implementations
You do not need to contribute here to use the specification. Anyone may build a
compatible resolver from the spec, under the
[trademark policy](TRADEMARK.md). Independent implementations are a primary
goal, not a threat.

## Licensing of contributions
By submitting a contribution you agree it is licensed under Apache-2.0 (the
license of this repository). The WordPress plugin is maintained separately
under the GPL, as required by WordPress.org.
