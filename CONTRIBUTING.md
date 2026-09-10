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

## Independent implementations
You do not need to contribute here to use the specification. Anyone may build a
compatible resolver from the spec, under the
[trademark policy](TRADEMARK.md). Independent implementations are a primary
goal, not a threat.

## Licensing of contributions
By submitting a contribution you agree it is licensed under Apache-2.0 (the
license of this repository). The WordPress plugin is maintained separately
under the GPL, as required by WordPress.org.
