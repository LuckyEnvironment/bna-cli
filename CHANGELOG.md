# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Safe URL fetching, honest local validation display, versioned JSON output,
  detached-JWS signing and verification, and probe etiquette safeguards.
- `@bna/probe-protocol` as a dependency, so the probe procedure and its result
  format come from the published specification rather than being restated here.
- `test/probe-protocol.test.js`, which runs the real command and validates its
  output against the published probe-summary schema. The CLI cannot drift away
  from the specification without this going red.

### Changed

- **`--json` probe output**: `result.summary` is now a conformant
  `probe-protocol` summary. It gains `specVersion`, and `samples` moves from
  `result.samples` to `result.summary.samples`.

  This is a breaking change to the `--json` contract, made before the first
  release rather than after. The reason is the one in the build brief: where
  the CLI and the specification disagreed, the specification is what BNA
  promised in public, so the CLI changed. The result is that a probe summary
  emitted by this tool is the same artefact the hosted service emits, and can
  be checked against the same schema by someone who trusts neither.
