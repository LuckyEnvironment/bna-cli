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

- **Dependencies are pinned to exact commit SHAs** rather than `file:../`
  paths. The local paths only resolved inside the development monorepo, so a
  clean clone produced dangling symlinks, and CI failed on typecheck and four
  test files. These become `^0.1.0` ranges once the `@bna` npm scope is
  published; see CONTRIBUTING.md.

### Fixed

- **`@bna/probe-protocol` is now bundled into the published tarball.** It was
  declared as a dependency but omitted from `bundleDependencies`, so a
  published `npx @bna/cli probe` would have installed cleanly and then thrown
  `MODULE_NOT_FOUND` on first use — breaking the one path that has to work on
  a clean machine.

  `npm run test:package` now derives the expected bundle set from the declared
  dependencies rather than a hard-coded list, so the same class of mistake
  cannot recur silently, and it exercises `probe` from the installed tarball
  rather than `validate` alone.

- **Validation output no longer reads "declared not declared".** The retention
  line prefixed every value with `declared `, including the absent case. Both
  the residency and retention lines now share one helper, so an undeclared
  field reads `not declared, not verifiable externally`.
