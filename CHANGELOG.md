# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — M3, reconciliation

- **`bna reconcile --agent <id> --access-log <path>`** — check BNA's published
  measurements of you against your own access log. Streams nginx combined,
  nginx JSON and Caddy JSON, with `--nonce-field` for any other shape, and
  auto-detects by sniffing the first lines. No account, no key, no network
  beyond fetching public leaves. Exit 0 clean, 1 discrepancies, 2 malformed
  input, 3 fetch failure.

  Named `reconcile`, not `witness`: a *witness* is the party that co-signs tree
  heads in M4, and overloading the word would collide the two roles exactly
  where telling them apart matters. `SURFACE-05-witness.md` is updated.

- **The guard that makes this safe to ship.** nginx does not log request
  headers by default, so the overwhelmingly likely first run finds zero nonces
  in a perfectly good log. Reporting that as "all 760 of BNA's observations are
  fabricated" would make this a tool for manufacturing false accusations
  against BNA — a strange thing for BNA to ship. Zero nonces in a non-empty log
  exits 2 with the `log_format` line needed to fix it, and never reports a
  contradiction.

- `npm run verify:streaming` — generates a multi-gigabyte log and reads it
  under a hard `--max-old-space-size` ceiling. Outside `npm run check`, like
  the container verification, because a suite people skip protects nothing.

### Changed

- **`audit-score` step 4 is now "no poisoned leaf *contributed* to the score"**,
  where it was "no poisoned leaf is *present*". A bundle discloses the
  observations that had a contradiction upheld against them and excludes them
  from the arithmetic — excluded, not deleted. The previous rule would have
  failed an honest bundle for being transparent about BNA's own errors.

### Added — M2, countersigning

- `audit-score` now discloses evidence-grade counts: how many observations the
  observed party countersigned. **Disclosure only.** The counts appear beside
  the verdict and in `--json`, and the output says so in words: a countersigned
  observation is worth exactly what an uncountersigned one is.

- `bna validate` reports `x-bna.probe-key` as informational. An undeclared probe
  key adds `· 1 informational, no verdict` to the summary and leaves a
  conformant card scoring `ok`.

### Changed

- **One JWS implementation.** `signDetachedJws` and `verifyDetachedJws` keep
  their envelope checks — each maps to an exit code and an actionable message —
  but the JOSE handling now comes from `@bna/witness-log`. Two implementations
  were free to drift on exactly the parsing edge cases the receipt replay suite
  exists to catch. Both are now `async`, because the shared module has to run
  in a browser and WebCrypto has no synchronous verify.

- **Dependencies are `file:../` again**, all three of them. The git-SHA pins
  resolved to commits predating this work, so the CLI was validating against a
  card schema without `x-bna.probe-key` and reporting 15 fields where the
  package now has 16. These must become SHA pins, and then `^0.1.0` ranges,
  before publish — a clean clone will not install as it stands. Tracked in
  `docs/ROADMAP.md`.

### Added

- **`bna audit-score <agentId> --period <YYYY-MM>`** — verify that a published
  score is backed by the transparency log. Four checks, all offline after the
  fetch: every leaf has a valid inclusion proof against the bundle's tree head;
  that tree head is consistent with one you recorded independently; re-running
  the probe protocol's §2.3 arithmetic over the leaves reproduces the claimed
  figures exactly; and no leaf is graded `poisoned`.

  The arithmetic is `aggregate` from `@bna/probe-protocol`, called rather than
  reimplemented. A verifier with its own copy of the scoring rule would agree
  with a bundle whenever both were wrong in the same way, which is the one
  failure this command exists to catch.

  `--bundle <file>` verifies a saved bundle offline; otherwise the bundle is
  fetched from `--log-base`, default `https://transparency.bna.dev`, which does
  not serve bundles yet.

- **Probe nonces.** Every probe generates 16 cryptographically random bytes,
  sends them as `BNA-Probe-Nonce`, and commits them into an observation leaf
  **before the request is sent**, alongside `requestedAt`. The nonce is what
  lets the observed party check BNA's claim against their own access log later:
  a logged observation with no matching request is a measurement that never
  happened, and it becomes provable by the vendor from data BNA published.

  The ordering is enforced structurally, not by convention. `openObservation`
  is the only source of both the nonce and the request headers carrying it, so
  a probe cannot be sent without having committed first, and `sealObservation`
  can only copy a commitment it is handed — a spread copy is refused by
  identity. The end-to-end test asserts the nonce in the emitted leaf is the
  one the *server* received, which fails if the leaf is ever built after the
  response is read.

- `BNA-Probe-Receipt` is captured verbatim into `leaf.receipt` and **not
  verified** at this milestone. A vendor who does not send one is not
  penalised: the outcome is decided by the response, never by whether a receipt
  was offered.

- `observations` in `probe --json` output — one leaf per sample. They travel
  beside the summary rather than inside it, because a probe-protocol summary is
  a published shape with `additionalProperties: false` that belongs to the
  specification rather than to this tool.

### Changed

- `responseDigest` covers a normalised response **head** only — the status and
  a fixed allowlist of headers, lowercased and sorted. The body is cancelled,
  never read. This is a retention commitment rather than an optimisation: the
  log cannot become a copy of what agents returned, which is what the
  zero-retention posture agent cards declare depends on.

### Added

- Safe URL fetching, honest local validation display, versioned JSON output,
  detached-JWS signing and verification, and probe etiquette safeguards.
- `@bna/probe-protocol` as a dependency, so the probe procedure and its result
  format come from the published specification rather than being restated here.
- `test/probe-protocol.test.js`, which runs the real command and validates its
  output against the published probe-summary schema. The CLI cannot drift away
  from the specification without this going red.
- `npm run verify:container` — packs the working tree and exercises the
  resulting tarball in a disposable Linux container on Node 20, 22 and 24,
  with `--network none`. Severing the network is what makes the run evidence
  rather than assertion: the install can only succeed if the tarball is
  self-contained, and no telemetry is possible even in principle. It checks
  the first-run transcript, all five documented exit codes, `--json` stdout
  purity, and conformance of probe output to the published schema.

  Covers Linux only, and ARM64 on Apple Silicon. It complements the CI matrix
  rather than replacing it.

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
