# Contributing

Thank you for helping make BNA's verification tooling auditable.

Please open an issue before substantial work, keep pull requests focused, and
run `npm run check` before submitting a change. BNA is maintained by one
person alongside a company, so responses are best effort, typically within one
week.

Do not include credentials, personal data, or live customer endpoints in an
issue or pull request. Report security vulnerabilities privately as described
in [SECURITY.md](./SECURITY.md).

## Compatibility and schema changes

Do not change a result or output schema incompatibly without a major version
bump and release notes. Changes to an existing score-affecting card field must
be a major schema version, announced 30 days in advance, with prior-version
results retained for comparison.

## Runtime dependencies

This package has two runtime dependencies, both first-party, and **both must
appear in `bundleDependencies`**. The published tarball has to be
self-contained: `npx @bna/cli` on a clean machine must work with no further
downloads, and a dependency that is declared but not bundled produces a tarball
that installs cleanly and then throws `MODULE_NOT_FOUND` on first use.

`npm run test:package` enforces this. It packs the tarball, installs it with
`--offline` so no registry or git access is possible, and exercises every
command including `probe`. Adding a dependency without bundling it fails that
test rather than reaching a user.

`npm run verify:container` is the stronger form of the same check and should be
run before any release. It installs the packed tarball in a disposable Linux
container with `--network none`, on Node 20, 22 and 24. Run it whenever you
change dependencies, the `files` allowlist, `bundleDependencies`, or anything
in `bin/`.

Do not add a third-party runtime dependency without justifying it in the issue:
what it does, why the standard library will not, its transitive count, and its
maintenance status.

### Migrating off the pinned git dependencies

`@bna/validator-core` and `@bna/probe-protocol` are currently pinned to exact
commit SHAs, because the `@bna` npm scope is not yet published. This keeps a
clean clone reproducible and CI green, but it is interim.

Once both packages are on npm, in this order:

1. Publish `@bna/validator-core`, then `@bna/probe-protocol`, each with
   `--provenance` from its release workflow.
2. In this repository, replace both `git+https://…#<sha>` specifiers with
   `^0.1.0`.
3. Delete `package-lock.json`, run `npm install`, and confirm the lockfile
   resolves to `https://registry.npmjs.org/…` rather than a git URL.
4. Run `npm run check` and `npm run test:package`.

Keep `bundleDependencies` unchanged throughout — it is what makes the published
artifact self-contained, and that property is independent of where the
dependencies are resolved from.

When bumping a pinned SHA in the meantime, bump it to a commit that exists on
the dependency's `main` branch and is itself green in CI. Never pin to a branch
name: a moving dependency makes a published score unreproducible, which is the
one thing this toolchain exists to prevent.
