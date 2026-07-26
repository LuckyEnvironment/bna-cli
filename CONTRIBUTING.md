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
