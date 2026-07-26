# @bna/cli

Validate an A2A agent card and make a polite, local liveness observation. It has
no telemetry, account requirement, postinstall hook, or hosted-service
dependency.

## Commands

- `bna login [--org <slug>] [--token <value>]`
  - OIDC device flow: `bna login --org <slug> --issuer <url> --client-id <id> [--scope <value>]`
- `bna whoami`
- `bna validate <url|file> [--strict] [--json] [--allow-private]`
- `bna probe <url> [--watch] [--window <n>] [--deadline <ms>] [--json]`
  `[--sign --key <private.pem> [--key-id <id>]] [--allow-private]`
- `bna verify <summary.json> --key <public.pem> [--json]`
- `bna diff <url|file> [--update] [--allow-private]`

## Local usage

```bash
cd bna-cli
node bin/bna.js --help
node bin/bna.js validate ./examples/valid-card.json
```

`validate` reports only the schema facts it observes locally. Transport,
residency, and retention declarations are shown as `----` when they cannot be
externally verified; they are never shown as a pass.

Remote URLs are protected against private, link-local, metadata, and redirect
SSRF targets. Use `--allow-private` only for local development; the CLI writes
a warning to stderr whenever it is enabled.

## Install locally as a global command

```bash
cd bna-cli
npm link
bna --help
```

## Exit codes

- `0` success
- `1` warning / drift detected
- `2` schema or command error
- `3` network/probe failure
- `4` auth context missing

## JSON API

`validate`, `probe`, and `verify` support `--json`. Their stdout is exactly one
versioned JSON envelope:

```json
{ "schemaVersion": "1.0.0", "tool": "validate", "toolVersion": "0.1.0",
  "generatedAt": "2026-01-01T00:00:00.000Z", "result": {} }
```

Diagnostics, including the `--allow-private` warning, always go to stderr. The
committed contract is [`schemas/cli-output.schema.json`](./schemas/cli-output.schema.json).
Additive fields are minor-version changes; renaming or removal is a major
schema-version change.

## Probe behaviour

A local `probe` is explicitly labelled as **one local vantage point**, not a
BNA multi-region trust score. It sends only `GET` (or explicit `HEAD`) requests
to the URL supplied; it never discovers or invokes endpoint tools. Its
`User-Agent` links to the BNA methodology. The default is one request, and
additional requests are paced one second apart. `429` responses honour
`Retry-After` and exponential backoff, and are recorded as `not_attempted`,
outside the availability denominator. A 30-second global deadline and SIGINT
produce partial results rather than continuing requests.

## Signed summaries and key rotation

`bna probe --sign` produces an RFC 7515 detached compact JWS
(`protected..signature`) over the complete JSON envelope excluding its
`signature` field. Use an Ed25519 private PEM (recommended) or RSA private PEM:

```bash
openssl genpkey -algorithm Ed25519 -out probe-private.pem
openssl pkey -in probe-private.pem -pubout -out probe-public.pem
bna probe https://agent.example --sign --key probe-private.pem --key-id 2026-01 > summary.json
bna verify summary.json --key probe-public.pem
```

`--key` accepts PEM text or a PEM path; `BNA_PROBE_SIGNING_KEY` is an
alternative. Signing does not use login tokens. Rotate by issuing a new key
with a new `--key-id`, retaining the corresponding old public key while
historical summaries need verification. The verifier intentionally does not
fetch keys: callers select the trusted public key themselves.

## Development checks

```bash
npm run check
npm run test:coverage
npm run test:package
```

The published package uses an explicit `files` allowlist and bundles the shared
validator runtime so a packed tarball can be installed and exercised locally.
