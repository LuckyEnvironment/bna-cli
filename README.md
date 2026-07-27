# @bna/cli

Validate an A2A agent card, and make a polite, read-only observation of a live endpoint.

No account, no API key, no config file, no telemetry, no postinstall script, and no hosted-service dependency. Everything below runs against the URL you give it and nothing else.

**The design rule this tool follows:** a field BNA cannot check is never shown as a pass. It gets its own state, `----`, and says so.

```
  Card schema            WARN   0 blocking, 3 incomplete fields
  Transport              ----   not observed by local schema validation
  Residency              ----   declared eu-west-1, not verifiable externally
  Retention policy       ----   not declared, not verifiable externally

  12 checks passed · 3 warnings · 0 failures
```

That is verbatim output from a card declaring residency and a contact but nothing else. Three of the four lines are things this tool did not measure, and it says so on each one.

---

## Install

> **Status: pre-release.** `@bna/cli` is not yet published to npm. Once it is, the line below is the whole install story. Until then, use *From source*.

```bash
npx @bna/cli validate https://agent.example.com/.well-known/agent.json
```

### From source

```bash
git clone https://github.com/LuckyEnvironment/bna-cli.git
cd bna-cli
npm install
node bin/bna.js --help
```

Node 20, 22 and 24 are supported on Linux, macOS and Windows.

---

## Commands

| Command | Purpose |
|---|---|
| `bna validate <url\|file>` | Check a card against the published schema |
| `bna probe <url>` | Read-only liveness observation from this machine |
| `bna verify <summary.json>` | Verify a signed probe summary |
| `bna diff <url\|file>` | Compare a card to a stored snapshot |
| `bna audit-score <agentId>` | Check a published score against the transparency log |
| `bna login` / `bna whoami` | Manage local auth context |

Full flags: `bna <command> --help`.

### validate

```bash
bna validate ./card.json
bna validate https://agent.example.com/.well-known/agent.json --strict
bna validate ./card.json --json
```

`--strict` promotes undeclared BNA extension fields from warnings to errors. Use it in CI when you require a complete card.

### probe

```bash
bna probe https://agent.example.com/a2a
bna probe https://agent.example.com/a2a --window 5 --json
```

**A local probe is one vantage point.** It is not, and must not be quoted as, a BNA trust score — that is a multi-region measurement made by the hosted service. Every summary says so in its output and carries `vantagePoint: "single-local"` in its JSON.

---

## The `----` state

Four outcomes, and the fourth is the point of the tool:

| State | Meaning |
|---|---|
| `PASS` | Measured, and it met the requirement |
| `WARN` | Measured, and it is incomplete but not blocking |
| `FAIL` | Measured, and it did not meet the requirement |
| `----` | **Not measured.** No claim is made either way |

A vendor declaring `zero-retention` does not make it true, and this tool has no way to check it from outside. So it reports the declaration as a declaration. Any tool that turns that into a green tick is telling you something it does not know.

The same rule governs the numbers: a probe run that attempted nothing reports `uptimePct: null`, never `0`. Zero percent availability is a measurement. No measurement is not.

---

## Exit codes

The CI contract. Every path is covered by a test.

| Code | Meaning |
|---:|---|
| `0` | Success |
| `1` | Warning, or drift detected |
| `2` | Schema or command error; for `audit-score`, an unbacked or malformed bundle |
| `3` | Network or probe failure |
| `4` | Auth context missing |

`audit-score` uses `2` rather than `1` for an unbacked score. A failed
inclusion proof is not a warning — the score is not supported by the log, and a
CI job that treats `1` as non-fatal must not be allowed to pass one. `1` is
reserved there for a result that verifies but is weaker than it looks, such as
a bundle containing leaves with an unresolved contradiction against them.

```bash
bna validate ./card.json --strict || echo "card is incomplete"
```

---

## JSON output is a public API

`validate`, `probe` and `verify` accept `--json`. Treat it as a stable interface:

```json
{
  "schemaVersion": "1.0.0",
  "tool": "probe",
  "toolVersion": "0.1.0",
  "generatedAt": "2026-07-26T12:00:00.000Z",
  "result": {}
}
```

- The contract is committed as [`schemas/cli-output.schema.json`](./schemas/cli-output.schema.json) and validated in tests.
- Additive fields are a minor version. Renaming or removing one is a major version.
- **With `--json`, stdout is exactly one JSON document.** No colour, no progress, no banners. Every diagnostic — including the `--allow-private` warning — goes to stderr.

Probe summaries additionally conform to the [BNA probe protocol](https://github.com/LuckyEnvironment/probe-protocol), so the same schema validates output from this CLI and from the hosted service.

---

## Probe etiquette

These are commitments to the operators being probed, and they are enforced in code and covered by tests — not merely documented.

- **Read-only.** `GET` and `HEAD` only. A disallowed method is refused, never silently substituted. No endpoint tool is ever discovered or invoked.
- **Identifies itself.** `User-Agent: BNA CLI/<version> (+https://bna.dev/trust-methodology)`
- **Honours `Retry-After`**, in both RFC 9110 forms. A malformed value is treated as absent, never as zero delay.
- **Backs off exponentially on 429**, and waits the longer of the backoff and any `Retry-After`.
- **A rate-limited probe is `not_attempted`, never a failure**, and stays out of the availability denominator. You are not penalised for defending your endpoint.
- **Paces requests** at no more than one per second by default.
- **Stops cleanly.** A global deadline and `SIGINT` produce partial results rather than continuing to make requests.

Full normative specification: [`probe-protocol/SPEC.md`](https://github.com/LuckyEnvironment/probe-protocol/blob/main/SPEC.md) §3–4.

If you see traffic claiming to be a BNA probe that does not behave this way, please report it — see [SECURITY.md](./SECURITY.md).

---

## Network safety

The CLI fetches URLs you supply, so it is hardened for use in CI against untrusted input:

- Private, link-local and cloud metadata addresses (`169.254.169.254` and friends) are refused by default.
- Redirects are capped, and the target is re-checked at **every hop** — a public URL cannot redirect into your private network.
- `--allow-private` exists for local development. It is off by default and prints a warning to stderr whenever it is used.

---

## No telemetry, verifiably

The CLI makes no network request other than to the URL you give it.

This is enforced rather than asserted: a test runs the CLI with all outbound traffic blocked except the target host, and fails if anything else is attempted.

---

## Signed summaries

`bna probe --sign` produces an RFC 7515 detached compact JWS (`protected..signature`) over the complete envelope, excluding its own `signature` field.

```bash
openssl genpkey -algorithm Ed25519 -out probe-private.pem
openssl pkey -in probe-private.pem -pubout -out probe-public.pem

bna probe https://agent.example.com/a2a --sign --key probe-private.pem --key-id 2026-07 > summary.json
bna verify summary.json --key probe-public.pem
```

Ed25519 (recommended) and RSA are supported. `--key` takes PEM text or a path; `BNA_PROBE_SIGNING_KEY` is an alternative. Signing never uses login tokens.

**Rotation:** issue a new key with a new `--key-id`, and keep the old public key for as long as historical summaries need verifying. The verifier deliberately does not fetch keys over the network — you choose which public key to trust, which is the only way the signature means anything.

---

## Dependencies

Two, both first-party, both bundled into the published tarball so that `npx` works on a clean machine with no further downloads:

| Package | Purpose |
|---|---|
| [`@bna/validator-core`](https://github.com/LuckyEnvironment/bna-validator-core) | The authoritative card schema and `validateCard` |
| [`@bna/probe-protocol`](https://github.com/LuckyEnvironment/probe-protocol) | The probe specification, result schema and conformance vectors |

They are currently pinned to exact commit SHAs rather than version ranges, because the `@bna` npm scope is not yet published. Once it is, these become `^0.1.0` ranges — see [CONTRIBUTING.md](./CONTRIBUTING.md).

Zero third-party runtime dependencies. In a security-adjacent CLI, every dependency is supply-chain surface and a question you will be asked.

---

## Development

```bash
npm run check             # lint + typecheck + tests — run this before committing
npm run test:coverage     # enforces an 85% line-coverage floor
npm run test:package      # packs the tarball, installs it, exercises every command
npm run verify:container  # runs the packed tarball in a clean Linux container
```

`test:package` is the one that matters before a release: it installs the real tarball with `--offline`, so it fails if any runtime dependency is missing from the shipped artifact rather than discovering it after publication.

`verify:container` goes further. It packs the working tree, then installs and exercises that tarball inside a disposable Linux container on Node 20, 22 and 24 — **with `--network none`**. Cutting the network proves three things at once that are otherwise argued rather than shown:

- the tarball is self-contained, because the install could not have reached any registry
- there is no telemetry, because nothing external is reachable at all
- `probe` still works, against loopback

It checks the first-run transcript, all five exit codes, that `--json` emits exactly one document on stdout with diagnostics on stderr, and that probe output conforms to the published probe-summary schema.

```
 node v22.23.1  ·  Linux/aarch64
 network: none (--network none confirmed)
install: OK
  PASS  exit 0 — valid card                          exit 0
  PASS  exit 1 — card with warnings                  exit 1
  PASS  exit 2 — schema or command error             exit 2
  PASS  exit 3 — network or probe failure            exit 3
  PASS  exit 4 — signing context missing             exit 4
  PASS  exit 0 — successful local probe              exit 0
  PASS  stdout parses as a single JSON document
  PASS  conformant to probe-summary-1.0.0
 node v22.23.1: 8 passed, 0 failed
```

Pass a version to narrow it (`npm run verify:container -- 22`), or set `KEEP_IMAGES=1` to keep the images for debugging. It needs a working Docker daemon; on macOS the Docker CLI alone is not enough, since containers require a Linux VM such as `colima`.

**This is not a substitute for CI.** It covers Linux only — macOS and Windows containers are not available on a macOS host — and on Apple Silicon it runs ARM64 while GitHub's runners are x86_64. Treat it as evidence alongside the CI matrix, not instead of it.

---

## Licence

[Apache 2.0](./LICENSE). See [NOTICE](./NOTICE), [SECURITY.md](./SECURITY.md), [CONTRIBUTING.md](./CONTRIBUTING.md), [CHANGELOG.md](./CHANGELOG.md).


## audit-score

Verify that a published score is backed by the transparency log. Everything
after the fetch happens offline, on your machine, with no further reference to
BNA.

```bash
bna audit-score agt_7c1f --period 2026-06 --against ./sth-i-saved-in-june.json
```

```
  Score bundle for agt_7c1f, period 2026-06 — 760 leaves
  PASS  1. every leaf has a valid inclusion proof against the bundle's tree head
  PASS  2. the tree head is consistent with an independently recorded one
  PASS  3. re-running the specification's arithmetic over the leaves reproduces the score
  PASS  4. no leaf in the set is graded poisoned

  BACKED — every premise of this score is public and checked.
```

| Flag | Effect |
|---|---|
| `--period <YYYY-MM>` | Required. The scoring period. |
| `--against <sth.json>` | A tree head you recorded earlier. Without it, step 2 proves nothing and says so. |
| `--bundle <file>` | Verify a saved bundle instead of fetching. Takes precedence over the network. |
| `--log-base <url>` | Where to fetch from. Defaults to `https://transparency.bna.dev`. |
| `--json` | Machine-readable envelope on stdout; notes and warnings on stderr. |

**Step 2 is the one that carries the weight**, and it only means something if
the tree head you compare against is one you held *before BNA knew you would
ask*. Record one now and keep it.

**What a BACKED verdict does not mean.** It means the leaves were committed to
the log before the score was published, the log has not been edited since, and
the arithmetic follows from the leaves. It does not mean the observations
happened: a fabricated measurement, committed honestly and never altered,
produces a perfectly valid set of proofs. Only the observed party can check
that, from their own access logs, against the nonce each probe sent — see
`@bna/witness-log` and `bna witness` when it ships.
