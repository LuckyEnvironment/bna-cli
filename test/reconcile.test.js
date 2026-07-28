// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { readAccessLog, sniffFormat } from "../src/lib/access-log.js";
import { parseSince, reconcileLeaves } from "../src/commands/reconcile.js";
import { runCli } from "./helpers.js";

const logs = fileURLToPath(new URL("./fixtures/access-logs/", import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), "bna-reconcile-"));

const N1 = "7qGjdDQhvL_k192Z5VqrDA";
const N2 = "hLgMce4COYWqXT-fZ4VhRw";
const N3 = "AAAAAAAAAAAAAAAAAAAAAA";
const MISSING = "zzzz9999____----AAAABB";

/** @param {string} name */
async function collect(name, options = {}) {
  const reader = readAccessLog(join(logs, name), options);
  const entries = [];
  let step = await reader.next();
  while (!step.done) {
    entries.push(step.value);
    step = await reader.next();
  }
  return { entries, summary: step.value };
}

/* ============================================================
   Parsing, one fixture per supported format
   ============================================================ */

test("nginx combined with the documented log_format is read", async () => {
  const { entries, summary } = await collect("nginx-combined.log");
  assert.equal(summary.format, "nginx-combined");
  assert.deepEqual(entries.map((entry) => entry.nonce), [N1, N2, N3]);
  assert.equal(entries[0].status, 200);
  assert.equal(entries[1].status, 503);
  assert.equal(entries[0].at, "2026-06-01T00:00:00.000Z");
});

test("nginx JSON is read", async () => {
  const { entries, summary } = await collect("nginx-json.log");
  assert.equal(summary.format, "nginx-json");
  assert.deepEqual(entries.map((entry) => entry.nonce), [N1, N2, N3, N1]);
  assert.equal(entries[1].status, 503);
  assert.equal(entries[0].at, "2026-06-01T00:00:00.000Z");
});

test("Caddy JSON is read, including headers nested as arrays", async () => {
  const { entries, summary } = await collect("caddy-json.log");
  assert.equal(summary.format, "caddy-json");
  assert.deepEqual(entries.map((entry) => entry.nonce), [N1, N2, N3, N1]);
  assert.equal(entries[1].status, 503);
  // Caddy logs seconds with a fraction; it must come back as an instant.
  assert.match(String(entries[0].at), /^2026-06-01T/);
});

test("an unrecognised shape is read via --nonce-field", async () => {
  const { entries } = await collect("custom.log", { nonceField: "meta.hdr.probe" });
  assert.deepEqual(entries.map((entry) => entry.nonce), [N1, N2, N3]);

  // The nonce is located because the caller said where it is. The status and
  // timestamp are not, because nothing said where *those* are — and guessing
  // at a field named `code` or `t` could invent a status_mismatch or a
  // timing_mismatch out of an unrelated value. Null means those comparisons
  // are skipped for this log, which is the honest outcome: `no_such_request`
  // still works, and the other two classes simply cannot be asserted.
  assert.equal(entries[1].status, null);
  assert.equal(entries[0].at, null);
});

test("format sniffing distinguishes the three shapes", () => {
  const read = (/** @type {string} */ name) =>
    readFileSync(join(logs, name), "utf8").split("\n").slice(0, 5);

  assert.equal(sniffFormat(read("nginx-combined.log")), "nginx-combined");
  assert.equal(sniffFormat(read("nginx-json.log")), "nginx-json");
  assert.equal(sniffFormat(read("caddy-json.log")), "caddy-json");
  assert.equal(sniffFormat([]), "unknown");
  assert.equal(sniffFormat(["", "   "]), "unknown");
});

test("an empty log is empty, not malformed", async () => {
  const { entries, summary } = await collect("empty.log");
  assert.equal(entries.length, 0);
  assert.equal(summary.lines, 0);
});

/* ============================================================
   The guard that stops false accusations — acceptance gate
   ============================================================ */

test("a log with no nonces yields no entries, so nothing can be accused from it", async () => {
  const { entries, summary } = await collect("nginx-no-nonce.log");
  assert.equal(entries.length, 0);
  assert.ok(summary.lines > 0, "the fixture should not be empty");
});

test("the command reports a missing log_format rather than mass contradictions", async () => {
  const bundle = join(scratch, "bundle.json");
  writeFileSync(bundle, JSON.stringify({ leaves: manyLeaves(760) }));

  const result = await runCli([
    "reconcile",
    "--agent",
    "agt_7c1f",
    "--access-log",
    join(logs, "nginx-no-nonce.log"),
    "--bundle",
    bundle
  ]);

  // Exit 2, malformed input — not exit 1, discrepancies found.
  assert.equal(result.code, 2, result.stdout + result.stderr);
  assert.match(result.stderr, /found no BNA-Probe-Nonce values/);
  assert.match(result.stderr, /Refusing to report contradictions on that basis/);
  assert.match(result.stderr, /log_format bna/, "the fix must be printed, not just named");
  assert.doesNotMatch(result.stdout, /no_such_request/);
});

/* ============================================================
   Matching rules
   ============================================================ */

/** @param {number} count */
function manyLeaves(count) {
  return Array.from({ length: count }, (_unused, index) => ({
    leaf: {
      leafVersion: "1.0.0",
      type: "observation",
      target: "https://agent.example.com/a2a",
      agentId: "agt_7c1f",
      targetKeyId: null,
      vantage: "eu-nl-1",
      probeKeyId: "bna-eu-nl-1",
      nonce: `n${String(index).padStart(3, "0")}`.padEnd(22, "A"),
      requestedAt: new Date(Date.UTC(2026, 5, 1, 0, index)).toISOString(),
      method: "GET",
      outcome: "success",
      reason: null,
      status: 200,
      ms: 80,
      responseDigest: null,
      receipt: null
    }
  }));
}

/**
 * @param {Partial<Record<string, any>>} [overrides]
 */
function leafFor(nonce, overrides = {}) {
  return {
    leafVersion: "1.0.0",
    type: "observation",
    target: "https://agent.example.com/a2a",
    agentId: "agt_7c1f",
    targetKeyId: null,
    vantage: "eu-nl-1",
    probeKeyId: "bna-eu-nl-1",
    nonce,
    requestedAt: "2026-06-01T00:00:00.000Z",
    method: "GET",
    outcome: "success",
    reason: null,
    status: 200,
    ms: 80,
    responseDigest: null,
    receipt: null,
    ...overrides
  };
}

test("a leaf with no matching request is a no_such_request contradiction", async () => {
  const seen = new Map([[N1, { status: 200, at: "2026-06-01T00:00:00.000Z", line: 1 }]]);
  const result = await reconcileLeaves([leafFor(N1), leafFor(MISSING)], seen);

  assert.equal(result.matched, 1);
  assert.equal(result.discrepancies.length, 1);
  assert.equal(result.discrepancies[0].class, "no_such_request");
  assert.match(result.discrepancies[0].detail, new RegExp(MISSING));
});

test("a status the vendor did not serve is a status_mismatch", async () => {
  const seen = new Map([[N1, { status: 200, at: "2026-06-01T00:00:00.000Z", line: 7 }]]);
  const result = await reconcileLeaves([leafFor(N1, { status: 503, outcome: "failure" })], seen);

  assert.equal(result.matched, 1);
  assert.equal(result.statusDisagrees, 1);
  assert.equal(result.discrepancies[0].class, "status_mismatch");
  assert.match(result.discrepancies[0].detail, /BNA published 503; the log line 7 recorded 200/);
});

test("a log line far from the published time is a timing_mismatch", async () => {
  const seen = new Map([[N1, { status: 200, at: "2026-06-01T04:00:00.000Z", line: 3 }]]);
  const result = await reconcileLeaves([leafFor(N1)], seen);
  assert.equal(result.discrepancies[0].class, "timing_mismatch");

  // Within the skew window it is not a discrepancy.
  const close = new Map([[N1, { status: 200, at: "2026-06-01T00:00:30.000Z", line: 3 }]]);
  assert.equal((await reconcileLeaves([leafFor(N1)], close)).discrepancies.length, 0);
});

test("a receipt that does not verify against the vendor's key is receipt_forged", async () => {
  const fixture = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../bna-witness-log/test/fixtures/jws-vectors.json", import.meta.url)),
      "utf8"
    )
  );
  const seen = new Map([[N1, { status: 200, at: "2026-06-01T00:00:00.000Z", line: 1 }]]);

  const forged = leafFor(N1, {
    targetKeyId: fixture.keys.EdDSA.public.kid,
    receipt: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpPU0UifQ.eyJub25jZSI6IngifQ.AAAA"
  });
  const result = await reconcileLeaves([forged], seen, { jwk: fixture.keys.EdDSA.public });

  assert.equal(result.discrepancies[0].class, "receipt_forged");
});

test("a clean reconciliation reports nothing", async () => {
  const seen = new Map([
    [N1, { status: 200, at: "2026-06-01T00:00:00.000Z", line: 1 }],
    [N2, { status: 503, at: "2026-06-01T00:01:00.000Z", line: 2 }]
  ]);
  const leaves = [leafFor(N1), leafFor(N2, { status: 503, requestedAt: "2026-06-01T00:01:00.000Z" })];
  const result = await reconcileLeaves(leaves, seen);

  assert.equal(result.discrepancies.length, 0);
  assert.equal(result.matched, 2);
});

/* ============================================================
   The command
   ============================================================ */

test("--since accepts days, hours and weeks and refuses anything else", () => {
  assert.equal(parseSince("30d"), 30 * 86_400_000);
  assert.equal(parseSince("12h"), 12 * 3_600_000);
  assert.equal(parseSince("2w"), 2 * 604_800_000);
  for (const bad of ["", "30", "d", "-1d", "30 days", "1y", null, undefined]) {
    assert.equal(parseSince(/** @type {any} */ (bad)), null, `accepted ${JSON.stringify(bad)}`);
  }
});

test("exit 0 when everything matches, 1 when it does not", async () => {
  const clean = join(scratch, "clean.json");
  writeFileSync(
    clean,
    JSON.stringify({
      leaves: [
        { leaf: leafFor(N1) },
        { leaf: leafFor(N2, { status: 503, requestedAt: "2026-06-01T00:01:00.000Z" }) },
        { leaf: leafFor(N3, { requestedAt: "2026-06-01T00:03:00.000Z" }) }
      ]
    })
  );
  const ok = await runCli([
    "reconcile", "--agent", "agt_7c1f",
    "--access-log", join(logs, "nginx-combined.log"),
    "--bundle", clean
  ]);
  assert.equal(ok.code, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /Everything BNA published about you is in your own logs/);

  const dirty = join(scratch, "dirty.json");
  writeFileSync(dirty, JSON.stringify({ leaves: [{ leaf: leafFor(N1) }, { leaf: leafFor(MISSING) }] }));
  const found = await runCli([
    "reconcile", "--agent", "agt_7c1f",
    "--access-log", join(logs, "nginx-combined.log"),
    "--bundle", dirty
  ]);
  assert.equal(found.code, 1);
  assert.match(found.stdout, /No corresponding request found\s+1/);
});

test("missing arguments and unreadable inputs exit 2", async () => {
  assert.equal((await runCli(["reconcile"])).code, 2);
  assert.equal((await runCli(["reconcile", "--agent", "a"])).code, 2);

  const bundle = join(scratch, "b.json");
  writeFileSync(bundle, JSON.stringify({ leaves: [{ leaf: leafFor(N1) }] }));
  assert.equal(
    (await runCli(["reconcile", "--agent", "a", "--access-log", "/nope.log", "--bundle", bundle])).code,
    2
  );
  assert.equal(
    (await runCli([
      "reconcile", "--agent", "a",
      "--access-log", join(logs, "nginx-combined.log"),
      "--bundle", bundle, "--since", "yesterday"
    ])).code,
    2
  );
});

test("--json output validates against the CLI output schema", async () => {
  const bundle = join(scratch, "json.json");
  writeFileSync(bundle, JSON.stringify({ leaves: [{ leaf: leafFor(N1) }, { leaf: leafFor(MISSING) }] }));

  const result = await runCli([
    "reconcile", "--agent", "agt_7c1f",
    "--access-log", join(logs, "nginx-combined.log"),
    "--bundle", bundle, "--json"
  ]);
  assert.equal(result.code, 1);

  const output = JSON.parse(result.stdout);
  assert.equal(output.schemaVersion, "1.0.0");
  assert.equal(output.tool, "reconcile");
  assert.equal(output.result.byClass.no_such_request, 1);
  assert.equal(output.result.matched, 1);
  assert.equal(output.result.discrepancies[0].class, "no_such_request");
  assert.doesNotThrow(() => JSON.parse(result.stdout), "stdout was not pure JSON");
});

test("the log is streamed: it runs under a heap far smaller than the file", async () => {
  // heapUsed is too noisy to assert on directly. A hard `--max-old-space-size`
  // in a child process is not: an implementation that buffered the file would
  // exceed the cap and die, and a streaming one cannot.
  const big = join(scratch, "big.log");
  const line = (/** @type {number} */ index) =>
    `10.0.0.1 - - [01/Jun/2026:00:00:00 +0000] "GET /a2a HTTP/1.1" 200 512 "-" "x" bna_nonce=${String(index).padStart(22, "0")}\n`;

  const { createWriteStream, statSync } = await import("node:fs");
  const stream = createWriteStream(big);
  for (let index = 0; index < 400_000; index += 1) {
    if (!stream.write(line(index))) await new Promise((resolve) => stream.once("drain", resolve));
  }
  await new Promise((resolve) => stream.end(resolve));

  const bytes = statSync(big).size;
  const capMb = 32;
  assert.ok(bytes > capMb * 1024 * 1024, `the log must exceed the heap cap; it is ${bytes} bytes`);

  const reader = fileURLToPath(new URL("../src/lib/access-log.js", import.meta.url));
  const script = `
    const { readAccessLog } = await import(${JSON.stringify(reader)});
    let count = 0;
    const iterator = readAccessLog(${JSON.stringify(big)});
    let step = await iterator.next();
    while (!step.done) { count += 1; step = await iterator.next(); }
    process.stdout.write(String(count) + ":" + String(step.value.lines));
  `;

  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [`--max-old-space-size=${capMb}`, "--input-type=module", "-e", script],
    { maxBuffer: 1 << 20 }
  );

  assert.equal(stdout, "400000:400000", "the reader did not see every line");
});
