// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { validate } from "@bna/probe-protocol";
import {
  consistencyProof,
  inclusionProof,
  leafHash,
  merkleRoot,
  verifyInclusion
} from "@bna/witness-log";
import { verifyBundle } from "../src/commands/audit-score.js";
import { runCli } from "./helpers.js";

const scratch = mkdtempSync(join(tmpdir(), "bna-audit-"));

/**
 * @param {number} index
 * @param {"success" | "failure" | "not_attempted"} outcome
 * @param {number} ms
 */
function leafFor(index, outcome, ms) {
  return {
    leafVersion: "1.0.0",
    type: "observation",
    target: "https://agent.example.com/a2a",
    agentId: "agt_7c1f",
    targetKeyId: null,
    vantage: "eu-nl-1",
    probeKeyId: "bna-eu-nl-1-2026q3",
    // 16 bytes base64url is exactly 22 characters; the schema enforces it.
    nonce: `nonce${String(index).padStart(3, "0")}`.padEnd(22, "A"),
    requestedAt: new Date(Date.UTC(2026, 5, 1, 0, index)).toISOString(),
    method: "GET",
    outcome,
    reason: outcome === "not_attempted" ? "rate_limited" : null,
    status: outcome === "success" ? 200 : outcome === "failure" ? 503 : 429,
    ms,
    responseDigest: null,
    receipt: null
  };
}

const digest = (/** @type {Uint8Array} */ bytes) =>
  `sha256:${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

/**
 * Build a real, internally consistent bundle: real leaves, a real tree, real
 * inclusion proofs. Nothing here is a stub, so a test that passes proves the
 * verifier agrees with the construction rather than with a fixture.
 *
 * @param {{outcome: "success" | "failure" | "not_attempted", ms: number}[]} spec
 * @param {string[]} [grades]
 */
async function buildBundle(spec, grades) {
  const leaves = spec.map((entry, index) => leafFor(index, entry.outcome, entry.ms));
  const hashes = await Promise.all(leaves.map((leaf) => leafHash(leaf)));
  const root = await merkleRoot(hashes);

  const entries = [];
  for (let index = 0; index < leaves.length; index += 1) {
    const proof = await inclusionProof(index, hashes);
    entries.push({
      leaf: leaves[index],
      index,
      grade: grades?.[index] ?? "logged",
      proof: proof.map(digest)
    });
  }

  const success = spec.filter((entry) => entry.outcome === "success").length;
  const failure = spec.filter((entry) => entry.outcome === "failure").length;
  const notAttempted = spec.filter((entry) => entry.outcome === "not_attempted").length;
  const attempted = success + failure;
  const latency = spec
    .filter((entry) => entry.outcome !== "not_attempted")
    .reduce((total, entry) => total + entry.ms, 0);

  return {
    bundle: {
      agentId: "agt_7c1f",
      period: { from: "2026-06-01T00:00:00.000Z", to: "2026-07-01T00:00:00.000Z" },
      sth: {
        logId: "bna-witness-v1",
        treeSize: leaves.length,
        rootHash: digest(root),
        timestamp: "2026-07-01T00:00:00.000Z",
        signature: "not-verified-at-m1"
      },
      leaves: entries,
      derived: {
        requested: leaves.length,
        attempted,
        success,
        failure,
        notAttempted,
        uptimePct: attempted === 0 ? null : Number(((success / attempted) * 100).toFixed(2)),
        avgLatencyMs: attempted === 0 ? null : Math.round(latency / attempted)
      },
      grades: {
        attested: entries.filter((entry) => entry.grade === "attested").length,
        logged: entries.filter((entry) => entry.grade === "logged").length,
        disputed: entries.filter((entry) => entry.grade === "disputed").length,
        poisoned: entries.filter((entry) => entry.grade === "poisoned").length
      },
      methodologyVersion: "0.1"
    },
    hashes,
    root
  };
}

test("a well-formed bundle verifies, and every step passes", async () => {
  const { bundle } = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "success", ms: 90 },
    { outcome: "failure", ms: 120 },
    { outcome: "not_attempted", ms: 0 }
  ]);

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, true, JSON.stringify(result.steps, null, 2));
  assert.deepEqual(
    result.steps.map((step) => step.passed),
    [true, true, true, true]
  );
});

test("the bundle validates against the committed score-bundle schema", async () => {
  const { SCORE_BUNDLE_SCHEMA } = await import("@bna/witness-log");
  const { bundle } = await buildBundle([{ outcome: "success", ms: 80 }]);
  assert.deepEqual(validate(bundle, SCORE_BUNDLE_SCHEMA), []);
});

test("a tampered leaf breaks its inclusion proof — step 1 fails", async () => {
  const { bundle } = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "failure", ms: 90 }
  ]);

  // The log claims the probe succeeded. The tree says otherwise.
  bundle.leaves[1].leaf.outcome = "success";

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, false);
  assert.equal(result.steps[0].passed, false);
  assert.match(String(result.steps[0].detail), /not provably in the tree/);
});

test("arithmetic that does not follow from the leaves — step 3 fails", async () => {
  const { bundle } = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "failure", ms: 100 }
  ]);

  bundle.derived.uptimePct = 100;

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, false);
  assert.equal(result.steps[2].passed, false);
  assert.match(String(result.steps[2].detail), /uptimePct/);
});

test("not_attempted stays out of the denominator, per SPEC section 2.3", async () => {
  const { bundle } = await buildBundle([
    { outcome: "success", ms: 100 },
    { outcome: "not_attempted", ms: 0 },
    { outcome: "not_attempted", ms: 0 }
  ]);

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, true);
  // One success, one attempt: 100%, not 33%.
  assert.equal(/** @type {any} */ (result.derived).uptimePct, 100);
  assert.equal(/** @type {any} */ (result.derived).attempted, 1);
});

test("a period in which nothing was attempted reports null, never 0", async () => {
  const { bundle } = await buildBundle([
    { outcome: "not_attempted", ms: 0 },
    { outcome: "not_attempted", ms: 0 }
  ]);

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, true, JSON.stringify(result.steps));
  assert.equal(/** @type {any} */ (result.derived).uptimePct, null);
  assert.equal(/** @type {any} */ (result.derived).avgLatencyMs, null);
});

test("a poisoned leaf makes the score unbacked — step 4 fails", async () => {
  const { bundle } = await buildBundle(
    [
      { outcome: "success", ms: 80 },
      { outcome: "success", ms: 90 }
    ],
    ["logged", "poisoned"]
  );

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, false);
  assert.equal(result.steps[3].passed, false);
  assert.match(String(result.steps[3].detail), /poisoned/);
});

test("a disputed leaf is a warning, not a failure", async () => {
  const { bundle } = await buildBundle(
    [
      { outcome: "success", ms: 80 },
      { outcome: "success", ms: 90 }
    ],
    ["logged", "disputed"]
  );

  const result = await verifyBundle(bundle, null);
  assert.equal(result.backed, true);
  assert.ok(result.warnings.some((warning) => /disputed/.test(warning)));
});

test("omitting --against is reported as an unproven step, not a silent pass", async () => {
  const { bundle } = await buildBundle([{ outcome: "success", ms: 80 }]);
  const result = await verifyBundle(bundle, null);

  assert.equal(result.steps[1].passed, true);
  assert.match(String(result.steps[1].detail), /skipped/);
  assert.ok(
    result.notices.some((notice) => /has not been rewritten/.test(notice)),
    "a skipped consistency check must say that nothing was proved by it"
  );
  // A notice, not a warning: running without --against is the ordinary first
  // use, and exiting non-zero for it teaches people to ignore the exit code.
  assert.deepEqual(result.warnings, []);
});

test("consistency against a previously recorded tree head verifies", async () => {
  const early = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "success", ms: 90 },
    { outcome: "success", ms: 70 }
  ]);
  const later = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "success", ms: 90 },
    { outcome: "success", ms: 70 },
    { outcome: "failure", ms: 200 },
    { outcome: "success", ms: 60 }
  ]);

  const proof = await consistencyProof(3, later.hashes);
  const against = {
    treeSize: 3,
    rootHash: early.bundle.sth.rootHash,
    consistencyProof: proof.map(digest)
  };

  const result = await verifyBundle(later.bundle, against);
  assert.equal(result.steps[1].passed, true, String(result.steps[1].detail));
  assert.equal(result.backed, true);
});

test("a log that rewrote history cannot prove consistency — step 2 fails", async () => {
  const early = await buildBundle([
    { outcome: "failure", ms: 200 },
    { outcome: "success", ms: 90 },
    { outcome: "success", ms: 70 }
  ]);

  // A different history: the inconvenient first failure is now a success.
  const rewritten = await buildBundle([
    { outcome: "success", ms: 200 },
    { outcome: "success", ms: 90 },
    { outcome: "success", ms: 70 },
    { outcome: "success", ms: 60 }
  ]);

  const proof = await consistencyProof(3, rewritten.hashes);
  const against = {
    treeSize: 3,
    rootHash: early.bundle.sth.rootHash,
    consistencyProof: proof.map(digest)
  };

  const result = await verifyBundle(rewritten.bundle, against);
  assert.equal(result.steps[1].passed, false);
  assert.equal(result.backed, false);
});

test("the CLI exits 0 backed, 2 unbacked, and 2 on a malformed bundle", async () => {
  const { auditScoreCommand } = await import("../src/commands/audit-score.js");
  const { bundle } = await buildBundle([{ outcome: "success", ms: 80 }]);

  const good = join(scratch, "good.json");
  writeFileSync(good, JSON.stringify(bundle));
  assert.equal(await auditScoreCommand("agt_7c1f", { period: "2026-06", bundle: good }), 0);

  const poisonedBuild = await buildBundle([{ outcome: "success", ms: 80 }], ["poisoned"]);
  const poisoned = join(scratch, "poisoned.json");
  writeFileSync(poisoned, JSON.stringify(poisonedBuild.bundle));
  assert.equal(await auditScoreCommand("agt_7c1f", { period: "2026-06", bundle: poisoned }), 2);

  const malformed = join(scratch, "malformed.json");
  writeFileSync(malformed, JSON.stringify({ agentId: "x" }));
  assert.equal(await auditScoreCommand("agt_7c1f", { period: "2026-06", bundle: malformed }), 2);

  const missing = join(scratch, "does-not-exist.json");
  assert.equal(await auditScoreCommand("agt_7c1f", { period: "2026-06", bundle: missing }), 2);

  // A bad period is a command error, not a verification result.
  assert.equal(await auditScoreCommand("agt_7c1f", { period: "June", bundle: good }), 2);
});

test("--json output from the real binary validates against the CLI output schema", async () => {
  const { bundle } = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "failure", ms: 90 }
  ]);
  const path = join(scratch, "json.json");
  writeFileSync(path, JSON.stringify(bundle));

  // The real command, run as a subprocess, so this checks the shipped output
  // rather than an in-process approximation of it — matching how probe --json
  // is already tested.
  const result = await runCli(["audit-score", "agt_7c1f", "--period", "2026-06", "--bundle", path, "--json"]);
  assert.equal(result.code, 0, result.stderr);

  const output = JSON.parse(result.stdout);
  assert.equal(output.schemaVersion, "1.0.0");
  assert.equal(output.tool, "audit-score");
  assert.equal(output.result.backed, true);
  assert.equal(output.result.steps.length, 4);
});

test("--json stdout carries nothing but the envelope", async () => {
  const { bundle } = await buildBundle([{ outcome: "success", ms: 80 }]);
  const path = join(scratch, "pure.json");
  writeFileSync(path, JSON.stringify(bundle));

  const result = await runCli(["audit-score", "agt_7c1f", "--period", "2026-06", "--bundle", path, "--json"]);
  assert.doesNotThrow(() => JSON.parse(result.stdout), "stdout was not pure JSON");
  // The notice about --against belongs on stderr, where it cannot corrupt a pipe.
  assert.match(result.stderr, /--against/);
});

test("a proof from a different tree does not verify against this one", async () => {
  const mine = await buildBundle([
    { outcome: "success", ms: 80 },
    { outcome: "success", ms: 90 }
  ]);
  const theirs = await buildBundle([
    { outcome: "failure", ms: 80 },
    { outcome: "failure", ms: 90 }
  ]);

  assert.equal(
    await verifyInclusion(mine.hashes[0], 0, 2, await inclusionProof(0, theirs.hashes), mine.root),
    false
  );
});
