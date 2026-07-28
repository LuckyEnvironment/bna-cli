// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { aggregate } from "@bna/probe-protocol";
import {
  contradictionHashOf,
  contradictionStatus,
  countsTowardScore,
  deriveGrade,
  inclusionProof,
  leafHash,
  merkleRoot,
  verifyInclusion
} from "@bna/witness-log";
import { reconcileLeaves } from "../src/commands/reconcile.js";
import { runCli } from "./helpers.js";

/**
 * The whole loop, end to end — the acceptance gate for M3.
 *
 * BNA publishes an observation that never happened. The vendor's own log has
 * no request bearing its nonce. They reconcile, file, it is adjudicated, and
 * the leaf drops out of the score — while remaining in the log forever, with
 * its inclusion proof still valid.
 *
 * That last part is the point. An upheld contradiction must not be able to
 * make evidence disappear, or the log would be as revisable as the thing it
 * replaced.
 */

const scratch = mkdtempSync(join(tmpdir(), "bna-roundtrip-"));
const T0 = Date.parse("2026-06-01T00:00:00.000Z");
const DAY = 86_400_000;

/**
 * @param {number} index
 * @param {"success" | "failure"} outcome
 */
function observation(index, outcome) {
  return {
    leafVersion: "1.0.0",
    type: "observation",
    target: "https://agent.example.com/a2a",
    agentId: "agt_7c1f",
    targetKeyId: null,
    vantage: "eu-nl-1",
    probeKeyId: "bna-eu-nl-1-2026q3",
    nonce: `n${String(index).padStart(3, "0")}`.padEnd(22, "A"),
    requestedAt: new Date(T0 + index * 60_000).toISOString(),
    method: "GET",
    outcome,
    reason: null,
    status: outcome === "success" ? 200 : 503,
    ms: outcome === "success" ? 80 : 400,
    responseDigest: null,
    receipt: null
  };
}

test("a fabricated observation is found, filed, upheld, and drops out of the score while staying in the log", async () => {
  /* ---------- 1. BNA publishes five observations. One never happened. ---------- */
  const leaves = [
    observation(0, "success"),
    observation(1, "success"),
    observation(2, "failure"), // the fabrication: BNA claims a 503 it never saw
    observation(3, "success"),
    observation(4, "success")
  ];
  const fabricated = leaves[2];

  const hashes = await Promise.all(leaves.map((leaf) => leafHash(leaf)));
  const root = await merkleRoot(hashes);
  const proofs = await Promise.all(leaves.map((_leaf, index) => inclusionProof(index, hashes)));

  // It is genuinely in the tree — that is what makes this hard. The log is not
  // lying about what it committed to; it is lying about what it measured.
  assert.equal(await verifyInclusion(hashes[2], 2, 5, proofs[2], root), true);

  const publishedScore = aggregate(leaves);
  assert.equal(publishedScore.failure, 1);
  assert.equal(publishedScore.uptimePct, 80);

  /* ---------- 2. The vendor reconciles against their own log ---------- */
  // Their server saw four of the five probes. Never the third.
  const seen = new Map(
    leaves
      .filter((leaf) => leaf !== fabricated)
      .map((leaf) => [leaf.nonce, { status: leaf.status, at: leaf.requestedAt, line: 1 }])
  );

  const reconciled = await reconcileLeaves(leaves, seen);
  assert.equal(reconciled.matched, 4);
  assert.equal(reconciled.discrepancies.length, 1);
  assert.equal(reconciled.discrepancies[0].class, "no_such_request");
  assert.equal(reconciled.discrepancies[0].leaf.nonce, fabricated.nonce);

  /* ---------- 3. They file, signed with their card key ---------- */
  const filing = {
    leafVersion: "1.0.0",
    type: "contradiction",
    leafHash: `sha256:${Array.from(hashes[2], (byte) => byte.toString(16).padStart(2, "0")).join("")}`,
    claimant: "acme-probe-2026q3",
    class: "no_such_request",
    weight: "full",
    evidence: {
      statement: "No request bearing this nonce appears in our access log for the period.",
      accessLogExcerpt: null
    },
    filedAt: new Date(T0 + DAY).toISOString(),
    signature: "detached-jws-by-the-card-key"
  };

  const filedAt = Date.parse(filing.filedAt);

  // Open. The accused leaf is disputed — and still counted.
  assert.equal(contradictionStatus(filing, [], filedAt + 60_000)?.state, "open");
  const disputedGrade = deriveGrade(fabricated, { contradictions: [filing] }, filedAt + 60_000);
  assert.equal(disputedGrade, "disputed");

  const whileOpen = leaves.filter(
    (leaf) => leaf !== fabricated || countsTowardScore(disputedGrade)
  );
  assert.deepEqual(
    aggregate(whileOpen),
    publishedScore,
    "an open contradiction must not move the score — otherwise disputes become a delete button"
  );

  /* ---------- 4. Adjudication ---------- */
  const resolution = {
    leafVersion: "1.0.0",
    type: "resolution",
    contradictionHash: contradictionHashOf(filing),
    state: "upheld",
    decidedAt: new Date(filedAt + 3 * DAY).toISOString(),
    reason: "BNA could not produce a receipt or an egress record for this probe.",
    signature: null
  };

  const now = filedAt + 4 * DAY;
  const finalGrade = deriveGrade(fabricated, { contradictions: [filing], resolutions: [resolution] }, now);
  assert.equal(finalGrade, "poisoned");

  /* ---------- 5. It drops out of the score ---------- */
  const grades = leaves.map((leaf) =>
    leaf === fabricated
      ? finalGrade
      : deriveGrade(leaf, { contradictions: [], resolutions: [] }, now)
  );
  const counted = leaves.filter((_leaf, index) => countsTowardScore(grades[index]));

  const corrected = aggregate(counted);
  assert.equal(counted.length, 4, "the poisoned leaf is excluded from the arithmetic");
  assert.equal(corrected.failure, 0, "the fabricated failure no longer counts against the vendor");
  assert.equal(corrected.uptimePct, 100);
  assert.notDeepEqual(corrected, publishedScore, "the score must change once the contradiction is upheld");

  /* ---------- 6. And is still in the log ---------- */
  assert.equal(leaves.length, 5, "the leaf was excluded, not deleted");
  assert.ok(leaves.includes(fabricated));
  assert.equal(
    await verifyInclusion(hashes[2], 2, 5, proofs[2], root),
    true,
    "the poisoned leaf's inclusion proof must still verify — history is not rewritten"
  );
  assert.deepEqual(await merkleRoot(hashes), root, "the tree root is unchanged by adjudication");
});

test("the corrected bundle verifies with audit-score, disclosing the poisoned leaf", async () => {
  const leaves = [observation(0, "success"), observation(1, "failure")];
  const hashes = await Promise.all(leaves.map((leaf) => leafHash(leaf)));
  const root = await merkleRoot(hashes);
  const hex = (/** @type {Uint8Array} */ bytes) =>
    `sha256:${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

  const entries = [];
  for (let index = 0; index < leaves.length; index += 1) {
    entries.push({
      leaf: leaves[index],
      index,
      grade: index === 1 ? "poisoned" : "logged",
      proof: (await inclusionProof(index, hashes)).map(hex)
    });
  }

  const bundle = {
    agentId: "agt_7c1f",
    period: { from: "2026-06-01T00:00:00.000Z", to: "2026-07-01T00:00:00.000Z" },
    sth: {
      logId: "bna-witness-v1",
      treeSize: leaves.length,
      rootHash: hex(root),
      timestamp: "2026-07-01T00:00:00.000Z",
      signature: "sig"
    },
    leaves: entries,
    // Computed over the one leaf that still counts.
    derived: {
      requested: 1,
      attempted: 1,
      success: 1,
      failure: 0,
      notAttempted: 0,
      uptimePct: 100,
      avgLatencyMs: 80
    },
    grades: { attested: 0, logged: 1, disputed: 0, poisoned: 1 },
    methodologyVersion: "0.1"
  };

  const path = join(scratch, "corrected.json");
  writeFileSync(path, JSON.stringify(bundle));

  const result = await runCli(["audit-score", "agt_7c1f", "--period", "2026-06", "--bundle", path]);
  assert.equal(result.code, 1, result.stdout + result.stderr); // backed, with a warning
  assert.match(result.stdout, /BACKED/);
  assert.match(result.stdout, /1 poisoned/, "the poisoned leaf must be disclosed to the reader");
  assert.match(result.stderr, /contradiction upheld against them/);
});
