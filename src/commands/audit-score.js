// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { aggregate } from "@bna/probe-protocol";
import { validate } from "@bna/probe-protocol";
import {
  SCORE_BUNDLE_SCHEMA,
  countsTowardScore,
  leafHash,
  verifyConsistency,
  verifyInclusion
} from "@bna/witness-log";
import { codedError, errorMessage } from "../lib/errors.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { safeFetch } from "../lib/network-safety.js";

/**
 * `bna audit-score` — check that a published number is backed by the log.
 *
 * The four steps come from SURFACE-05 section 6. Every one of them runs
 * offline once the bundle is in hand, and none of them consults BNA for an
 * opinion: the leaves are hashed here, the proofs are checked here, and the
 * arithmetic is re-run here. Pass all four and the score stops being an
 * assertion and becomes a theorem whose premises are all public.
 *
 * What it does not prove is worth saying plainly. A valid bundle shows the
 * leaves were committed to the log before the score was published and that the
 * arithmetic over them is honest. It does not show the observations were
 * honestly *collected* — that a probe BNA claims to have sent was really sent.
 * Only the vendor can check that, from their own logs, using the nonce; see
 * `bna reconcile`.
 */

const DEFAULT_LOG_BASE = "https://transparency.bna.dev";

/** The exit codes, matching the table in README.md. */
const EXIT = Object.freeze({
  backed: 0,
  warnings: 1,
  unbacked: 2,
  fetchFailed: 3
});

/**
 * @param {string} value
 * @returns {boolean}
 */
function isPeriod(value) {
  return /^\d{4}-(0[1-9]|1[0-2])$/.test(value);
}

/**
 * @param {string} hex a "sha256:…" string
 * @returns {Uint8Array | null}
 */
function fromDigest(hex) {
  const match = /^sha256:([0-9a-f]{64})$/.exec(String(hex));
  if (!match) return null;
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(match[1].slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * @param {string} path
 * @returns {unknown}
 */
function readBundleFile(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw codedError(`Could not read ${path}: ${errorMessage(error)}`, "BUNDLE");
  }
}

/**
 * @param {string} agentId
 * @param {string} period
 * @param {string} base
 * @returns {Promise<unknown>}
 */
async function fetchBundle(agentId, period, base) {
  const url = `${base.replace(/\/$/, "")}/log/v1/scorebundle/${encodeURIComponent(agentId)}/${encodeURIComponent(period)}`;
  let response;
  try {
    response = await safeFetch(url, { headers: { accept: "application/json" } }, {});
  } catch (error) {
    throw codedError(`Could not reach the log at ${url}: ${errorMessage(error)}`, "NETWORK");
  }
  if (!response.ok) {
    throw codedError(`The log returned HTTP ${response.status} for ${url}`, "NETWORK");
  }
  try {
    return await response.json();
  } catch (error) {
    throw codedError(`The log returned invalid JSON: ${errorMessage(error)}`, "BUNDLE");
  }
}

/**
 * Verify a bundle. Pure: no I/O, no printing.
 *
 * @param {any} bundle
 * @param {any | null} against an STH the caller recorded independently
 * @returns {Promise<{ backed: boolean, steps: {step: number, name: string, passed: boolean, detail: string | null}[], derived: unknown, grades: Record<string, number>, warnings: string[], notices: string[] }>}
 */
export async function verifyBundle(bundle, against) {
  /** @type {{step: number, name: string, passed: boolean, detail: string | null}[]} */
  const steps = [];

  /** Conditions that make the verdict weaker than it looks. These set exit 1. */
  const warnings = [];

  /**
   * Things the run did not establish. Printed, but they do not change the exit
   * code: running without `--against` is the ordinary first use, and failing
   * it would teach people that a non-zero exit from this command is noise.
   */
  const notices = [];

  const root = fromDigest(bundle.sth?.rootHash);
  const treeSize = bundle.sth?.treeSize;

  /* Step 1 — every leaf is in the tree the bundle names. */
  let inclusionFailure = null;
  if (!root) {
    inclusionFailure = "the tree head has no readable root hash";
  } else {
    for (const entry of bundle.leaves) {
      const computed = await leafHash(entry.leaf);
      const proof = (entry.proof ?? []).map(fromDigest);
      if (proof.some((/** @type {Uint8Array | null} */ node) => node === null)) {
        inclusionFailure = `leaf at index ${entry.index} has a malformed proof`;
        break;
      }
      const ok = await verifyInclusion(computed, entry.index, treeSize, proof, root);
      if (!ok) {
        inclusionFailure = `leaf at index ${entry.index} is not provably in the tree of size ${treeSize}`;
        break;
      }
    }
  }
  steps.push({
    step: 1,
    name: "every leaf has a valid inclusion proof against the bundle's tree head",
    passed: inclusionFailure === null,
    detail: inclusionFailure
  });

  /* Step 2 — the tree head extends one the caller already held. */
  if (against === null) {
    steps.push({
      step: 2,
      name: "the tree head is consistent with an independently recorded one",
      passed: true,
      detail: "skipped: no --against tree head was supplied"
    });
    notices.push(
      "No --against tree head was supplied, so nothing here proves the log has not been rewritten. Record this tree head and pass it next time — a consistency check is only meaningful against something you held before BNA knew you would ask."
    );
  } else {
    const oldRoot = fromDigest(against.rootHash);
    const newRoot = fromDigest(bundle.sth?.rootHash);
    const proof = (against.consistencyProof ?? bundle.consistencyProof ?? []).map(fromDigest);
    const usable =
      oldRoot !== null &&
      newRoot !== null &&
      !proof.some((/** @type {Uint8Array | null} */ node) => node === null);

    const passed =
      usable &&
      (await verifyConsistency(against.treeSize, oldRoot, treeSize, newRoot, proof));

    steps.push({
      step: 2,
      name: "the tree head is consistent with an independently recorded one",
      passed,
      detail: passed
        ? null
        : `the log cannot show that its tree of size ${treeSize} extends the tree of size ${against.treeSize} you recorded`
    });
  }

  /* Step 3 — the arithmetic is re-derived, not accepted, over the leaves that
     may contribute to a score. A poisoned leaf is excluded here rather than
     rejected outright: "excluded, not deleted" means a bundle discloses BNA's
     own upheld errors instead of hiding them, so a verifier has to know they
     are present and check they were not counted.
     SPEC section 2.3 lives in @bna/probe-protocol and is called, not copied:
     attempted = success + failure, `not_attempted` stays out of the
     denominator, and uptimePct/avgLatencyMs are null when nothing was
     attempted rather than 0. */
  const scoreable = bundle.leaves.filter((/** @type {any} */ entry) => countsTowardScore(entry.grade));
  const recomputed = aggregate(scoreable.map((/** @type {any} */ entry) => entry.leaf));
  const claimed = bundle.derived ?? {};
  const mismatches = [];
  for (const key of ["attempted", "success", "failure", "notAttempted", "uptimePct", "avgLatencyMs"]) {
    if (claimed[key] !== /** @type {any} */ (recomputed)[key]) {
      mismatches.push(`${key}: bundle says ${JSON.stringify(claimed[key])}, the leaves give ${JSON.stringify(/** @type {any} */ (recomputed)[key])}`);
    }
  }
  if (claimed.requested !== scoreable.length) {
    mismatches.push(
      `requested: bundle says ${JSON.stringify(claimed.requested)}, it carries ${scoreable.length} scoreable leaves`
    );
  }
  steps.push({
    step: 3,
    name: "re-running the specification's arithmetic over the leaves reproduces the score",
    passed: mismatches.length === 0,
    detail: mismatches.length === 0 ? null : mismatches.join("; ")
  });

  /* Step 4 — nothing upheld against BNA is being counted.

     Not "no poisoned leaf is present". A bundle that disclosed none of BNA's
     overturned measurements would be a bundle a reader learns less from, and
     the doctrine is exclusion rather than deletion. What must hold is that a
     poisoned leaf did not enter the arithmetic — which step 3 above enforces
     by construction, and this step states explicitly so a reader can see it
     was checked rather than assumed. */
  const poisoned = bundle.leaves.filter((/** @type {any} */ entry) => entry.grade === "poisoned");
  const poisonedCounted = poisoned.length > 0 && scoreable.length !== bundle.leaves.length - poisoned.length;
  steps.push({
    step: 4,
    name: "no poisoned leaf contributed to the score",
    passed: !poisonedCounted,
    detail: poisonedCounted
      ? "a leaf with an upheld contradiction against it was counted"
      : poisoned.length === 0
        ? null
        : `${poisoned.length} poisoned leaf/leaves are disclosed and excluded from the arithmetic`
  });

  if (poisoned.length > 0) {
    warnings.push(
      `${poisoned.length} observation(s) in this period had a contradiction upheld against them. They are retained in the log and excluded from the score.`
    );
  }

  // Evidence grades are disclosure, never arithmetic. They say what you can
  // check about BNA — whether the observed party countersigned a measurement —
  // and nothing about the agent's behaviour. A vendor who does not implement
  // receipts sees `logged` here and an identical score, which is enforced by a
  // property test in @bna/witness-log rather than by this comment.
  const grades = { attested: 0, logged: 0, disputed: 0, poisoned: 0 };
  for (const entry of bundle.leaves) {
    if (Object.prototype.hasOwnProperty.call(grades, entry.grade)) grades[entry.grade] += 1;
  }

  const disputed = bundle.leaves.filter((/** @type {any} */ entry) => entry.grade === "disputed");
  if (disputed.length > 0) {
    warnings.push(
      `${disputed.length} leaf/leaves are graded disputed: a contradiction has been filed and is unresolved. They still count until it is upheld.`
    );
  }

  return {
    backed: steps.every((step) => step.passed),
    steps,
    derived: recomputed,
    grades,
    warnings,
    notices
  };
}

/**
 * @param {string} agentId
 * @param {{ period?: string, against?: string, bundle?: string, logBase?: string, json?: boolean }} options
 * @returns {Promise<number>}
 */
export async function auditScoreCommand(agentId, options) {
  const period = options.period ?? "";
  if (!agentId) {
    console.error("Missing <agentId>. Next action: run bna audit-score <agentId> --period YYYY-MM");
    return EXIT.unbacked;
  }
  if (!isPeriod(period)) {
    console.error(`--period must be YYYY-MM, got ${JSON.stringify(period)}. Next action: pass --period 2026-06`);
    return EXIT.unbacked;
  }

  /** @type {any} */
  let bundle;
  try {
    bundle = options.bundle
      ? readBundleFile(options.bundle)
      : await fetchBundle(agentId, period, options.logBase ?? DEFAULT_LOG_BASE);
  } catch (error) {
    const code = /** @type {any} */ (error)?.code;
    console.error(
      `${errorMessage(error)} Next action: ${code === "NETWORK" ? "check connectivity, or verify a saved bundle with --bundle" : "supply a readable JSON bundle"}.`
    );
    return code === "NETWORK" ? EXIT.fetchFailed : EXIT.unbacked;
  }

  const schemaErrors = validate(bundle, SCORE_BUNDLE_SCHEMA);
  if (schemaErrors.length > 0) {
    console.error("The bundle is malformed and was not verified:");
    for (const problem of schemaErrors.slice(0, 10)) console.error(`  ${problem}`);
    console.error("Next action: this is not a score bundle this version can read; check the log's schema version.");
    return EXIT.unbacked;
  }

  /** @type {any} */
  let against = null;
  if (options.against) {
    try {
      against = JSON.parse(readFileSync(options.against, "utf8"));
    } catch (error) {
      console.error(`Could not read ${options.against}: ${errorMessage(error)} Next action: pass a saved tree head as JSON.`);
      return EXIT.unbacked;
    }
  }

  const result = await verifyBundle(bundle, against);

  if (options.json) {
    writeJson(
      createEnvelope("audit-score", {
        agentId,
        period,
        backed: result.backed,
        leafCount: bundle.leaves.length,
        steps: result.steps,
        derived: result.derived,
        grades: result.grades,
        claimed: bundle.derived ?? null
      })
    );
  } else {
    console.log(`  Score bundle for ${agentId}, period ${period} — ${bundle.leaves.length} leaves`);
    for (const step of result.steps) {
      const mark = step.passed ? "PASS" : "FAIL";
      console.log(`  ${mark}  ${step.step}. ${step.name}`);
      if (step.detail) console.log(`        ${step.detail}`);
    }
    console.log(
      `\n  Evidence: ${result.grades.attested} attested · ${result.grades.logged} logged` +
        `${result.grades.disputed ? ` · ${result.grades.disputed} disputed` : ""}` +
        `${result.grades.poisoned ? ` · ${result.grades.poisoned} poisoned` : ""}` +
        `\n  Disclosure only — a countersigned observation is worth exactly what an uncountersigned one is.`
    );
    console.log(
      result.backed
        ? "\n  BACKED — every premise of this score is public and checked."
        : "\n  UNBACKED — this score is not supported by the log. Do not rely on it."
    );
  }

  // Always on stderr, in both modes: stdout under --json has to stay parseable,
  // and a caller piping it must still be told what was not established.
  for (const notice of result.notices) console.error(`  Note: ${notice}`);
  for (const warning of result.warnings) console.error(`  Warning: ${warning}`);

  if (!result.backed) return EXIT.unbacked;
  return result.warnings.length > 0 ? EXIT.warnings : EXIT.backed;
}
