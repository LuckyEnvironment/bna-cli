// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { ALLOWED_METHODS, SPEC_VERSION, USER_AGENT_PATTERN, validateSummary } from "@bna/probe-protocol";
import { runCli, withServer } from "./helpers.js";

/**
 * Checkpoint 4 of the build brief: the CLI's probe output must validate
 * against the published schema, and where the two disagree the specification
 * is what BNA promised. This test is the mechanism that keeps that true — it
 * runs the real command and parses the real bytes rather than a hand-built
 * object, so the CLI cannot drift away from the spec without going red.
 */

/**
 * @param {string} stdout
 * @returns {Record<string, any>}
 */
function probeSummary(stdout) {
  const envelope = JSON.parse(stdout);
  assert.equal(envelope.tool, "probe");
  return envelope.result.summary;
}

test("probe output validates against the published probe-protocol schema", async () => {
  await withServer(
    (request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    },
    async (url) => {
      const { code, stdout } = await runCli(["probe", url, "--json", "--window", "2", "--allow-private"]);
      assert.equal(code, 0);
      const summary = probeSummary(stdout);
      assert.deepEqual(validateSummary(summary), [], "probe summary is not conformant");
      assert.equal(summary.specVersion, SPEC_VERSION);
      assert.equal(summary.vantagePoint, "single-local");
      assert.equal(summary.samples.length, 2);
    }
  );
});

test("a rate-limited run stays conformant and keeps 429s out of the denominator", async () => {
  await withServer(
    (request, response) => {
      response.writeHead(429, { "retry-after": "0" });
      response.end();
    },
    async (url) => {
      const { stdout } = await runCli(["probe", url, "--json", "--window", "2", "--allow-private"]);
      const summary = probeSummary(stdout);
      assert.deepEqual(validateSummary(summary), []);
      assert.equal(summary.failure, 0, "a 429 was recorded as a failure");
      assert.equal(summary.attempted, 0);
      assert.equal(summary.uptimePct, null, "unmeasured availability was reported as a number");
      assert.equal(summary.avgLatencyMs, null);
      assert.ok(summary.samples.every((/** @type {any} */ sample) => sample.reason === "rate_limited"));
    }
  );
});

test("a deadline-truncated run emits a conformant partial summary", async () => {
  await withServer(
    (request, response) => {
      response.writeHead(200);
      response.end("{}");
    },
    async (url) => {
      const { stdout } = await runCli([
        "probe",
        url,
        "--json",
        "--window",
        "5",
        "--deadline",
        "1",
        "--allow-private"
      ]);
      const summary = probeSummary(stdout);
      assert.deepEqual(validateSummary(summary), [], "partial results must still be conformant");
    }
  );
});

test("the CLI and the specification agree on probe etiquette", async () => {
  /** @type {Array<{ method: string | undefined, userAgent: string | undefined }>} */
  const seen = [];
  await withServer(
    (request, response) => {
      seen.push({ method: request.method, userAgent: request.headers["user-agent"] });
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    },
    async (url) => {
      const { stdout } = await runCli(["probe", url, "--json", "--window", "1", "--allow-private"]);
      const summary = probeSummary(stdout);

      assert.ok(ALLOWED_METHODS.includes(summary.method), `${summary.method} is not read-only`);
      assert.match(summary.userAgent, USER_AGENT_PATTERN, "probe does not identify itself as SPEC.md §4.1 requires");

      // What the target actually received, not merely what we reported.
      assert.equal(seen.length, 1);
      assert.ok(ALLOWED_METHODS.includes(String(seen[0].method)), `${seen[0].method} reached the endpoint`);
      assert.match(String(seen[0].userAgent), USER_AGENT_PATTERN);
    }
  );
});
