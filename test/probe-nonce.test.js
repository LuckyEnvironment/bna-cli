// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { validate } from "@bna/probe-protocol";
import { OBSERVATION_LEAF_SCHEMA } from "@bna/witness-log";
import {
  NONCE_HEADER,
  digestResponseHead,
  normaliseResponseHead,
  openObservation,
  sealObservation
} from "../src/lib/observation.js";
import { runCli, withServer } from "./helpers.js";

/**
 * The ordering property, tested end to end.
 *
 * A nonce is only worth anything if it was fixed before the outcome was known.
 * That is not checkable by reading the leaf — a leaf built afterwards looks
 * identical. It is checkable from the *target's* side: the server records the
 * `BNA-Probe-Nonce` it received, and the emitted leaf must carry that same
 * value. If someone refactors the probe so the leaf is constructed after the
 * response is read, the nonce in the leaf cannot be the one the server saw,
 * and this test fails.
 */

test("the nonce in the leaf is the nonce the server received", async () => {
  /** @type {string[]} */
  const received = [];

  await withServer(
    (request, response) => {
      received.push(String(request.headers[NONCE_HEADER.toLowerCase()] ?? ""));
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    },
    async (url) => {
      const result = await runCli([
        "probe",
        url,
        "--window",
        "2",
        "--json",
        "--allow-private"
      ]);
      assert.equal(result.code, 0, result.stderr);

      const output = JSON.parse(result.stdout);
      const observations = output.result.observations;

      assert.equal(observations.length, 2, "one leaf per probe");
      assert.equal(received.length, 2, "the server did not see two probes");

      for (const [index, observation] of observations.entries()) {
        assert.match(observation.nonce, /^[A-Za-z0-9_-]{22}$/, "a nonce is not 16 base64url bytes");
        assert.equal(
          observation.nonce,
          received[index],
          "the leaf's nonce is not the one that was sent — the leaf was not committed before the request"
        );
      }

      // Distinct per probe: a reused nonce would let one request stand in for
      // another, which is the whole property being bought here.
      assert.notEqual(observations[0].nonce, observations[1].nonce);
    }
  );
});

test("requestedAt precedes the response, and every leaf is schema-conformant", async () => {
  await withServer(
    (request, response) => {
      response.writeHead(200, { "content-type": "application/json", etag: '"abc"' });
      response.end("{}");
    },
    async (url) => {
      const before = new Date().toISOString();
      const result = await runCli(["probe", url, "--window", "1", "--json", "--allow-private"]);
      const after = new Date().toISOString();
      assert.equal(result.code, 0, result.stderr);

      const [observation] = JSON.parse(result.stdout).result.observations;
      assert.ok(observation.requestedAt >= before, "requestedAt precedes the command");
      assert.ok(observation.requestedAt <= after, "requestedAt is after the command finished");

      assert.deepEqual(
        validate(observation, OBSERVATION_LEAF_SCHEMA),
        [],
        "a probe emitted a leaf that does not match the published schema"
      );
    }
  );
});

test("a receipt header is captured verbatim and not interpreted", async () => {
  const receipt = "eyJhbGciOiJFZERTQSJ9..not-a-real-signature";

  await withServer(
    (request, response) => {
      response.writeHead(200, { "content-type": "application/json", "bna-probe-receipt": receipt });
      response.end("{}");
    },
    async (url) => {
      const result = await runCli(["probe", url, "--window", "1", "--json", "--allow-private"]);
      const [observation] = JSON.parse(result.stdout).result.observations;

      // Captured, not verified: at this milestone the vendor's key is never
      // fetched, so a receipt is evidence for later, not a grade awarded now.
      assert.equal(observation.receipt, receipt);
    }
  );
});

test("a probe with no receipt records null, and is not penalised for it", async () => {
  await withServer(
    (request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    },
    async (url) => {
      const result = await runCli(["probe", url, "--window", "1", "--json", "--allow-private"]);
      const output = JSON.parse(result.stdout);
      const [observation] = output.result.observations;

      assert.equal(observation.receipt, null);
      // The outcome is decided by the response, never by whether a receipt was
      // offered. A missing receipt is absence of evidence, not evidence of
      // absence — see SURFACE-05 section 4.
      assert.equal(observation.outcome, "success");
      assert.equal(output.result.summary.success, 1);
    }
  );
});

test("sealObservation cannot be handed anything but a real commitment", () => {
  const { commitment } = openObservation({
    target: "https://example.invalid/a2a",
    vantage: "single-local",
    probeKeyId: "local-unsigned",
    method: "GET",
    userAgent: "test"
  });

  const observed = { outcome: /** @type {const} */ ("success"), ms: 10 };

  // A hand-built object with all the right fields is still refused: the only
  // way to obtain a commitment is to have opened one before the request.
  assert.throws(() => sealObservation(/** @type {any} */ ({ ...commitment }), observed), TypeError);
  assert.throws(() => sealObservation(/** @type {any} */ (null), observed), TypeError);
  assert.throws(() => sealObservation(/** @type {any} */ ({}), observed), TypeError);

  assert.equal(sealObservation(commitment, observed).nonce, commitment.nonce);
});

test("a commitment is frozen, so a nonce cannot be rewritten once sent", () => {
  const { commitment, headers } = openObservation({
    target: "https://example.invalid/a2a",
    vantage: "single-local",
    probeKeyId: "local-unsigned",
    method: "GET",
    userAgent: "test"
  });

  assert.equal(Object.isFrozen(commitment), true);
  assert.throws(() => {
    /** @type {any} */ (commitment).nonce = "rewritten";
  }, TypeError);

  // The headers are the only carrier of the nonce, and they come from the same
  // call — a probe cannot send one without having committed to it.
  assert.equal(headers[NONCE_HEADER], commitment.nonce);
});

test("the response digest covers the head only, and never the body", () => {
  const headers = new Headers({
    "content-type": "application/json",
    etag: '"v1"',
    "set-cookie": "session=secret",
    "x-internal": "should-not-appear"
  });

  const normalised = normaliseResponseHead(200, headers);

  assert.match(normalised, /^status: 200\n/);
  assert.match(normalised, /content-type: application\/json/);
  assert.match(normalised, /etag: "v1"/);

  // Anything outside the allowlist stays out — the digest must not become a
  // channel through which response content is retained.
  assert.doesNotMatch(normalised, /set-cookie/);
  assert.doesNotMatch(normalised, /secret/);
  assert.doesNotMatch(normalised, /x-internal/);

  // Reproducible: the same head always gives the same digest.
  assert.equal(digestResponseHead(200, headers), digestResponseHead(200, headers));
  assert.notEqual(digestResponseHead(200, headers), digestResponseHead(503, headers));
  assert.equal(digestResponseHead(null, null), null);
});

test("header order does not change the digest", () => {
  const one = new Headers({ "content-type": "application/json", etag: '"v1"' });
  const two = new Headers({ etag: '"v1"', "content-type": "application/json" });
  assert.equal(digestResponseHead(200, one), digestResponseHead(200, two));
});
