// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes } from "node:crypto";
import { LEAF_VERSION } from "@bna/witness-log";

/**
 * Observation leaves, and the ordering rule that makes them worth anything.
 *
 * A nonce fixed *before* the request is sent cannot be minted afterwards to
 * match a story, and because it travels in a request header the target's own
 * infrastructure holds an independent record of the same event. That is the
 * whole basis on which a vendor can later contradict a measurement BNA
 * published. If the nonce were generated after the response came back, the
 * leaf would still look identical and the property would be silently gone.
 *
 * So the ordering is enforced by construction rather than by comment:
 * `openObservation` is the only source of both the nonce and the request
 * headers that carry it. A probe physically cannot send `BNA-Probe-Nonce`
 * without having opened the commitment first, and `sealObservation` has no way
 * to produce a nonce or a timestamp of its own — it can only copy the ones it
 * is handed.
 */

/**
 * The commitments this process has issued.
 *
 * A `WeakSet` rather than a marker property, because a property — even a
 * symbol-keyed one — survives `{...commitment}`, so a spread copy would have
 * passed the check. Identity does not: a copy is a different object and is
 * refused. That matters because the copy is exactly what a well-meaning
 * refactor produces when someone wants to "adjust one field" after the
 * response has come back.
 */
const issued = new WeakSet();

export const NONCE_HEADER = "BNA-Probe-Nonce";
export const RECEIPT_HEADER = "BNA-Probe-Receipt";

/**
 * Response headers that go into `responseDigest`.
 *
 * A fixed allowlist, not "everything we saw": the digest has to be reproducible
 * by a third party, and it must not become a channel through which response
 * content is retained. The body is never read. This is a retention commitment
 * that the zero-retention posture agent cards declare depends on, not an
 * optimisation.
 */
const DIGESTED_HEADERS = Object.freeze([
  "content-length",
  "content-type",
  "etag",
  "last-modified",
  "location",
  "retry-after"
]);

/**
 * @typedef {{
 *   leafVersion: string,
 *   type: "observation",
 *   target: string,
 *   agentId: string | null,
 *   targetKeyId: string | null,
 *   vantage: string,
 *   probeKeyId: string,
 *   nonce: string,
 *   requestedAt: string,
 *   method: "GET" | "HEAD"
 * }} Commitment
 */

/**
 * 16 cryptographically random bytes, base64url, unpadded.
 *
 * @returns {string}
 */
function freshNonce() {
  return randomBytes(16).toString("base64url");
}

/**
 * Fix everything that must be decided before the outcome is known, and produce
 * the request headers that carry it.
 *
 * @param {{
 *   target: string,
 *   agentId?: string | null,
 *   targetKeyId?: string | null,
 *   vantage: string,
 *   probeKeyId: string,
 *   method: "GET" | "HEAD",
 *   userAgent: string
 * }} fields
 * @returns {{ commitment: Commitment, headers: Record<string, string> }}
 */
export function openObservation(fields) {
  const commitment = Object.freeze({
    leafVersion: LEAF_VERSION,
    type: /** @type {"observation"} */ ("observation"),
    target: fields.target,
    agentId: fields.agentId ?? null,
    targetKeyId: fields.targetKeyId ?? null,
    vantage: fields.vantage,
    probeKeyId: fields.probeKeyId,
    nonce: freshNonce(),
    requestedAt: new Date().toISOString(),
    method: fields.method
  });
  issued.add(commitment);

  return {
    commitment: /** @type {Commitment} */ (commitment),
    headers: Object.freeze({
      "user-agent": fields.userAgent,
      [NONCE_HEADER]: commitment.nonce
    })
  };
}

/**
 * The normalised response head: the status, then the allowlisted headers,
 * lowercased and sorted. Never the body.
 *
 * @param {number | null} status
 * @param {Headers | null} headers
 * @returns {string}
 */
export function normaliseResponseHead(status, headers) {
  const lines = [`status: ${status ?? ""}`];
  for (const name of DIGESTED_HEADERS) {
    const value = headers?.get(name);
    if (value !== null && value !== undefined) lines.push(`${name}: ${value}`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * @param {number | null} status
 * @param {Headers | null} headers
 * @returns {string | null}
 */
export function digestResponseHead(status, headers) {
  if (status === null || headers === null) return null;
  const hash = createHash("sha256").update(normaliseResponseHead(status, headers), "utf8").digest("hex");
  return `sha256:${hash}`;
}

/**
 * Complete a leaf once the outcome is known.
 *
 * Takes the commitment rather than the fields inside it, so there is no path
 * by which a nonce or a `requestedAt` can be introduced at this point. Refuses
 * anything that did not come from `openObservation`.
 *
 * @param {Commitment} commitment
 * @param {{
 *   outcome: "success" | "failure" | "not_attempted",
 *   reason?: string | null,
 *   status?: number | null,
 *   ms: number,
 *   responseDigest?: string | null,
 *   receipt?: string | null
 * }} observed
 * @returns {Record<string, unknown>}
 */
export function sealObservation(commitment, observed) {
  if (typeof commitment !== "object" || commitment === null || !issued.has(commitment)) {
    throw new TypeError(
      "sealObservation requires the commitment object returned by openObservation, not a copy of it"
    );
  }

  return {
    leafVersion: commitment.leafVersion,
    type: commitment.type,
    target: commitment.target,
    agentId: commitment.agentId,
    targetKeyId: commitment.targetKeyId,
    vantage: commitment.vantage,
    probeKeyId: commitment.probeKeyId,
    nonce: commitment.nonce,
    requestedAt: commitment.requestedAt,
    method: commitment.method,
    outcome: observed.outcome,
    reason: observed.reason ?? null,
    status: observed.status ?? null,
    ms: observed.ms,
    responseDigest: observed.responseDigest ?? null,
    receipt: observed.receipt ?? null
  };
}
