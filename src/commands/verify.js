// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { asCodedError, codedError, errorMessage } from "../lib/errors.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { resolveSigningKey, verifyDetachedJws } from "./probe.js";

/** @typedef {{ key?: string, json?: boolean }} VerifyOptions */

/**
 * @param {string} target
 * @param {VerifyOptions} [options]
 * @returns {Promise<number>}
 */
export async function verifyCommand(target, options = {}) {
  try {
    const key = resolveSigningKey(options.key);
    if (!key) {
      console.error("Verification requires a public key. Use --key <public.pem> or BNA_PROBE_SIGNING_KEY.");
      return 4;
    }

    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(target, "utf8"));
    } catch {
      throw codedError(`Could not read ${target} as a signed JSON summary.`, "INPUT");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw codedError("Signed summary must be a JSON object.", "INPUT");
    }
    const summary = /** @type {Record<string, unknown>} */ (parsed);
    const signature = summary.signature;
    const payload = { ...summary };
    delete payload.signature;
    const verification = await verifyDetachedJws(payload, signature, key);
    const result = { valid: verification.valid, algorithm: verification.algorithm, ...(verification.keyId ? { keyId: verification.keyId } : {}) };

    if (options.json) {
      writeJson(createEnvelope("verify", result));
    } else if (verification.valid) {
      console.log(`Signature verified (${verification.algorithm}${verification.keyId ? `, key ${verification.keyId}` : ""}).`);
    } else {
      console.error("Signature verification failed. Next action: use the public key that matches the signing key.");
    }
    return verification.valid ? 0 : 2;
  } catch (error) {
    const coded = asCodedError(error);
    if (coded?.code === "NETWORK") return 3;
    console.error(`Verification failed: ${errorMessage(error)} Next action: provide a valid signed summary and public key.`);
    return 2;
  }
}
