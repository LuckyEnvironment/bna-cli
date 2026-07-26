// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";
import { asCodedError, codedError } from "./errors.js";
import { safeFetch } from "./network-safety.js";

/** @typedef {{ allowPrivateHosts?: boolean, signal?: AbortSignal }} ReadJsonOptions */

/**
 * @param {string} input
 * @returns {boolean}
 */
export function isHttpUrl(input) {
  return /^https?:\/\//i.test(input);
}

/**
 * @param {string} target
 * @param {ReadJsonOptions} [options]
 * @returns {Promise<unknown>}
 */
export async function readJsonSource(target, options = {}) {
  if (isHttpUrl(target)) {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 10_000);
    const abort = () => ctrl.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      const res = await safeFetch(
        target,
        { headers: { accept: "application/json" }, method: "GET", signal: ctrl.signal },
        { allowPrivateHosts: options.allowPrivateHosts }
      );
      if (!res.ok) {
        throw codedError(`Target returned HTTP ${res.status} ${res.statusText}.`, "NETWORK");
      }
      try {
        return await res.json();
      } catch {
        throw codedError("Target did not return valid JSON. Check the agent card URL.", "INPUT");
      }
    } catch (err) {
      const coded = asCodedError(err);
      if (coded?.code) throw coded;
      if (err instanceof Error && err.name === "AbortError") {
        throw codedError("Request timed out after 10 seconds. Check the target and try again.", "NETWORK");
      }
      throw codedError(`Could not fetch the target: ${err instanceof Error ? err.message : String(err)}`, "NETWORK");
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
    }
  }
  const abs = path.resolve(process.cwd(), target);
  let raw;
  try {
    raw = fs.readFileSync(abs, "utf8");
  } catch {
    throw codedError(`Could not read ${target}. Check that the file exists.`, "INPUT");
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw codedError(`Could not parse ${target} as JSON. Fix the JSON and try again.`, "INPUT");
  }
}
