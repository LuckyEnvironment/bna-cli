// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import { loadConfig, saveConfig } from "../lib/config.js";
import { asCodedError, errorMessage } from "../lib/errors.js";
import { readJsonSource } from "../lib/io.js";

/** @typedef {{ update?: boolean, allowPrivateHosts?: boolean }} DiffOptions */

/**
 * @param {unknown} card
 * @returns {string}
 */
function hashCard(card) {
  return crypto.createHash("sha256").update(JSON.stringify(card)).digest("hex");
}

/**
 * @param {unknown} object
 * @param {string} [prefix]
 * @param {Record<string, unknown>} [out]
 * @returns {Record<string, unknown>}
 */
function flat(object, prefix = "", out = {}) {
  if (typeof object !== "object" || object === null || Array.isArray(object)) return out;
  for (const [keyPart, value] of Object.entries(object)) {
    const key = prefix ? `${prefix}.${keyPart}` : keyPart;
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      flat(value, key, out);
    } else {
      out[key] = value;
    }
  }
  return out;
}

/**
 * @param {string} target
 * @param {DiffOptions} [options]
 * @returns {Promise<number>}
 */
export async function diffCommand(target, options = {}) {
  try {
    const card = await readJsonSource(target, { allowPrivateHosts: options.allowPrivateHosts });
    const currentHash = hashCard(card);
    const cfg = loadConfig();
    cfg.snapshots ??= {};
    const previous = cfg.snapshots[target];

    if (!previous) {
      cfg.snapshots[target] = { hash: currentHash, at: new Date().toISOString(), card };
      saveConfig(cfg);
      console.log(`No prior snapshot for ${target}. Baseline created.`);
      return 0;
    }

    if (previous.hash === currentHash) {
      console.log(`✓ manifest matches sha256:${currentHash.slice(0, 10)}…`);
      return 0;
    }

    const previousFlat = flat(previous.card);
    const nextFlat = flat(card);
    /** @type {Array<{ key: string, from: unknown, to: unknown }>} */
    const changed = [];
    const keys = new Set([...Object.keys(previousFlat), ...Object.keys(nextFlat)]);
    for (const key of keys) {
      const before = previousFlat[key];
      const after = nextFlat[key];
      if (JSON.stringify(before) !== JSON.stringify(after)) changed.push({ key, from: before, to: after });
    }

    console.log(`! manifest drift detected (${changed.length} changed fields)`);
    for (const row of changed.slice(0, 20)) {
      console.log(`! ${row.key}: ${JSON.stringify(row.from)} -> ${JSON.stringify(row.to)}`);
    }

    if (options.update) {
      cfg.snapshots[target] = { hash: currentHash, at: new Date().toISOString(), card };
      saveConfig(cfg);
      console.log("Snapshot updated.");
    } else {
      console.log("Run with --update to accept this as the new baseline.");
    }
    return 1;
  } catch (error) {
    const coded = asCodedError(error);
    if (coded?.code === "NETWORK") {
      console.error(`Network error: ${coded.message} Next action: check reachability and retry.`);
      return 3;
    }
    console.error(`Diff failed: ${errorMessage(error)} Next action: correct the input and try again.`);
    return 2;
  }
}
