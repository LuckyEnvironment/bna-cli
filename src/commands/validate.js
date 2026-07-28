// SPDX-License-Identifier: Apache-2.0

import { readJsonSource } from "../lib/io.js";
import { asCodedError, errorMessage } from "../lib/errors.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { readCardField, validateCard } from "../schema.js";

/** @typedef {{ strict?: boolean, json?: boolean, allowPrivateHosts?: boolean }} ValidateOptions */

/**
 * @param {string} target
 * @param {ValidateOptions} [options]
 * @returns {Promise<number>}
 */
export async function validateCommand(target, options = {}) {
  try {
    const card = await readJsonSource(target, { allowPrivateHosts: options.allowPrivateHosts });
    const report = validateCard(card, { strict: options.strict });
    if (options.json) {
      writeJson(createEnvelope("validate", { report }));
    } else {
      printHuman(report, card);
    }
    if (report.errors > 0) return 2;
    if (report.warns > 0) return 1;
    return 0;
  } catch (err) {
    const coded = asCodedError(err);
    if (coded?.code === "NETWORK") {
      console.error(`Network error: ${coded.message} Next action: check reachability and retry.`);
      return 3;
    }
    console.error(`Validation failed: ${errorMessage(err)} Next action: correct the input and try again.`);
    return 2;
  }
}

/**
 * @param {unknown} card
 * @param {string} key
 * @returns {unknown}
 */
function cardValue(card, key) {
  if (typeof card !== "object" || card === null || Array.isArray(card)) return undefined;
  const record = /** @type {Record<string, unknown>} */ (card);
  return record[key];
}

/**
 * @param {string} label
 * @param {"PASS" | "WARN" | "FAIL" | "----"} state
 * @param {string} detail
 * @returns {string}
 */
function humanLine(label, state, detail) {
  const prefix = `  ${label.padEnd(22)} ${state.padEnd(6)} `;
  const maximumDetailLength = 99 - prefix.length;
  const shortened = detail.length > maximumDetailLength ? `${detail.slice(0, Math.max(0, maximumDetailLength - 1))}…` : detail;
  return `${prefix}${shortened}`;
}

/**
 * Describe a field the CLI cannot check from here.
 *
 * Both branches end in the same disclaimer, because both are the same state:
 * BNA did not measure this. A declared value is reported as a declaration and
 * never as an observation.
 *
 * @param {string | null} declared
 * @returns {string}
 */
function unverifiable(declared) {
  return declared === null ? "not declared, not verifiable externally" : `declared ${declared}, not verifiable externally`;
}

/**
 * Render only local observations. In particular, a card declaration is never
 * shown as a transport, residency, or retention pass.
 *
 * @param {ReturnType<typeof validateCard>} report
 * @param {unknown} card
 * @returns {void}
 */
export function printHuman(report, card) {
  const schemaState = report.verdict === "ok" ? "PASS" : report.verdict === "warn" ? "WARN" : "FAIL";
  const capabilities = cardValue(card, "capabilities");
  const capabilityCount =
    typeof capabilities === "object" && capabilities !== null && !Array.isArray(capabilities)
      ? Object.keys(capabilities).length
      : 0;
  const protocol = cardValue(card, "protocolVersion");
  const schemaDetail =
    schemaState === "PASS"
      ? `a2a/${typeof protocol === "string" ? protocol : "unknown"}, ${report.fields.length} fields, ${capabilityCount} capabilities declared`
      : `${report.errors} blocking, ${report.warns} incomplete fields`;

  // Resolved through the validator, not by reading the flat key directly, so
  // that a card using the accepted nested form is not reported as undeclared.
  const residency = readCardField(card, "x-bna.residency");
  const zdr = readCardField(card, "x-bna.zdr");

  console.log(humanLine("Card schema", schemaState, schemaDetail));
  console.log(humanLine("Transport", "----", "not observed by local schema validation"));
  console.log(
    humanLine("Residency", "----", unverifiable(typeof residency.value === "string" ? residency.value : null))
  );
  console.log(
    humanLine(
      "Retention policy",
      "----",
      unverifiable(zdr.value === true ? "zero-retention" : zdr.value === false ? "retention" : null)
    )
  );
  // `infos` are counted separately and never as failures. An undeclared probe
  // key is the vendor declining to countersign BNA's measurements of them,
  // which is their right and costs them nothing.
  const infos = report.infos ?? 0;
  console.log(
    `\n  ${report.fields.filter((field) => field.level === "ok").length} checks passed · ${report.warns} warnings · ${report.errors} failures` +
      (infos > 0 ? ` · ${infos} informational, no verdict` : "")
  );
}
