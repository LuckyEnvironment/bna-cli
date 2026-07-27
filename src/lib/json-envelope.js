// SPDX-License-Identifier: Apache-2.0

export const JSON_SCHEMA_VERSION = "1.0.0";
export const CLI_VERSION = "0.1.0";

/** @typedef {"validate" | "probe" | "verify" | "audit-score"} JsonTool */

/**
 * @template {Record<string, unknown>} T
 * @param {JsonTool} tool
 * @param {T} result
 * @returns {{ schemaVersion: string, tool: JsonTool, toolVersion: string, generatedAt: string, result: T }}
 */
export function createEnvelope(tool, result) {
  return {
    schemaVersion: JSON_SCHEMA_VERSION,
    tool,
    toolVersion: CLI_VERSION,
    generatedAt: new Date().toISOString(),
    result
  };
}

/**
 * The only stdout writer used by machine-readable commands.
 *
 * @param {unknown} value
 * @returns {void}
 */
export function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}
