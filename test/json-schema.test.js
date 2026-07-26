// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { createEnvelope } from "../src/lib/json-envelope.js";
import { validCard } from "./helpers.js";

const schemaPath = new URL("../schemas/cli-output.schema.json", import.meta.url);
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

/**
 * Small standards-focused test validator. It deliberately covers the keywords
 * used by the committed public schema and avoids adding a runtime dependency.
 *
 * @param {unknown} value
 * @param {Record<string, unknown>} rule
 * @param {Record<string, unknown>} root
 * @returns {boolean}
 */
function validates(value, rule, root) {
  if (typeof rule.$ref === "string") {
    const path = rule.$ref.replace(/^#\//, "").split("/");
    /** @type {unknown} */
    let target = root;
    for (const part of path) {
      if (typeof target !== "object" || target === null) return false;
      target = /** @type {Record<string, unknown>} */ (target)[part];
    }
    return typeof target === "object" && target !== null && validates(value, /** @type {Record<string, unknown>} */ (target), root);
  }
  if (Array.isArray(rule.oneOf)) {
    return rule.oneOf.filter((candidate) => validates(value, /** @type {Record<string, unknown>} */ (candidate), root)).length === 1;
  }
  if (Array.isArray(rule.allOf) && !rule.allOf.every((candidate) => validates(value, /** @type {Record<string, unknown>} */ (candidate), root))) {
    return false;
  }
  if ("const" in rule && value !== rule.const) return false;
  if (Array.isArray(rule.enum) && !rule.enum.includes(value)) return false;
  if (rule.type === "object") {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const object = /** @type {Record<string, unknown>} */ (value);
    if (Array.isArray(rule.required) && rule.required.some((key) => typeof key !== "string" || !(key in object))) return false;
    const properties = typeof rule.properties === "object" && rule.properties !== null ? /** @type {Record<string, unknown>} */ (rule.properties) : {};
    if (
      rule.additionalProperties === false &&
      Object.keys(object).some((key) => !Object.hasOwn(properties, key))
    ) {
      return false;
    }
    return Object.entries(properties).every(([key, child]) => !(key in object) || validates(object[key], /** @type {Record<string, unknown>} */ (child), root));
  }
  if (rule.type === "array") {
    return Array.isArray(value) && (typeof rule.items !== "object" || rule.items === null || value.every((item) => validates(item, /** @type {Record<string, unknown>} */ (rule.items), root)));
  }
  if (rule.type === "string") {
    if (typeof value !== "string") return false;
    return typeof rule.pattern !== "string" || new RegExp(rule.pattern).test(value);
  }
  if (rule.type === "boolean") return typeof value === "boolean";
  if (rule.type === "integer") return typeof value === "number" && Number.isInteger(value) && (typeof rule.minimum !== "number" || value >= rule.minimum);
  return true;
}

test("committed schema accepts each versioned JSON envelope", () => {
  const report = {
    verdict: "ok",
    errors: 0,
    warns: 0,
    fields: Object.keys(validCard()).map((key) => ({ key }))
  };
  const validation = createEnvelope("validate", { report });
  const probe = createEnvelope("probe", {
    summary: {
      specVersion: "1.0.0",
      target: "https://example.invalid",
      vantagePoint: "single-local",
      attempted: 1,
      success: 1,
      failure: 0,
      notAttempted: 0,
      samples: []
    }
  });
  const verification = createEnvelope("verify", { valid: true, algorithm: "EdDSA", keyId: "2026-01" });

  assert.equal(validates(validation, schema, schema), true);
  assert.equal(validates(probe, schema, schema), true);
  assert.equal(validates(verification, schema, schema), true);
});

test("committed schema rejects incompatible envelopes", () => {
  const invalid = createEnvelope("validate", {
    report: { verdict: "ok", errors: 0, warns: 0, fields: [] }
  });
  invalid.schemaVersion = "2.0.0";
  assert.equal(validates(invalid, schema, schema), false);
});
