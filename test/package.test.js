// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { testDirectory, validCard } from "./helpers.js";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";

/**
 * @param {string[]} args
 * @param {string} cwd
 * @returns {string}
 */
function execNpm(args, cwd) {
  return execFileSync(npm, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

test("packed tarball contains only publish files and runs with its bundled validator", () => {
  const directory = testDirectory("package");
  /** @type {string | undefined} */
  let tarball;
  try {
    const packed = /** @type {Array<{ filename: string, files: Array<{ path: string }> }>} */ (
      JSON.parse(execNpm(["pack", "--json"], process.cwd()))
    );
    tarball = path.join(process.cwd(), packed[0].filename);
    const files = packed[0].files.map((entry) => entry.path);
    assert.ok(files.includes("schemas/cli-output.schema.json"));
    assert.ok(files.includes("node_modules/@bna/validator-core/src/index.js"));
    assert.ok(files.every((file) => !file.startsWith("test/") && !file.startsWith("coverage/") && !file.includes(".env")));

    execNpm(["init", "--yes"], directory);
    execNpm(["install", "--ignore-scripts", "--no-package-lock", "--no-audit", "--no-fund", "--offline", tarball], directory);
    const card = path.join(directory, "card.json");
    fs.writeFileSync(card, JSON.stringify(validCard()));
    const stdout = execFileSync(process.execPath, ["node_modules/@bna/cli/bin/bna.js", "validate", card, "--json"], {
      cwd: directory,
      encoding: "utf8"
    });
    assert.equal(JSON.parse(stdout).result.report.verdict, "ok");
  } finally {
    if (tarball) fs.rmSync(tarball, { force: true });
  }
});
