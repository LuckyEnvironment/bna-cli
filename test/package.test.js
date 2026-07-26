// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { testDirectory, validCard, withServer } from "./helpers.js";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";

/**
 * Run the installed CLI and collect its output.
 *
 * This must be asynchronous. `execFileSync` blocks this process's event loop,
 * which stops the fixture HTTP server in the same process from ever accepting
 * the child's connection — the probe then times out and reports a network
 * failure that has nothing to do with the code under test.
 *
 * @param {string} bna
 * @param {string[]} args
 * @param {string} cwd
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
function runInstalled(bna, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bna, ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/**
 * @param {string[]} args
 * @param {string} cwd
 * @returns {string}
 */
function execNpm(args, cwd) {
  return execFileSync(npm, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/**
 * Pack the working tree and install the resulting tarball into a scratch
 * project, exactly as a user would receive it.
 *
 * `--offline` is the load-bearing flag: it forbids any registry or git access,
 * so the install can only succeed if every dependency is genuinely bundled
 * inside the tarball. Without it this test would pass while `npx @bna/cli`
 * crashed on a clean machine.
 *
 * @param {string} directory
 * @returns {{ tarball: string, files: string[] }}
 */
function packAndInstall(directory) {
  const packed = /** @type {Array<{ filename: string, files: Array<{ path: string }> }>} */ (
    JSON.parse(execNpm(["pack", "--json"], process.cwd()))
  );
  const tarball = path.join(process.cwd(), packed[0].filename);

  fs.writeFileSync(
    path.join(directory, "package.json"),
    JSON.stringify({ name: "cli-smoke", version: "1.0.0", private: true, type: "module" })
  );
  execNpm(["install", "--ignore-scripts", "--no-package-lock", "--no-audit", "--no-fund", "--offline", tarball], directory);

  return { tarball, files: packed[0].files.map((entry) => entry.path) };
}

test("packed tarball ships only publish files and every runtime dependency", () => {
  const directory = testDirectory("package");
  /** @type {string | undefined} */
  let tarball;
  try {
    const packed = packAndInstall(directory);
    tarball = packed.tarball;
    const { files } = packed;

    assert.ok(files.includes("schemas/cli-output.schema.json"), "output schema is not published");

    // Every runtime dependency must be bundled. A dependency added to
    // package.json but forgotten here produces a tarball that installs fine
    // and then throws MODULE_NOT_FOUND on first use.
    const declared = Object.keys(JSON.parse(fs.readFileSync("package.json", "utf8")).dependencies ?? {});
    assert.ok(declared.length > 0, "expected the CLI to declare runtime dependencies");
    for (const dependency of declared) {
      assert.ok(
        files.some((file) => file.startsWith(`node_modules/${dependency}/`)),
        `${dependency} is declared as a dependency but is not bundled in the tarball`
      );
    }

    assert.ok(
      files.every((file) => !file.startsWith("test/") && !file.startsWith("coverage/") && !file.includes(".env")),
      "tarball contains files that should not be published"
    );
  } finally {
    if (tarball) fs.rmSync(tarball, { force: true });
  }
});

test("every command runs from the installed tarball on a clean machine", async () => {
  const directory = testDirectory("package-commands");
  /** @type {string | undefined} */
  let tarball;
  try {
    tarball = packAndInstall(directory).tarball;
    const bna = path.join(directory, "node_modules", "@bna", "cli", "bin", "bna.js");

    /**
     * @param {string[]} args
     * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
     */
    const run = (args) => runInstalled(bna, args, directory);

    const help = await run(["--help"]);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /bna <command>/);

    const version = await run(["--version"]);
    assert.equal(version.code, 0);
    assert.match(version.stdout, /\d+\.\d+\.\d+/);

    const card = path.join(directory, "card.json");
    fs.writeFileSync(card, JSON.stringify(validCard()));
    const validated = await run(["validate", card, "--json"]);
    assert.equal(validated.code, 0);
    assert.equal(JSON.parse(validated.stdout).result.report.verdict, "ok");

    // `probe` is the command that pulls in @bna/probe-protocol. Exercising it
    // here is what proves that dependency is present in the shipped artifact
    // rather than only in the development tree.
    await withServer(
      (request, response) => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end("{}");
      },
      async (url) => {
        const probed = await run(["probe", url, "--json", "--allow-private"]);
        assert.equal(probed.code, 0, `probe exited ${probed.code}: ${probed.stderr}`);
        const output = JSON.parse(probed.stdout);
        assert.equal(output.tool, "probe");
        assert.equal(output.result.summary.specVersion, "1.0.0");
        assert.equal(output.result.summary.vantagePoint, "single-local");
        assert.equal(output.result.summary.success, 1);
      }
    );
  } finally {
    if (tarball) fs.rmSync(tarball, { force: true });
  }
});
