// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { parseFlags, runCli as runCliDirect } from "../src/cli.js";
import { validCard, runCli, testDirectory, withServer } from "./helpers.js";

/**
 * @param {string} directory
 * @param {string} name
 * @param {unknown} value
 * @returns {string}
 */
function writeJson(directory, name, value) {
  const target = path.join(directory, name);
  fs.writeFileSync(target, JSON.stringify(value));
  return target;
}

test("clean validation display is plain, bounded, and marks observations as unverifiable", async () => {
  const directory = testDirectory("display");
  const card = writeJson(directory, "card.json", validCard());
  const result = await runCli(["validate", card], { env: { BNA_CONFIG_DIR: path.join(directory, "config") } });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Card schema\s+PASS/);
  assert.match(result.stdout, /Transport\s+----/);
  assert.match(result.stdout, /Residency\s+----/);
  assert.match(result.stdout, /Retention policy\s+----/);
  assert.doesNotMatch(result.stdout, /\x1b\[/);
  for (const line of result.stdout.split("\n")) assert.ok(line.length <= 100, `line exceeded 100 columns: ${line}`);
});

test("a card using the accepted nested extension form is never reported as undeclared", async () => {
  // validateCard accepts `x-bna: { residency }` as a style warning, so the
  // renderer must resolve it the same way. Reading the flat key alone told a
  // compliant vendor their residency was "not declared" — the product exists
  // to stop exactly that kind of unfounded statement about a third party.
  const directory = testDirectory("nested-extension-form");
  const { "x-bna.residency": residency, "x-bna.zdr": zdr, ...flat } = validCard();
  const card = writeJson(directory, "card.json", {
    ...flat,
    "x-bna": { residency, zdr }
  });

  const result = await runCli(["validate", card], { env: { BNA_CONFIG_DIR: path.join(directory, "config") } });

  assert.match(result.stdout, /Residency\s+----\s+declared eu-west-1/, "a declared residency was rendered as absent");
  assert.match(result.stdout, /Retention policy\s+----\s+declared zero-retention/);
  assert.doesNotMatch(result.stdout, /not declared/, "the card declared these fields; the output says it did not");

  // Still unverified, and still never a pass.
  assert.match(result.stdout, /Residency\s+----/);
  assert.doesNotMatch(result.stdout, /Residency\s+PASS/);
});

test("all documented exit codes have an executable CLI path", async () => {
  const directory = testDirectory("exit-codes");
  const config = path.join(directory, "config");
  const good = writeJson(directory, "good.json", validCard());
  const warning = writeJson(directory, "warning.json", validCard({ "x-bna.contact": undefined }));
  const invalid = writeJson(directory, "invalid.json", {});

  assert.equal((await runCli(["validate", good], { env: { BNA_CONFIG_DIR: config } })).code, 0);
  assert.equal((await runCli(["validate", warning], { env: { BNA_CONFIG_DIR: config } })).code, 1);
  assert.equal((await runCli(["validate", invalid], { env: { BNA_CONFIG_DIR: config } })).code, 2);
  assert.equal((await runCli(["whoami"], { env: { BNA_CONFIG_DIR: path.join(directory, "empty") } })).code, 4);

  await withServer(
    (_request, response) => {
      response.writeHead(503);
      response.end();
    },
    async (url) => {
      const probe = await runCli(["probe", url, "--allow-private", "--json"], { env: { BNA_CONFIG_DIR: config } });
      assert.equal(probe.code, 3);
      assert.doesNotThrow(() => JSON.parse(probe.stdout));
      assert.match(probe.stderr, /allow-private/);
    }
  );
});

test("JSON output uses the public envelope and keeps diagnostics off stdout", async () => {
  await withServer(
    (_request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(validCard()));
    },
    async (url) => {
      const directory = testDirectory("json");
      const result = await runCli(["validate", url, "--allow-private", "--json"], {
        env: { BNA_CONFIG_DIR: path.join(directory, "config") }
      });
      assert.equal(result.code, 0);
      const output = JSON.parse(result.stdout);
      assert.deepEqual(Object.keys(output).sort(), ["generatedAt", "result", "schemaVersion", "tool", "toolVersion"]);
      assert.equal(output.schemaVersion, "1.0.0");
      assert.equal(output.tool, "validate");
      assert.match(result.stderr, /allow-private/);
    }
  );
});

test("private targets are rejected unless loudly opted in", async () => {
  const result = await runCli(["validate", "http://127.0.0.1:1/card.json", "--json"]);
  assert.equal(result.code, 2);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Private, link-local, and metadata hosts are blocked/);
});

test("no telemetry test blocks every outbound request except the supplied target", async () => {
  await withServer(
    (_request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(validCard()));
    },
    async (url) => {
      const directory = testDirectory("no-telemetry");
      const hook = new URL("../test-support/block-outbound.js", import.meta.url).href;
      const result = await runCli(["validate", url, "--allow-private", "--json"], {
        env: {
          BNA_ALLOWED_ORIGIN: url,
          BNA_CONFIG_DIR: path.join(directory, "config"),
          NODE_OPTIONS: `--import=${hook}`
        }
      });
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).tool, "validate");
    }
  );
});

test("probe is polite, excludes rate limits, and never sends a tool invocation", async () => {
  /** @type {string[]} */
  const methods = [];
  /** @type {string[]} */
  const agents = [];
  let calls = 0;
  await withServer(
    (request, response) => {
      calls += 1;
      methods.push(request.method ?? "");
      agents.push(request.headers["user-agent"] ?? "");
      if (calls === 1) {
        response.writeHead(429, { "retry-after": "0" });
      } else {
        response.writeHead(200);
      }
      response.end();
    },
    async (url) => {
      const directory = testDirectory("probe");
      const result = await runCli(["probe", url, "--window", "2", "--deadline", "5000", "--allow-private", "--json"], {
        env: { BNA_CONFIG_DIR: path.join(directory, "config") }
      });
      assert.equal(result.code, 1);
      const output = JSON.parse(result.stdout);
      assert.equal(output.result.summary.attempted, 1);
      assert.equal(output.result.summary.success, 1);
      assert.equal(output.result.summary.notAttempted, 1);
      assert.equal(output.result.summary.uptimePct, 100);
      assert.equal(output.result.summary.samples[0].reason, "rate_limited");
      assert.deepEqual(methods, ["GET", "GET"]);
      assert.ok(agents.every((agent) => agent.includes("BNA CLI/") && agent.includes("https://bna.dev/trust-methodology")));

      const denied = await runCli(["probe", url, "--method", "POST", "--allow-private", "--json"]);
      assert.equal(denied.code, 2);
      assert.equal(calls, 2);
    }
  );
});

test("probe signatures round trip through bna verify using Ed25519 detached JWS", async () => {
  const directory = testDirectory("signatures");
  const pair = crypto.generateKeyPairSync("ed25519");
  const privatePath = path.join(directory, "private.pem");
  const publicPath = path.join(directory, "public.pem");
  fs.writeFileSync(privatePath, pair.privateKey.export({ format: "pem", type: "pkcs8" }));
  fs.writeFileSync(publicPath, pair.publicKey.export({ format: "pem", type: "spki" }));

  await withServer(
    (_request, response) => {
      response.writeHead(200);
      response.end();
    },
    async (url) => {
      const signed = await runCli(["probe", url, "--allow-private", "--json", "--sign", "--key", privatePath, "--key-id", "2026-01"]);
      assert.equal(signed.code, 0, signed.stderr);
      const summary = JSON.parse(signed.stdout);
      assert.match(summary.signature.detachedJws, /^[^.]+\.\.[^.]+$/);
      const summaryPath = writeJson(directory, "summary.json", summary);

      const verified = await runCli(["verify", summaryPath, "--key", publicPath, "--json"]);
      assert.equal(verified.code, 0, verified.stderr);
      assert.equal(JSON.parse(verified.stdout).result.valid, true);

      summary.result.summary.success = 9;
      writeJson(directory, "tampered.json", summary);
      const tampered = await runCli(["verify", path.join(directory, "tampered.json"), "--key", publicPath, "--json"]);
      assert.equal(tampered.code, 2);
      assert.equal(JSON.parse(tampered.stdout).result.valid, false);
    }
  );
});

test("flag parser and direct runner preserve command errors", async () => {
  assert.deepEqual(parseFlags(["validate", "card.json", "--strict"]).positionals, ["validate", "card.json"]);
  assert.throws(() => parseFlags(["--window"]), /Missing value/);
  assert.equal(await runCliDirect(["unknown"]), 2);
});
