// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { login, loginWithDeviceCode, whoami } from "../src/commands/auth.js";
import { diffCommand } from "../src/commands/diff.js";
import {
  allowedProbeMethod,
  parseRetryAfter,
  probeCommand,
  signDetachedJws,
  verifyDetachedJws
} from "../src/commands/probe.js";
import { validateCommand } from "../src/commands/validate.js";
import { getConfigPath, loadConfig } from "../src/lib/config.js";
import { validCard, testDirectory, withServer } from "./helpers.js";

test("auth stores manual and synthetic contexts and reports missing auth", async () => {
  const directory = testDirectory("auth");
  process.env.BNA_CONFIG_DIR = path.join(directory, "config");
  assert.equal(await whoami(), 4);
  assert.equal(await login({ org: "acme", token: "secret-token" }), 0);
  assert.equal(loadConfig().auth?.org, "acme");
  assert.equal(await whoami(), 0);
  assert.equal(await login({}), 0);
  assert.match(loadConfig().auth?.accessToken ?? "", /^local-dev-token-/);
  assert.match(getConfigPath(), /config\.json$/);
});

test("OIDC device-code helper obtains a token without waiting in tests", async () => {
  await withServer(
    (request, response) => {
      response.setHeader("content-type", "application/json");
      if (request.url === "/.well-known/openid-configuration") {
        response.end(
          JSON.stringify({
            device_authorization_endpoint: `http://${request.headers.host}/device`,
            token_endpoint: `http://${request.headers.host}/token`
          })
        );
      } else if (request.url === "/device") {
        response.end(JSON.stringify({ device_code: "device", user_code: "code", verification_uri: "https://example.invalid", interval: 0 }));
      } else {
        response.end(JSON.stringify({ access_token: "access", token_type: "Bearer", expires_in: 1 }));
      }
    },
    async (url) => {
      const auth = await loginWithDeviceCode({ issuer: url, clientId: "client", sleep: async () => {} });
      assert.equal(auth.accessToken, "access");
      assert.equal(auth.clientId, "client");
    }
  );
});

test("diff retains snapshots and validation handles file errors", async () => {
  const directory = testDirectory("diff");
  process.env.BNA_CONFIG_DIR = path.join(directory, "config");
  const target = path.join(directory, "card.json");
  fs.writeFileSync(target, JSON.stringify(validCard()));
  assert.equal(await diffCommand(target), 0);
  assert.equal(await diffCommand(target), 0);
  fs.writeFileSync(target, JSON.stringify(validCard({ version: "2.0.0" })));
  assert.equal(await diffCommand(target), 1);
  assert.equal(await diffCommand(target, { update: true }), 1);
  assert.equal(await diffCommand(target), 0);
  assert.equal(await validateCommand(path.join(directory, "missing.json")), 2);
});

test("probe signing primitives reject unsupported methods and detect mutation", async () => {
  assert.equal(allowedProbeMethod("head"), "HEAD");
  assert.throws(() => allowedProbeMethod("POST"), /read-only GET or HEAD/);
  assert.equal(parseRetryAfter("3"), 3_000);
  assert.equal(parseRetryAfter("invalid"), null);
  const pair = awaitableKeyPair();
  const payload = { schemaVersion: "1.0.0", result: { success: true } };
  // Async since the JOSE handling moved into @bna/witness-log, which has to
  // run in a browser too and therefore cannot use a synchronous digest.
  const signature = await signDetachedJws(payload, pair.privateKey, "test");
  assert.equal((await verifyDetachedJws(payload, signature, pair.publicKey)).valid, true);
  payload.result.success = false;
  assert.equal((await verifyDetachedJws(payload, signature, pair.publicKey)).valid, false);
});

test("probe deadline and SIGINT return honest partial results", async () => {
  await withServer(
    (request, response) => {
      // Deliberately leave the request pending until SIGINT aborts it.
      void request;
      void response;
    },
    async (url) => {
      const deadlineCode = await probeCommand(url, {
        allowPrivateHosts: true,
        deadline: 20,
        intervalMs: 0,
        json: true,
        window: 2
      });
      assert.equal(deadlineCode, 1);
      const interrupt = setTimeout(() => process.emit("SIGINT"), 20);
      try {
        const code = await probeCommand(url, {
          allowPrivateHosts: true,
          deadline: 5_000,
          intervalMs: 0,
          json: true,
          window: 2
        });
        assert.equal(code, 1);
      } finally {
        clearTimeout(interrupt);
      }
    }
  );
});

/**
 * @returns {{ privateKey: string, publicKey: string }}
 */
function awaitableKeyPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey: String(pair.privateKey.export({ format: "pem", type: "pkcs8" })),
    publicKey: String(pair.publicKey.export({ format: "pem", type: "spki" }))
  };
}
