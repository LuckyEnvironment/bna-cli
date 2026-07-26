// SPDX-License-Identifier: Apache-2.0

import { once } from "node:events";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";

/**
 * @param {Record<string, unknown>} [overrides]
 * @returns {Record<string, unknown>}
 */
export function validCard(overrides = {}) {
  return {
    protocolVersion: "1.0",
    name: "Test agent",
    description: "A test agent",
    version: "1.0.0",
    url: "https://example.invalid/a2a",
    "provider.name": "BNA test",
    capabilities: { streaming: true, pushNotifications: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: ["test"],
    "x-bna.residency": "eu-west-1",
    "x-bna.zdr": true,
    "x-bna.compliance": ["GDPR"],
    "x-bna.pricing": { model: "free" },
    "x-bna.contact": "ops@example.invalid",
    ...overrides
  };
}

/**
 * @param {(request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse) => void} listener
 * @param {(url: string) => Promise<void>} action
 * @returns {Promise<void>}
 */
export async function withServer(listener, action) {
  const server = http.createServer(listener);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not allocate test server.");
  try {
    await action(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    server.closeAllConnections();
    await once(server, "close");
  }
}

/**
 * @param {string} name
 * @returns {string}
 */
export function testDirectory(name) {
  const directory = path.join(process.cwd(), ".test-runtime", name);
  fs.rmSync(directory, { force: true, recursive: true });
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

/**
 * @param {string[]} args
 * @param {{ env?: NodeJS.ProcessEnv, cwd?: string }} [options]
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
export function runCli(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["bin/bna.js", ...args], {
      cwd: options.cwd ?? process.cwd(),
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"]
    });
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
