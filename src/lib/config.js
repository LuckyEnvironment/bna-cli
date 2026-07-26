// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * @typedef {{
 *   org?: string,
 *   tokenType?: string,
 *   accessToken?: string,
 *   issuer?: string,
 *   clientId?: string,
 *   scope?: string,
 *   refreshToken?: string | null,
 *   expiresAt?: string | null,
 *   source?: string,
 *   updatedAt?: string
 * }} AuthContext
 * @typedef {{ hash: string, at: string, card: unknown }} Snapshot
 * @typedef {{ auth?: AuthContext, snapshots?: Record<string, Snapshot> }} Config
 */

function configDirectory() {
  return process.env.BNA_CONFIG_DIR ?? path.join(os.homedir(), ".config", "bna-cli");
}

function configPath() {
  return path.join(configDirectory(), "config.json");
}

/** @returns {Config} */
export function loadConfig() {
  try {
    const raw = fs.readFileSync(configPath(), "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? /** @type {Config} */ (parsed)
      : {};
  } catch {
    return {};
  }
}

/** @param {Config} cfg */
export function saveConfig(cfg) {
  fs.mkdirSync(configDirectory(), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2));
}

/** @returns {string} */
export function getConfigPath() {
  return configPath();
}
