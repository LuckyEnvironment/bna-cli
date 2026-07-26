// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import { loadConfig, saveConfig } from "../lib/config.js";
import { codedError, errorMessage } from "../lib/errors.js";

const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/** @typedef {{ issuer?: string, clientId?: string, scope?: string, org?: string, token?: string }} LoginFlags */
/** @typedef {{ issuer: string, clientId: string, scope?: string, sleep?: (milliseconds: number) => Promise<void> }} DeviceLoginOptions */

/**
 * @param {unknown} value
 * @returns {Record<string, unknown>}
 */
function record(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? /** @type {Record<string, unknown>} */ (value) : {};
}

/**
 * @param {Record<string, unknown>} object
 * @param {string} key
 * @returns {string | undefined}
 */
function stringValue(object, key) {
  const value = object[key];
  return typeof value === "string" ? value : undefined;
}

/**
 * @param {string} url
 * @param {RequestInit} [init]
 * @returns {Promise<Record<string, unknown>>}
 */
async function fetchJson(url, init = {}) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const response = await fetch(url, { ...init, signal: ctrl.signal });
    const text = await response.text();
    let json;
    try {
      json = record(text ? JSON.parse(text) : {});
    } catch {
      json = {};
    }
    if (!response.ok) {
      throw codedError(
        stringValue(json, "error_description") ?? stringValue(json, "error") ?? `${response.status} ${response.statusText}`,
        "HTTP"
      );
    }
    return json;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * @param {DeviceLoginOptions} options
 * @returns {Promise<import("../lib/config.js").AuthContext>}
 */
export async function loginWithDeviceCode(options) {
  const configUrl = `${options.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const metadata = await fetchJson(configUrl);
  const deviceEndpoint = stringValue(metadata, "device_authorization_endpoint");
  const tokenEndpoint = stringValue(metadata, "token_endpoint");
  if (!deviceEndpoint || !tokenEndpoint) {
    throw new Error("Issuer does not publish device_authorization_endpoint/token_endpoint.");
  }

  const startBody = new URLSearchParams({ client_id: options.clientId });
  if (options.scope) startBody.set("scope", options.scope);
  const device = await fetchJson(deviceEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: startBody.toString()
  });
  const deviceCode = stringValue(device, "device_code");
  const userCode = stringValue(device, "user_code");
  const verificationUri = stringValue(device, "verification_uri");
  if (!deviceCode || !userCode || !verificationUri) {
    throw new Error("Device authorization response missing device_code/user_code/verification_uri.");
  }

  console.log(`Open: ${stringValue(device, "verification_uri_complete") ?? verificationUri}`);
  console.log(`Enter code: ${userCode}`);
  console.log("Waiting for approval...");

  const interval = Math.max(2, Number(device.interval ?? 5));
  const expiresAt = Date.now() + Number(device.expires_in ?? 900) * 1_000;
  const wait = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));

  while (Date.now() < expiresAt) {
    await wait(interval * 1_000);
    const tokenBody = new URLSearchParams({
      grant_type: DEVICE_GRANT_TYPE,
      device_code: deviceCode,
      client_id: options.clientId
    });
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 10_000);
    try {
      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString(),
        signal: ctrl.signal
      });
      const text = await response.text();
      const json = record(text ? JSON.parse(text) : {});
      const accessToken = stringValue(json, "access_token");
      if (response.ok && accessToken) {
        return {
          issuer: options.issuer,
          clientId: options.clientId,
          scope: stringValue(json, "scope") ?? options.scope ?? "",
          tokenType: stringValue(json, "token_type") ?? "Bearer",
          accessToken,
          refreshToken: stringValue(json, "refresh_token") ?? null,
          expiresAt:
            typeof json.expires_in === "number"
              ? new Date(Date.now() + json.expires_in * 1_000).toISOString()
              : null
        };
      }
      const errorCode = stringValue(json, "error");
      if (errorCode === "authorization_pending") continue;
      if (errorCode === "slow_down") {
        await wait(5_000);
        continue;
      }
      if (errorCode === "expired_token") throw new Error("Device code expired before approval.");
      if (errorCode === "access_denied") throw new Error("Login was denied.");
      throw new Error(stringValue(json, "error_description") ?? errorCode ?? `Token endpoint failed (${response.status}).`);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw new Error("Timed out waiting for device approval.");
}

/** @returns {string} */
function syntheticToken() {
  return `local-dev-token-${crypto.randomUUID().replace(/-/g, "")}`;
}

/**
 * @param {LoginFlags} flags
 * @returns {Promise<number>}
 */
export async function login(flags) {
  const org = flags.org ?? "default-org";
  /** @type {import("../lib/config.js").AuthContext} */
  let auth;
  if (flags.token) {
    auth = { org, tokenType: "Bearer", accessToken: flags.token, source: "manual", updatedAt: new Date().toISOString() };
  } else if (flags.issuer && flags.clientId) {
    auth = {
      org,
      ...(await loginWithDeviceCode({ issuer: flags.issuer, clientId: flags.clientId, scope: flags.scope })),
      source: "oidc-device-code",
      updatedAt: new Date().toISOString()
    };
  } else {
    auth = {
      org,
      tokenType: "Bearer",
      accessToken: syntheticToken(),
      source: "local-dev",
      updatedAt: new Date().toISOString()
    };
  }
  const cfg = loadConfig();
  cfg.auth = auth;
  saveConfig(cfg);
  console.log(`✓ signed in for org "${org}" (${auth.source})`);
  return 0;
}

/** @returns {Promise<number>} */
export async function whoami() {
  const cfg = loadConfig();
  if (!cfg.auth?.accessToken) {
    console.error("Not signed in. Run: bna login --org <slug> --token <token>");
    return 4;
  }
  console.log(`Org: ${cfg.auth.org ?? "unknown"}`);
  if (cfg.auth.issuer) {
    console.log(`Issuer: ${cfg.auth.issuer}`);
    console.log(`Client ID: ${cfg.auth.clientId ?? "unknown"}`);
  }
  if (cfg.auth.scope) console.log(`Scope: ${cfg.auth.scope}`);
  console.log(`Token: ${mask(cfg.auth.accessToken)}`);
  if (cfg.auth.expiresAt) console.log(`Expires: ${cfg.auth.expiresAt}`);
  console.log(`Source: ${cfg.auth.source ?? "unknown"}`);
  console.log(`Updated: ${cfg.auth.updatedAt ?? "unknown"}`);
  return 0;
}

/**
 * @param {string} token
 * @returns {string}
 */
function mask(token) {
  if (token.length <= 8) return "********";
  return `${token.slice(0, 4)}…${token.slice(-4)}`;
}

export { errorMessage };
