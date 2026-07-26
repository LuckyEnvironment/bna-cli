// SPDX-License-Identifier: Apache-2.0

import dns from "node:dns/promises";
import net from "node:net";
import { codedError } from "./errors.js";

const V4_BLOCKED = [
  { base: "0.0.0.0", mask: 8 },
  { base: "10.0.0.0", mask: 8 },
  { base: "100.64.0.0", mask: 10 },
  { base: "127.0.0.0", mask: 8 },
  { base: "169.254.0.0", mask: 16 },
  { base: "172.16.0.0", mask: 12 },
  { base: "192.0.0.0", mask: 24 },
  { base: "192.0.2.0", mask: 24 },
  { base: "192.168.0.0", mask: 16 },
  { base: "198.18.0.0", mask: 15 },
  { base: "198.51.100.0", mask: 24 },
  { base: "203.0.113.0", mask: 24 },
  { base: "224.0.0.0", mask: 4 }
];

const METADATA_HOSTS = new Set([
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal"
]);

/** @typedef {{ allowPrivateHosts?: boolean, maxRedirects?: number }} NetworkSafetyOptions */

/**
 * @param {string} ip
 * @returns {number}
 */
function ipv4ToInt(ip) {
  return ip.split(".").reduce((accumulator, octet) => (accumulator << 8) + Number(octet), 0) >>> 0;
}

/**
 * @param {string} ip
 * @param {string} base
 * @param {number} mask
 * @returns {boolean}
 */
function cidrContains(ip, base, mask) {
  const bits = mask === 0 ? 0 : (~((1 << (32 - mask)) - 1) >>> 0);
  return (ipv4ToInt(ip) & bits) === (ipv4ToInt(base) & bits);
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    return V4_BLOCKED.some((range) => cidrContains(ip, range.base, range.mask));
  }

  if (!net.isIPv6(ip)) return false;
  const lowered = ip.toLowerCase();
  return (
    lowered === "::" ||
    lowered === "::1" ||
    lowered.startsWith("fc") ||
    lowered.startsWith("fd") ||
    /^fe[89ab]/.test(lowered)
  );
}

/**
 * @param {string} hostname
 * @returns {boolean}
 */
function isBlockedHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    METADATA_HOSTS.has(normalized) ||
    normalized.endsWith(".metadata.google.internal")
  );
}

/**
 * Reject a hostname that can resolve to local, private, link-local, or cloud
 * metadata address space. This is copied from the sandbox safety model so URL
 * handling does not drift between the local and hosted entry points.
 *
 * @param {string} hostname
 * @param {NetworkSafetyOptions} [options]
 * @returns {Promise<void>}
 */
export async function assertRemoteHostAllowed(hostname, options = {}) {
  if (options.allowPrivateHosts) return;

  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (isBlockedHostname(normalized) || isPrivateAddress(normalized)) {
    throw codedError(
      "Private, link-local, and metadata hosts are blocked. Use --allow-private only for local development.",
      "PRIVATE_HOST"
    );
  }

  let records;
  try {
    records = await dns.lookup(normalized, { all: true });
  } catch {
    throw codedError(`Could not resolve ${hostname}. Check the hostname and DNS connection.`, "NETWORK");
  }
  if (records.length === 0) {
    throw codedError(`Host ${hostname} has no DNS records. Check the hostname.`, "NETWORK");
  }

  for (const record of records) {
    if (isPrivateAddress(record.address)) {
      throw codedError(
        "The target resolves to a private, link-local, or metadata address and was blocked.",
        "PRIVATE_HOST"
      );
    }
  }
}

/**
 * @param {string | URL} input
 * @returns {URL}
 */
export function parseRemoteUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw codedError("Target must be an absolute http or https URL.", "UNSAFE_URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw codedError("Target must use http or https.", "UNSAFE_URL");
  }
  if (url.username || url.password) {
    throw codedError("URLs containing credentials are not accepted.", "UNSAFE_URL");
  }
  return url;
}

/**
 * Fetch an untrusted URL without allowing automatic redirects. Every redirect
 * target is parsed and checked again before a connection is made.
 *
 * @param {string | URL} input
 * @param {RequestInit} [init]
 * @param {NetworkSafetyOptions} [options]
 * @returns {Promise<Response>}
 */
export async function safeFetch(input, init = {}, options = {}) {
  const maxRedirects = options.maxRedirects ?? 3;
  let current = parseRemoteUrl(input);

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    await assertRemoteHostAllowed(current.hostname, options);
    let response;
    try {
      response = await fetch(current, { ...init, redirect: "manual" });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") throw error;
      throw codedError(`Could not fetch ${current.hostname}: ${error instanceof Error ? error.message : String(error)}`, "NETWORK");
    }

    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) return response;
    if (redirects === maxRedirects) {
      throw codedError(`Redirect limit of ${maxRedirects} reached. Check the target URL.`, "NETWORK");
    }
    await response.body?.cancel();
    current = parseRemoteUrl(new URL(location, current));
  }

  throw codedError("Redirect handling failed unexpectedly.", "NETWORK");
}
