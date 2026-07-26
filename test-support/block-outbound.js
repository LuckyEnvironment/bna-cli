// SPDX-License-Identifier: Apache-2.0

import dns from "node:dns/promises";

const allowedOrigin = process.env.BNA_ALLOWED_ORIGIN;
if (!allowedOrigin) throw new Error("BNA_ALLOWED_ORIGIN is required for the outbound test hook.");

const nativeFetch = globalThis.fetch;
/** @type {typeof fetch} */
const guardedFetch = async (input, init) => {
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  if (url.origin !== allowedOrigin) throw new Error(`Outbound request blocked by no-telemetry test: ${url.origin}`);
  return nativeFetch(input, init);
};
globalThis.fetch = guardedFetch;

const nativeLookup = dns.lookup.bind(dns);
/** @type {{ lookup: (hostname: string, options: unknown) => Promise<unknown> }} */
const mutableDns = /** @type {any} */ (dns);
mutableDns.lookup = async (hostname, options) => {
  if (hostname !== "127.0.0.1") throw new Error(`DNS lookup blocked by no-telemetry test: ${hostname}`);
  return nativeLookup(hostname, /** @type {any} */ (options));
};
