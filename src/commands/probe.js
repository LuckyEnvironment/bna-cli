// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import { SPEC_VERSION } from "@bna/probe-protocol";
import { asCodedError, codedError, errorMessage } from "../lib/errors.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { parseRemoteUrl, safeFetch } from "../lib/network-safety.js";

const PROBE_USER_AGENT = "BNA CLI/0.1.0 (+https://bna.dev/trust-methodology)";
const DEFAULT_PROBE_INTERVAL_MS = 1_000;
const DEFAULT_DEADLINE_MS = 30_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 8_000;
const DEFAULT_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;
const ALLOWED_METHODS = new Set(["GET", "HEAD"]);

/**
 * @typedef {"success" | "failure" | "not_attempted"} ProbeOutcome
 * @typedef {{
 *   index: number,
 *   outcome: ProbeOutcome,
 *   ms: number,
 *   at: string,
 *   status?: number,
 *   reason?: string,
 *   retryAfterMs?: number
 * }} ProbeSample
 * @typedef {{
 *   watch?: boolean,
 *   json?: boolean,
 *   sign?: boolean,
 *   key?: string,
 *   keyId?: string,
 *   window?: number,
 *   deadline?: number,
 *   method?: string,
 *   allowPrivateHosts?: boolean,
 *   intervalMs?: number,
 *   backoffBaseMs?: number
 * }} ProbeOptions
 * @typedef {{
 *   specVersion: string,
 *   target: string,
 *   startedAt: string,
 *   finishedAt: string,
 *   requested: number,
 *   attempted: number,
 *   success: number,
 *   failure: number,
 *   notAttempted: number,
 *   uptimePct: number | null,
 *   avgLatencyMs: number | null,
 *   vantagePoint: "single-local",
 *   vantagePointNote: string,
 *   method: "GET" | "HEAD",
 *   userAgent: string,
 *   deadlineMs: number,
 *   interrupted: boolean,
 *   samples: ProbeSample[]
 * }} ProbeSummary
 */

/**
 * @param {number} milliseconds
 * @param {AbortSignal} signal
 * @returns {Promise<boolean>}
 */
function sleep(milliseconds, signal) {
  if (milliseconds <= 0 || signal.aborted) return Promise.resolve(signal.aborted);
  return new Promise((resolve) => {
    const timer = setTimeout(done, milliseconds);
    function done() {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve(signal.aborted);
    }
    function onAbort() {
      done();
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * @param {string | null} value
 * @param {number} [now]
 * @returns {number | null}
 */
export function parseRetryAfter(value, now = Date.now()) {
  if (!value) return null;
  if (/^\d+$/.test(value.trim())) return Number(value.trim()) * 1_000;
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, date - now);
}

/**
 * @param {string | undefined} method
 * @returns {"GET" | "HEAD"}
 */
export function allowedProbeMethod(method) {
  const normalized = (method ?? "GET").toUpperCase();
  if (!ALLOWED_METHODS.has(normalized)) {
    throw codedError("Probe requests are limited to read-only GET or HEAD. No endpoint tools are invoked.", "INPUT");
  }
  return /** @type {"GET" | "HEAD"} */ (normalized);
}

/**
 * @param {string} url
 * @param {{
 *   index: number,
 *   method: "GET" | "HEAD",
 *   signal: AbortSignal,
 *   deadlineAt: number,
 *   allowPrivateHosts?: boolean
 * }} options
 * @returns {Promise<ProbeSample>}
 */
export async function singleProbe(url, options) {
  const started = performance.now();
  const timeout = Math.max(1, Math.min(DEFAULT_REQUEST_TIMEOUT_MS, options.deadlineAt - Date.now()));
  const requestController = new AbortController();
  const abort = () => requestController.abort();
  options.signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, timeout);

  try {
    const response = await safeFetch(
      url,
      {
        headers: { "user-agent": PROBE_USER_AGENT },
        method: options.method,
        signal: requestController.signal
      },
      { allowPrivateHosts: options.allowPrivateHosts }
    );
    const ms = Math.round(performance.now() - started);
    const at = new Date().toISOString();

    if (response.status === 429) {
      const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
      await response.body?.cancel();
      return {
        index: options.index,
        outcome: "not_attempted",
        ms,
        at,
        status: response.status,
        reason: "rate_limited",
        ...(retryAfterMs === null ? {} : { retryAfterMs })
      };
    }

    await response.body?.cancel();
    return {
      index: options.index,
      outcome: response.ok ? "success" : "failure",
      ms,
      at,
      status: response.status,
      ...(response.ok ? {} : { reason: `http_${response.status}` })
    };
  } catch (error) {
    const coded = asCodedError(error);
    if (coded?.code === "PRIVATE_HOST" || coded?.code === "UNSAFE_URL") throw coded;
    const deadlineReached = options.signal.reason === "deadline" || Date.now() >= options.deadlineAt;
    const interrupted = options.signal.aborted || deadlineReached;
    return {
      index: options.index,
      outcome: interrupted ? "not_attempted" : "failure",
      ms: Math.round(performance.now() - started),
      at: new Date().toISOString(),
      reason: interrupted ? (deadlineReached ? "deadline_exceeded" : "interrupted") : "network_error"
    };
  } finally {
    clearTimeout(timer);
    options.signal.removeEventListener("abort", abort);
  }
}

/**
 * @param {ProbeSample} sample
 * @param {number} requested
 * @param {number} success
 * @param {number} attempted
 * @returns {void}
 */
function printProgress(sample, requested, success, attempted) {
  const uptime = attempted === 0 ? "n/a" : `${((success / attempted) * 100).toFixed(1)}%`;
  const status = sample.outcome === "success" ? "PASS" : sample.outcome === "failure" ? "FAIL" : "----";
  console.log(`  ${status} ${sample.index}/${requested} · local single-vantage · availability ${uptime}`);
}

/**
 * @param {string | undefined} explicitKey
 * @returns {string | null}
 */
export function resolveSigningKey(explicitKey) {
  const value = explicitKey ?? process.env.BNA_PROBE_SIGNING_KEY;
  if (!value) return null;
  if (fs.existsSync(value)) return fs.readFileSync(value, "utf8");
  return value;
}

/**
 * @param {string} keyMaterial
 * @returns {{ key: crypto.KeyObject, algorithm: "EdDSA" | "RS256" }}
 */
function privateSigningKey(keyMaterial) {
  let key;
  try {
    key = crypto.createPrivateKey(keyMaterial);
  } catch {
    throw codedError(
      "Signing key must be an Ed25519 or RSA private PEM (or a path to one). Generate a new key and retry.",
      "INPUT"
    );
  }
  if (key.asymmetricKeyType === "ed25519") return { key, algorithm: "EdDSA" };
  if (key.asymmetricKeyType === "rsa" || key.asymmetricKeyType === "rsa-pss") {
    return { key, algorithm: "RS256" };
  }
  throw codedError("Only Ed25519 and RSA private keys are supported for detached JWS signatures.", "INPUT");
}

/**
 * @param {Buffer} value
 * @returns {string}
 */
function base64url(value) {
  return value.toString("base64url");
}

/**
 * Create an RFC 7515 detached compact JWS. The payload's base64url segment is
 * included in the signing input and omitted only from the serialized JWS.
 *
 * @param {Record<string, unknown>} payload
 * @param {string} keyMaterial
 * @param {string | undefined} keyId
 * @returns {{ format: "detached-jws", detachedJws: string, algorithm: "EdDSA" | "RS256", keyId?: string }}
 */
export function signDetachedJws(payload, keyMaterial, keyId) {
  const signing = privateSigningKey(keyMaterial);
  const protectedHeader = {
    alg: signing.algorithm,
    typ: "JOSE",
    ...(keyId ? { kid: keyId } : {})
  };
  const encodedHeader = base64url(Buffer.from(JSON.stringify(protectedHeader)));
  const encodedPayload = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  const signature =
    signing.algorithm === "EdDSA"
      ? crypto.sign(null, signingInput, signing.key)
      : crypto.sign("RSA-SHA256", signingInput, signing.key);

  return {
    format: "detached-jws",
    detachedJws: `${encodedHeader}..${base64url(signature)}`,
    algorithm: signing.algorithm,
    ...(keyId ? { keyId } : {})
  };
}

/**
 * @param {Record<string, unknown>} payload
 * @param {unknown} signature
 * @param {string} keyMaterial
 * @returns {{ valid: boolean, algorithm: "EdDSA" | "RS256", keyId?: string }}
 */
export function verifyDetachedJws(payload, signature, keyMaterial) {
  if (typeof signature !== "object" || signature === null || Array.isArray(signature)) {
    throw codedError("Summary does not include a detached JWS signature.", "INPUT");
  }
  const record = /** @type {Record<string, unknown>} */ (signature);
  if (record.format !== "detached-jws" || typeof record.detachedJws !== "string") {
    throw codedError("Summary signature is not a supported detached JWS.", "INPUT");
  }
  const parts = record.detachedJws.split(".");
  if (parts.length !== 3 || parts[1] !== "" || !parts[0] || !parts[2]) {
    throw codedError("Detached JWS must use the protected..signature compact form.", "INPUT");
  }

  /** @type {{ alg?: unknown, kid?: unknown }} */
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw codedError("Detached JWS protected header is not valid JSON.", "INPUT");
  }
  if (header.alg !== "EdDSA" && header.alg !== "RS256") {
    throw codedError("Detached JWS uses an unsupported algorithm.", "INPUT");
  }
  if (record.algorithm !== header.alg) {
    throw codedError("Detached JWS algorithm does not match the protected header.", "INPUT");
  }

  let key;
  try {
    key = crypto.createPublicKey(keyMaterial);
  } catch {
    throw codedError("Verification key must be an Ed25519 or RSA public PEM (or a path to one).", "INPUT");
  }
  if (
    (header.alg === "EdDSA" && key.asymmetricKeyType !== "ed25519") ||
    (header.alg === "RS256" && key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "rsa-pss")
  ) {
    throw codedError("Verification key type does not match the JWS algorithm.", "INPUT");
  }

  const encodedPayload = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${parts[0]}.${encodedPayload}`);
  const valid =
    header.alg === "EdDSA"
      ? crypto.verify(null, signingInput, key, Buffer.from(parts[2], "base64url"))
      : crypto.verify("RSA-SHA256", signingInput, key, Buffer.from(parts[2], "base64url"));
  const keyId = typeof header.kid === "string" ? header.kid : undefined;
  return { valid, algorithm: header.alg, ...(keyId ? { keyId } : {}) };
}

/**
 * @param {string} url
 * @param {ProbeOptions} [options]
 * @returns {Promise<number>}
 */
export async function probeCommand(url, options = {}) {
  let signingKey = null;
  try {
    parseRemoteUrl(url);
    const method = allowedProbeMethod(options.method);
    const requested = Number.isFinite(options.window) && Number(options.window) > 0 ? Math.floor(Number(options.window)) : 1;
    const deadlineMs =
      Number.isFinite(options.deadline) && Number(options.deadline) > 0
        ? Math.floor(Number(options.deadline))
        : DEFAULT_DEADLINE_MS;
    const intervalMs =
      Number.isFinite(options.intervalMs) && Number(options.intervalMs) >= 0
        ? Number(options.intervalMs)
        : DEFAULT_PROBE_INTERVAL_MS;
    const backoffBaseMs =
      Number.isFinite(options.backoffBaseMs) && Number(options.backoffBaseMs) >= 0
        ? Number(options.backoffBaseMs)
        : DEFAULT_BACKOFF_MS;

    if (options.sign) {
      signingKey = resolveSigningKey(options.key);
      if (!signingKey) {
        console.error("Signing requested but no private key is available. Use --key <private.pem> or BNA_PROBE_SIGNING_KEY.");
        return 4;
      }
    }

    const controller = new AbortController();
    let interrupted = false;
    const onInterrupt = () => {
      interrupted = true;
      controller.abort("interrupted");
    };
    process.once("SIGINT", onInterrupt);

    const startedAt = new Date().toISOString();
    const deadlineAt = Date.now() + deadlineMs;
    const deadlineTimer = setTimeout(() => controller.abort("deadline"), deadlineMs);
    /** @type {ProbeSample[]} */
    const samples = [];
    let success = 0;
    let failure = 0;
    let notAttempted = 0;
    let totalLatency = 0;
    let rateLimitCount = 0;

    try {
      for (let index = 1; index <= requested; index += 1) {
        if (controller.signal.aborted || Date.now() >= deadlineAt) {
          const reason = interrupted ? "interrupted" : "deadline_exceeded";
          samples.push({ index, outcome: "not_attempted", ms: 0, at: new Date().toISOString(), reason });
          notAttempted += 1;
          break;
        }
        const sample = await singleProbe(url, {
          index,
          method,
          signal: controller.signal,
          deadlineAt,
          allowPrivateHosts: options.allowPrivateHosts
        });
        samples.push(sample);
        if (sample.outcome === "success") {
          success += 1;
          totalLatency += sample.ms;
        } else if (sample.outcome === "failure") {
          failure += 1;
          totalLatency += sample.ms;
        } else {
          notAttempted += 1;
        }
        const attempted = success + failure;
        if (options.watch && !options.json && !options.sign) printProgress(sample, requested, success, attempted);

        if (index < requested) {
          const backoff = Math.min(MAX_BACKOFF_MS, backoffBaseMs * 2 ** rateLimitCount);
          const waitMs =
            sample.outcome === "not_attempted" && sample.reason === "rate_limited"
              ? Math.max(sample.retryAfterMs ?? 0, backoff)
              : intervalMs;
          if (sample.outcome === "not_attempted" && sample.reason === "rate_limited") rateLimitCount += 1;
          const stopped = await sleep(waitMs, controller.signal);
          if (stopped && controller.signal.reason !== "deadline") interrupted = true;
        }
      }
    } finally {
      clearTimeout(deadlineTimer);
      process.removeListener("SIGINT", onInterrupt);
    }

    const attempted = success + failure;
    /** @type {ProbeSummary} */
    const summary = {
      // The summary is a probe-protocol artifact, not a CLI-shaped one: it
      // must validate against the published schema so that a third party can
      // check this output against the spec rather than against our word.
      specVersion: SPEC_VERSION,
      target: url,
      startedAt,
      finishedAt: new Date().toISOString(),
      requested,
      attempted,
      success,
      failure,
      notAttempted,
      uptimePct: attempted === 0 ? null : Number(((success / attempted) * 100).toFixed(2)),
      avgLatencyMs: attempted === 0 ? null : Math.round(totalLatency / attempted),
      vantagePoint: "single-local",
      vantagePointNote: "Local probes are a single vantage point, not BNA's multi-region trust score.",
      method,
      userAgent: PROBE_USER_AGENT,
      deadlineMs,
      interrupted,
      samples
    };
    const output = createEnvelope("probe", { summary });
    if (options.sign && signingKey) {
      Object.assign(output, { signature: signDetachedJws(output, signingKey, options.keyId) });
    }

    if (options.json || options.sign) {
      writeJson(output);
    } else {
      console.log("  Local probe — single vantage point; not a BNA multi-region trust score.");
      console.log(
        `  ${success}/${attempted} successful attempts · ${notAttempted} not attempted · ${summary.avgLatencyMs ?? "n/a"}ms average`
      );
      if (interrupted) console.error("Probe interrupted; partial results were emitted.");
    }

    if (failure > 0) return 3;
    return notAttempted > 0 || interrupted ? 1 : 0;
  } catch (error) {
    const coded = asCodedError(error);
    const exitCode = coded?.code === "NETWORK" ? 3 : 2;
    console.error(`Probe failed: ${errorMessage(error)} Next action: correct the target or use --allow-private only for local testing.`);
    return exitCode;
  }
}
