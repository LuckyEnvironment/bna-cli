// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import {
  SPEC_VERSION,
  aggregate,
  assertAllowedMethod,
  classifyOutcome,
  parseRetryAfter as specParseRetryAfter,
  waitMs as specWaitMs
} from "@bna/probe-protocol";
import { asCodedError, codedError, errorMessage } from "../lib/errors.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { parseRemoteUrl, safeFetch } from "../lib/network-safety.js";
import {
  parseCompactJws,
  signDetachedJws as sharedSignDetachedJws,
  verifyDetachedJws as sharedVerifyDetachedJws
} from "@bna/witness-log";
import {
  RECEIPT_HEADER,
  digestResponseHead,
  openObservation,
  sealObservation
} from "../lib/observation.js";

/**
 * Every normative rule below is imported from `@bna/probe-protocol` rather
 * than restated here. The spec package is what BNA published and what a third
 * party checks an independent implementation against; a second copy in the
 * CLI is a copy that can drift, and each of the three places it drifted
 * before (Retry-After parsing, 3xx classification, the consecutive-429
 * counter) produced output that contradicted the published specification.
 */

const PROBE_USER_AGENT = "BNA CLI/0.1.0 (+https://bna.dev/trust-methodology)";
const DEFAULT_PROBE_INTERVAL_MS = 1_000;
const DEFAULT_DEADLINE_MS = 30_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 8_000;
const DEFAULT_BACKOFF_MS = 1_000;

/**
 * A local probe is one machine, and the leaf says so rather than implying a
 * fleet. `vantagePoint: "single-local"` already carries this in the summary;
 * the leaf repeats it because a leaf has to stand on its own once it is in a
 * log alongside leaves from real vantage points.
 */
const LOCAL_VANTAGE = "single-local";
const LOCAL_PROBE_KEY_ID = "local-unsigned";

/**
 * @typedef {"success" | "failure" | "not_attempted"} ProbeOutcome
 * @typedef {{
 *   index: number,
 *   outcome: ProbeOutcome,
 *   ms: number,
 *   at: string,
 *   status?: number,
 *   reason?: string,
 *   retryAfterMs?: number,
 *   observation?: Record<string, unknown>
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
 * SPEC.md §4.2, resolved by the specification's own parser.
 *
 * @param {string | null} value
 * @param {number} [now]
 * @returns {number | null}
 */
export function parseRetryAfter(value, now = Date.now()) {
  return specParseRetryAfter(value, now);
}

/**
 * SPEC.md §3.1. The allowlist itself lives in the spec package; this wrapper
 * only restates the refusal as a CLI-coded error so the command still exits 2
 * with an actionable message.
 *
 * @param {string | undefined} method
 * @returns {"GET" | "HEAD"}
 */
export function allowedProbeMethod(method) {
  try {
    return assertAllowedMethod(method);
  } catch {
    throw codedError("Probe requests are limited to read-only GET or HEAD. No endpoint tools are invoked.", "INPUT");
  }
}

/**
 * @param {string} url
 * @param {{
 *   index: number,
 *   method: "GET" | "HEAD",
 *   signal: AbortSignal,
 *   deadlineAt: number,
 *   allowPrivateHosts?: boolean,
 *   agentId?: string | null,
 *   targetKeyId?: string | null
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

  // Opened before the request, because the nonce has to be inside it. The
  // headers below are the only ones that carry `BNA-Probe-Nonce`, so there is
  // no path that sends a probe without having committed to a nonce and a
  // `requestedAt` first. See src/lib/observation.js.
  const { commitment, headers } = openObservation({
    target: url,
    agentId: options.agentId ?? null,
    targetKeyId: options.targetKeyId ?? null,
    vantage: LOCAL_VANTAGE,
    probeKeyId: LOCAL_PROBE_KEY_ID,
    method: options.method,
    userAgent: PROBE_USER_AGENT
  });

  try {
    const response = await safeFetch(
      url,
      {
        headers,
        method: options.method,
        signal: requestController.signal
      },
      { allowPrivateHosts: options.allowPrivateHosts }
    );
    const ms = Math.round(performance.now() - started);
    const at = new Date().toISOString();

    // §2.2 decides the outcome, including that 3xx is a success and that a
    // 429 is `not_attempted`. `response.ok` is a 2xx test and is not the
    // spec's rule, so it is deliberately not consulted here.
    const { outcome, reason } = classifyOutcome({ status: response.status });
    const retryAfterMs = response.status === 429 ? parseRetryAfter(response.headers.get("retry-after")) : null;

    // The receipt is captured verbatim and not verified: at this milestone the
    // vendor's key is not fetched, so a receipt is evidence to be checked
    // later, never a grade awarded now.
    const receipt = response.headers.get(RECEIPT_HEADER);
    const responseDigest = digestResponseHead(response.status, response.headers);

    // The body is cancelled, never read. `responseDigest` covers the head
    // alone, so nothing an agent returned is retained anywhere.
    await response.body?.cancel();

    return {
      index: options.index,
      outcome,
      ms,
      at,
      status: response.status,
      ...(reason === undefined ? {} : { reason }),
      ...(retryAfterMs === null ? {} : { retryAfterMs }),
      observation: sealObservation(commitment, {
        outcome,
        reason: reason ?? null,
        status: response.status,
        ms,
        responseDigest,
        receipt
      })
    };
  } catch (error) {
    const coded = asCodedError(error);
    if (coded?.code === "PRIVATE_HOST" || coded?.code === "UNSAFE_URL") throw coded;

    // The two abort causes are kept apart so §2.2's ordering can distinguish
    // them; collapsing them would report an operator interrupt as a deadline.
    const deadlineReached = options.signal.reason === "deadline" || Date.now() >= options.deadlineAt;
    const interrupted = options.signal.aborted && !deadlineReached;
    const { outcome, reason } = classifyOutcome({ interrupted, deadlineReached, status: null });
    const ms = Math.round(performance.now() - started);

    return {
      index: options.index,
      outcome,
      ms,
      at: new Date().toISOString(),
      ...(reason === undefined ? {} : { reason }),
      // A failure is committed with the same nonce that was sent. It is the
      // leaf a vendor can contradict by showing no request ever arrived
      // bearing it — see SURFACE-05 section 5.
      observation: sealObservation(commitment, {
        outcome,
        reason: reason ?? null,
        status: null,
        ms,
        responseDigest: null,
        receipt: null
      })
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
 * Create an RFC 7515 detached compact JWS. The payload's base64url segment is
 * included in the signing input and omitted only from the serialized JWS.
 *
 * @param {Record<string, unknown>} payload
 * @param {string} keyMaterial
 * @param {string | undefined} keyId
 * @returns {Promise<{ format: "detached-jws", detachedJws: string, algorithm: "EdDSA" | "RS256", keyId?: string }>}
 */
export async function signDetachedJws(payload, keyMaterial, keyId) {
  const signing = privateSigningKey(keyMaterial);
  const detachedJws = await sharedSignDetachedJws(payload, {
    algorithm: signing.algorithm,
    privateKey: keyMaterial,
    keyId
  });

  return {
    format: "detached-jws",
    detachedJws,
    algorithm: signing.algorithm,
    ...(keyId ? { keyId } : {})
  };
}

/**
 * @param {Record<string, unknown>} payload
 * @param {unknown} signature
 * @param {string} keyMaterial
 * @returns {Promise<{ valid: boolean, algorithm: "EdDSA" | "RS256", keyId?: string }>}
 */
export async function verifyDetachedJws(payload, signature, keyMaterial) {
  // The envelope checks stay here, because they are the CLI's contract: each
  // one maps to an exit code and an actionable message. Only the JOSE handling
  // moved, so there is one implementation of it rather than two free to drift
  // on exactly the parsing edge cases the receipt replay suite exists to catch.
  if (typeof signature !== "object" || signature === null || Array.isArray(signature)) {
    throw codedError("Summary does not include a detached JWS signature.", "INPUT");
  }
  const record = /** @type {Record<string, unknown>} */ (signature);
  if (record.format !== "detached-jws" || typeof record.detachedJws !== "string") {
    throw codedError("Summary signature is not a supported detached JWS.", "INPUT");
  }

  const parsed = parseCompactJws(record.detachedJws);
  if (parsed === null || !parsed.detached) {
    throw codedError("Detached JWS must use the protected..signature compact form.", "INPUT");
  }
  const header = parsed.header;
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

  const checked = await sharedVerifyDetachedJws(
    record.detachedJws,
    payload,
    key.export({ format: "jwk" })
  );
  const keyId = typeof header.kid === "string" ? header.kid : undefined;
  return { valid: checked.valid, algorithm: header.alg, ...(keyId ? { keyId } : {}) };
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
    let rateLimitCount = 0;

    try {
      for (let index = 1; index <= requested; index += 1) {
        if (controller.signal.aborted || Date.now() >= deadlineAt) {
          const reason = interrupted ? "interrupted" : "deadline_exceeded";
          samples.push({ index, outcome: "not_attempted", ms: 0, at: new Date().toISOString(), reason });
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

        const running = aggregate(samples);
        if (options.watch && !options.json && !options.sign) {
          printProgress(sample, requested, running.success, running.attempted);
        }

        if (index < requested) {
          const rateLimited = sample.outcome === "not_attempted" && sample.reason === "rate_limited";
          // §4.3: the wait is the longer of Retry-After and the backoff, and
          // the consecutive counter resets on any response that is not a 429.
          const wait = specWaitMs({
            rateLimited,
            retryAfterMs: sample.retryAfterMs ?? null,
            consecutiveRateLimits: rateLimitCount,
            intervalMs,
            baseMs: backoffBaseMs
          });
          rateLimitCount = rateLimited ? rateLimitCount + 1 : 0;
          const stopped = await sleep(wait, controller.signal);
          if (stopped && controller.signal.reason !== "deadline") interrupted = true;
        }
      }
    } finally {
      clearTimeout(deadlineTimer);
      process.removeListener("SIGINT", onInterrupt);
    }

    const { attempted, success, failure, notAttempted, uptimePct, avgLatencyMs } = aggregate(samples);

    // The observation leaves travel beside the summary, not inside it. A
    // probe-protocol summary is a published shape with `additionalProperties:
    // false`, and it belongs to the specification rather than to this tool —
    // so the CLI extends its own envelope and leaves that contract alone.
    const observations = samples.map((sample) => sample.observation).filter(Boolean);
    /** @type {ProbeSample[]} */
    const specSamples = samples.map((sample) => {
      const copy = { ...sample };
      delete copy.observation;
      return copy;
    });

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
      uptimePct,
      avgLatencyMs,
      vantagePoint: "single-local",
      vantagePointNote: "Local probes are a single vantage point, not BNA's multi-region trust score.",
      method,
      userAgent: PROBE_USER_AGENT,
      deadlineMs,
      interrupted,
      samples: specSamples
    };
    const output = createEnvelope("probe", { summary, observations });
    if (options.sign && signingKey) {
      Object.assign(output, { signature: await signDetachedJws(output, signingKey, options.keyId) });
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
