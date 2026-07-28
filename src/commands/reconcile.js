// SPDX-License-Identifier: Apache-2.0

import { readFileSync, statSync } from "node:fs";
import { CONTRADICTION_CLASSES, DEFAULT_SKEW_MS, leafHash, verifyReceipt } from "@bna/witness-log";
import { errorMessage } from "../lib/errors.js";
import { NGINX_LOG_FORMAT_HINT, readAccessLog } from "../lib/access-log.js";
import { createEnvelope, writeJson } from "../lib/json-envelope.js";
import { safeFetch } from "../lib/network-safety.js";

/**
 * `bna reconcile` — check BNA's published measurements of you against your own
 * access log.
 *
 * This is the command that makes BNA falsifiable. Everything it reports is
 * computed on your machine, from your data and from leaves BNA published: BNA
 * is not in the trust path, and no account, key or permission is required to
 * run it.
 *
 * If the log contains a leaf claiming a probe at 14:03:22 and your log has no
 * request bearing that nonce, BNA published a measurement it did not make —
 * and that is now provable, by you, from data BNA published itself.
 *
 * The single most important behaviour in this file is what happens when a log
 * carries no nonces at all. nginx does not record request headers by default,
 * so that is the *expected* first run, and reporting it as "every observation
 * is fabricated" would turn this into a tool for manufacturing false
 * accusations. It reports a configuration problem instead, and exits 2.
 */

const DEFAULT_LOG_BASE = "https://transparency.bna.dev";
const DEFAULT_TIMING_SKEW_MS = DEFAULT_SKEW_MS;

/** @typedef {{ leaf: any, class: string, detail: string }} Discrepancy */

/**
 * @param {string} value e.g. "30d", "12h"
 * @returns {number | null} milliseconds
 */
export function parseSince(value) {
  const match = /^(\d+)\s*([dhw])$/.exec(String(value ?? "").trim());
  if (!match) return null;
  const size = { d: 86_400_000, h: 3_600_000, w: 604_800_000 }[match[2]];
  return Number(match[1]) * /** @type {number} */ (size);
}

/**
 * @param {string} path
 * @returns {any}
 */
function readBundle(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * @param {string} agentId
 * @param {string} base
 * @returns {Promise<any>}
 */
async function fetchLeaves(agentId, base) {
  const url = `${base.replace(/\/$/, "")}/log/v1/leaves/${encodeURIComponent(agentId)}`;
  const response = await safeFetch(url, { headers: { accept: "application/json" } }, {});
  if (!response.ok) throw new Error(`the log returned HTTP ${response.status} for ${url}`);
  return response.json();
}

/**
 * Compare published leaves against the nonces a vendor's log actually recorded.
 *
 * Pure, and takes the nonce index rather than a path, so the matching rules can
 * be tested without a file and the streaming can be tested without the rules.
 *
 * @param {any[]} leaves
 * @param {Map<string, { status: number | null, at: string | null, line: number }>} seen
 * @param {{ skewMs?: number, jwk?: unknown }} [options]
 * @returns {Promise<{ matched: number, statusDisagrees: number, attested: number, discrepancies: Discrepancy[] }>}
 */
export async function reconcileLeaves(leaves, seen, options = {}) {
  const skewMs = Number.isFinite(options.skewMs) ? /** @type {number} */ (options.skewMs) : DEFAULT_TIMING_SKEW_MS;

  let matched = 0;
  let statusDisagrees = 0;
  let attested = 0;
  /** @type {Discrepancy[]} */
  const discrepancies = [];

  for (const leaf of leaves) {
    const record = seen.get(leaf.nonce);

    if (!record) {
      discrepancies.push({
        leaf,
        class: "no_such_request",
        detail: `no request bearing nonce ${leaf.nonce} appears in the log`
      });
      continue;
    }

    matched += 1;

    if (record.status !== null && leaf.status !== null && record.status !== leaf.status) {
      statusDisagrees += 1;
      discrepancies.push({
        leaf,
        class: "status_mismatch",
        detail: `BNA published ${leaf.status}; the log line ${record.line} recorded ${record.status}`
      });
    }

    if (record.at !== null && leaf.requestedAt) {
      const drift = Math.abs(Date.parse(record.at) - Date.parse(leaf.requestedAt));
      if (Number.isFinite(drift) && drift > skewMs) {
        discrepancies.push({
          leaf,
          class: "timing_mismatch",
          detail: `the log line is ${Math.round(drift / 1000)}s from the published requestedAt`
        });
      }
    }

    // A receipt that verifies against the vendor's own key could only have been
    // produced by the vendor. One that does not verify was not — so it was
    // forged by whoever published the leaf.
    if (leaf.receipt && options.jwk) {
      const verdict = await verifyReceipt(leaf, options.jwk);
      if (verdict.valid) attested += 1;
      else if (verdict.reason !== "no receipt was offered") {
        discrepancies.push({
          leaf,
          class: "receipt_forged",
          detail: `the published receipt does not verify against your key: ${verdict.reason}`
        });
      }
    }
  }

  return { matched, statusDisagrees, attested, discrepancies };
}

/**
 * @param {{ agent?: string, since?: string, accessLog?: string, format?: string, nonceField?: string, bundle?: string, logBase?: string, json?: boolean, file?: boolean }} options
 * @returns {Promise<number>}
 */
export async function reconcileCommand(options) {
  if (!options.agent) {
    console.error("Missing --agent. Next action: run bna reconcile --agent <id> --access-log <path>");
    return 2;
  }
  if (!options.accessLog) {
    console.error("Missing --access-log. Next action: point it at your server's access log.");
    return 2;
  }

  const windowMs = options.since ? parseSince(options.since) : null;
  if (options.since && windowMs === null) {
    console.error(`--since must look like 30d, 12h or 2w, got ${JSON.stringify(options.since)}.`);
    return 2;
  }

  /* ---------- the published leaves ---------- */
  /** @type {any} */
  let published;
  try {
    published = options.bundle
      ? readBundle(options.bundle)
      : await fetchLeaves(options.agent, options.logBase ?? DEFAULT_LOG_BASE);
  } catch (error) {
    const offline = Boolean(options.bundle);
    console.error(
      `${errorMessage(error)} Next action: ${offline ? "supply a readable JSON bundle" : "check connectivity, or reconcile a saved bundle with --bundle"}.`
    );
    return offline ? 2 : 3;
  }

  const entries = Array.isArray(published?.leaves) ? published.leaves : [];
  let leaves = entries.map((/** @type {any} */ entry) => entry.leaf ?? entry).filter(Boolean);

  if (windowMs !== null) {
    const cutoff = Date.now() - windowMs;
    leaves = leaves.filter((/** @type {any} */ leaf) => Date.parse(leaf.requestedAt) >= cutoff);
  }

  if (leaves.length === 0) {
    console.error(`No published leaves for ${options.agent} in the window. Nothing to reconcile.`);
    return 2;
  }

  /* ---------- the vendor's log ---------- */
  let bytes = 0;
  try {
    bytes = statSync(options.accessLog).size;
  } catch (error) {
    console.error(`Could not read ${options.accessLog}: ${errorMessage(error)}`);
    return 2;
  }

  /** @type {Map<string, { status: number | null, at: string | null, line: number }>} */
  const seen = new Map();
  let lines = 0;
  let format = "unknown";

  try {
    const reader = readAccessLog(options.accessLog, {
      format: options.format,
      nonceField: options.nonceField
    });
    let step = await reader.next();
    while (!step.done) {
      const entry = step.value;
      // Only the nonces are retained, never the lines. This is what keeps a
      // multi-gigabyte log flat in memory.
      if (!seen.has(entry.nonce)) {
        seen.set(entry.nonce, { status: entry.status, at: entry.at, line: entry.line });
      }
      step = await reader.next();
    }
    lines = step.value.lines;
    format = step.value.format;
  } catch (error) {
    console.error(`Could not parse ${options.accessLog}: ${errorMessage(error)}`);
    return 2;
  }

  /* ---------- the guard that stops false accusations ---------- */
  if (seen.size === 0 && lines > 0) {
    console.error(
      `Read ${lines.toLocaleString()} lines from ${options.accessLog} (${format}) and found no BNA-Probe-Nonce values.\n\n` +
        `This almost certainly means the header is not being logged, not that BNA fabricated ` +
        `${leaves.length.toLocaleString()} observations. Refusing to report contradictions on that basis.\n\n${NGINX_LOG_FORMAT_HINT}\n`
    );
    return 2;
  }

  /* ---------- compare ---------- */
  const jwk = published?.probeKey ?? null;
  const result = await reconcileLeaves(leaves, seen, { jwk });

  const byClass = Object.fromEntries(CONTRADICTION_CLASSES.map((name) => [name, 0]));
  for (const discrepancy of result.discrepancies) byClass[discrepancy.class] += 1;

  if (options.json) {
    writeJson(
      createEnvelope("reconcile", {
        agentId: options.agent,
        leaves: leaves.length,
        logLines: lines,
        logFormat: format,
        matched: result.matched,
        statusDisagrees: result.statusDisagrees,
        attested: result.attested,
        discrepancies: result.discrepancies.map((discrepancy) => ({
          class: discrepancy.class,
          nonce: discrepancy.leaf.nonce,
          requestedAt: discrepancy.leaf.requestedAt,
          detail: discrepancy.detail
        })),
        byClass
      })
    );
  } else {
    const pad = (/** @type {number} */ value) => String(value).padStart(6);
    console.log(`  Leaves published for ${options.agent} in window ${pad(leaves.length)}`);
    console.log(`  Log lines read (${format}) ${pad(lines)}`);
    console.log("");
    console.log(`  Matched in your access log                  ${pad(result.matched)}`);
    console.log(`  Matched, status disagrees                   ${pad(result.statusDisagrees)}`);
    console.log(`  Attested by your own receipts               ${pad(result.attested)}`);
    console.log(`  No corresponding request found              ${pad(byClass.no_such_request)}`);
    console.log("");

    if (result.discrepancies.length === 0) {
      console.log("  Everything BNA published about you is in your own logs.");
    } else {
      for (const discrepancy of result.discrepancies.slice(0, 20)) {
        console.log(`  ${discrepancy.class}  ${discrepancy.leaf.requestedAt}  ${discrepancy.detail}`);
      }
      if (result.discrepancies.length > 20) {
        console.log(`  … and ${result.discrepancies.length - 20} more`);
      }
      console.log(`\n  ${result.discrepancies.length} discrepancies. File them?  bna reconcile --file`);
    }
  }

  if (options.file) {
    console.error(
      "\n  --file is not available yet: filing needs a log service to accept contradictions, " +
        "which is not built. The contradiction leaves and their state machine ship in " +
        "@bna/witness-log; nothing can submit them.\n"
    );
  }

  void bytes;
  void leafHash;
  return result.discrepancies.length > 0 ? 1 : 0;
}
