// SPDX-License-Identifier: Apache-2.0

import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

/**
 * Reading a vendor's access log for probe nonces.
 *
 * Two constraints shape everything here.
 *
 * **It streams.** A busy endpoint's monthly log is measured in gigabytes, and
 * a tool that asks a vendor to hold one in memory to check BNA's honesty is a
 * tool they will not run. Lines are consumed one at a time and only the nonces
 * are retained.
 *
 * **It refuses to guess.** nginx does not log request headers by default, so
 * the overwhelmingly likely first run finds *zero* nonces in a perfectly good
 * log. Reporting that as "every one of BNA's 760 observations is fabricated"
 * would be worse than useless — it would be a tool for manufacturing false
 * accusations against BNA, which is a strange thing for BNA to ship. So zero
 * nonces in a non-empty log is reported as a configuration problem, with the
 * `log_format` line needed to fix it, and never as a contradiction.
 */

/** The header BNA sends, lowercased as it appears in logs. */
export const NONCE_HEADER = "bna-probe-nonce";

/** 16 bytes of base64url. Anything else is not a nonce. */
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22}$/;

/**
 * The one-line change a vendor needs. Printed verbatim when a log turns out to
 * carry no nonces, because "your log_format is missing the header" is useless
 * advice without the line to paste.
 */
export const NGINX_LOG_FORMAT_HINT = `nginx does not log request headers by default. Add the nonce to your log_format:

    log_format bna '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" bna_nonce=$http_bna_probe_nonce';

    access_log /var/log/nginx/access.log bna;

Caddy's JSON log includes request headers already; check that
\`log > format > json\` is set and that headers are not being filtered.`;

/** @typedef {{ nonce: string, status: number | null, at: string | null, line: number }} LogEntry */

/**
 * nginx "combined" plus a trailing `bna_nonce=` field, which is what the hint
 * above produces. The nonce is read from the field wherever it appears, so a
 * vendor who put it in a different position is still understood.
 */
const COMBINED = /"(?:[A-Z]+)\s[^"]*"\s+(\d{3})\s/;
const COMBINED_TIME = /\[([^\]]+)\]/;
const COMBINED_NONCE = /bna[_-]nonce[=:]"?([A-Za-z0-9_-]{22})"?/i;

/**
 * @param {string} line
 * @param {number} number
 * @returns {LogEntry | null}
 */
function parseCombined(line, number) {
  const nonce = COMBINED_NONCE.exec(line);
  if (!nonce) return null;
  const status = COMBINED.exec(line);
  const at = COMBINED_TIME.exec(line);
  return {
    nonce: nonce[1],
    status: status ? Number(status[1]) : null,
    at: at ? nginxTime(at[1]) : null,
    line: number
  };
}

/**
 * nginx's `[10/Oct/2026:13:55:36 +0000]` to ISO 8601. Returns null rather than
 * a wrong answer: a mis-parsed timestamp would produce a `timing_mismatch`
 * accusation out of nothing.
 *
 * @param {string} value
 * @returns {string | null}
 */
function nginxTime(value) {
  const match = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-]\d{4})$/.exec(value);
  if (!match) return null;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = months.indexOf(match[2]);
  if (month < 0) return null;
  const offset = `${match[7].slice(0, 3)}:${match[7].slice(3)}`;
  const parsed = Date.parse(
    `${match[3]}-${String(month + 1).padStart(2, "0")}-${match[1]}T${match[4]}:${match[5]}:${match[6]}${offset}`
  );
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

/**
 * Depth-limited search for the nonce anywhere in a JSON log line.
 *
 * nginx JSON, Caddy JSON and every hand-rolled variant put request headers in a
 * different place — `req.headers`, `request.headers`, a flat `http_*` key. The
 * value is unmistakable (22 characters of base64url under a key naming the
 * header), so it is found by shape rather than by requiring each vendor to
 * describe their schema.
 *
 * @param {unknown} value
 * @param {number} depth
 * @returns {string | null}
 */
function findNonce(value, depth = 0) {
  if (depth > 6 || value === null || typeof value !== "object") return null;

  for (const [key, item] of Object.entries(value)) {
    const named = key.toLowerCase().replace(/[^a-z]/g, "");
    if (named.includes("bnaprobenonce")) {
      const candidate = Array.isArray(item) ? item[0] : item;
      if (typeof candidate === "string" && NONCE_PATTERN.test(candidate)) return candidate;
    }
    const nested = findNonce(item, depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * @param {unknown} value
 * @param {string[]} names
 * @param {number} depth
 * @returns {unknown}
 */
function findField(value, names, depth = 0) {
  if (depth > 6 || value === null || typeof value !== "object") return undefined;
  for (const [key, item] of Object.entries(value)) {
    if (names.includes(key.toLowerCase())) return item;
    const nested = findField(item, names, depth + 1);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

/**
 * @param {string} line
 * @param {number} number
 * @param {string | undefined} nonceField
 * @returns {LogEntry | null}
 */
function parseJsonLine(line, number, nonceField) {
  /** @type {any} */
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    return null;
  }
  if (record === null || typeof record !== "object") return null;

  const nonce = nonceField
    ? readPath(record, nonceField)
    : findNonce(record);
  if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce)) return null;

  const status = findField(record, ["status", "status_code", "response_status"]);
  const at =
    findField(record, ["ts", "time", "timestamp", "time_local", "time_iso8601", "@timestamp"]) ?? null;

  return {
    nonce,
    status: typeof status === "number" ? status : Number.isFinite(Number(status)) ? Number(status) : null,
    at: normaliseTime(at),
    line: number
  };
}

/**
 * `a.b.c` against a parsed record. Used for `--nonce-field`, which exists so a
 * vendor with a log shape nothing recognises can still run this rather than
 * being told their format is unsupported.
 *
 * @param {any} record
 * @param {string} path
 * @returns {unknown}
 */
function readPath(record, path) {
  let cursor = record;
  for (const part of path.split(".")) {
    if (cursor === null || typeof cursor !== "object") return undefined;
    cursor = cursor[part];
  }
  return Array.isArray(cursor) ? cursor[0] : cursor;
}

/**
 * @param {unknown} value
 * @returns {string | null}
 */
function normaliseTime(value) {
  if (typeof value === "number") {
    // Caddy logs seconds with a fractional part.
    const ms = value > 1e12 ? value : value * 1000;
    return new Date(ms).toISOString();
  }
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? nginxTime(value) : new Date(parsed).toISOString();
}

/**
 * Decide a format from the first lines that carry any content.
 *
 * @param {string[]} sample
 * @returns {"nginx-json" | "caddy-json" | "nginx-combined" | "unknown"}
 */
export function sniffFormat(sample) {
  const lines = sample.filter((line) => line.trim().length > 0);
  if (lines.length === 0) return "unknown";

  const json = lines.filter((line) => line.trimStart().startsWith("{"));
  if (json.length >= Math.ceil(lines.length / 2)) {
    for (const line of json) {
      try {
        const record = JSON.parse(line);
        // Caddy's shape is distinctive: a `request` object with its own headers.
        if (record && typeof record === "object" && record.request && "headers" in record.request) {
          return "caddy-json";
        }
      } catch {
        /* fall through to the generic JSON reader */
      }
    }
    return "nginx-json";
  }

  return lines.some((line) => COMBINED.test(line)) ? "nginx-combined" : "unknown";
}

/**
 * Read a log, yielding one entry per line that carries a nonce.
 *
 * Deliberately a generator over a line stream: memory stays flat regardless of
 * file size, and the caller decides what to retain.
 *
 * @param {string} path
 * @param {{ format?: string, nonceField?: string }} [options]
 * @returns {AsyncGenerator<LogEntry, { lines: number, format: string, matched: number }>}
 */
export async function* readAccessLog(path, options = {}) {
  const sample = [];
  let format = options.format && options.format !== "auto" ? options.format : null;

  const input = createInterface({
    input: createReadStream(path, { encoding: "utf8", highWaterMark: 1 << 20 }),
    crlfDelay: Number.POSITIVE_INFINITY
  });

  let lines = 0;
  let matched = 0;

  for await (const line of input) {
    lines += 1;

    // Sniff from the first few lines, then commit. Re-deciding per line would
    // let one odd line change how every later one is read.
    if (format === null) {
      sample.push(line);
      if (sample.length < 5) continue;
      format = sniffFormat(sample);
      for (const [offset, buffered] of sample.entries()) {
        const entry = parseLine(buffered, lines - sample.length + offset + 1, format, options.nonceField);
        if (entry) {
          matched += 1;
          yield entry;
        }
      }
      sample.length = 0;
      continue;
    }

    const entry = parseLine(line, lines, format, options.nonceField);
    if (entry) {
      matched += 1;
      yield entry;
    }
  }

  // A file shorter than the sample window never triggered the flush above.
  if (format === null) {
    format = sniffFormat(sample);
    for (const [offset, buffered] of sample.entries()) {
      const entry = parseLine(buffered, offset + 1, format, options.nonceField);
      if (entry) {
        matched += 1;
        yield entry;
      }
    }
  }

  return { lines, format: format ?? "unknown", matched };
}

/**
 * @param {string} line
 * @param {number} number
 * @param {string} format
 * @param {string | undefined} nonceField
 * @returns {LogEntry | null}
 */
function parseLine(line, number, format, nonceField) {
  if (line.trim().length === 0) return null;
  if (format === "nginx-combined") return parseCombined(line, number);
  if (format === "unknown") {
    // Try both rather than give up: an unrecognised shape is not a reason to
    // report a vendor's honest log as empty.
    return parseJsonLine(line, number, nonceField) ?? parseCombined(line, number);
  }
  return parseJsonLine(line, number, nonceField);
}
