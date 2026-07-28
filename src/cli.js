// SPDX-License-Identifier: Apache-2.0

import { login, whoami } from "./commands/auth.js";
import { diffCommand } from "./commands/diff.js";
import { probeCommand } from "./commands/probe.js";
import { reconcileCommand } from "./commands/reconcile.js";
import { auditScoreCommand } from "./commands/audit-score.js";
import { validateCommand } from "./commands/validate.js";
import { verifyCommand } from "./commands/verify.js";
import { errorMessage } from "./lib/errors.js";
import { CLI_VERSION } from "./lib/json-envelope.js";

/** @typedef {Record<string, string | boolean>} Flags */

function helpText() {
  return `
bna <command> [options]

Commands:
  login [--org <slug>] [--token <value>]   Save local auth context
        [--issuer <url> --client-id <id> [--scope <value>]]
  whoami                                    Show active auth context
  validate <url|file> [--strict] [--json] [--allow-private]
                                            Validate an A2A card
  probe <url> [--watch] [--window <n>] [--deadline <ms>] [--json]
        [--sign --key <private.pem> [--key-id <id>]] [--allow-private]
                                            Run read-only liveness probes
  verify <summary.json> --key <public.pem> [--json]
                                            Verify a detached JWS summary
  diff <url|file> [--update] [--allow-private]
                                            Compare card to stored snapshot
  reconcile --agent <id> --access-log <path> [--since 30d] [--format auto]
        [--bundle <file>] [--nonce-field <path>] [--json]
                                            Check BNA's claims against your logs
  audit-score <agentId> --period <YYYY-MM> [--against <sth.json>]
        [--bundle <bundle.json>] [--log-base <url>] [--json]
                                            Check a score against the log

Flags:
  --allow-private    Permit local/private targets for development (announced)
  -h, --help         Show help
  -v, --version      Show version
`;
}

/**
 * @param {string[]} args
 * @returns {{ flags: Flags, positionals: string[] }}
 */
export function parseFlags(args) {
  /** @type {Flags} */
  const flags = {};
  /** @type {string[]} */
  const positionals = [];
  const booleanFlags = new Set(["--strict", "--json", "--watch", "--update", "--sign", "--allow-private", "--file"]);
  const valueFlags = new Set([
    "--org",
    "--token",
    "--period",
    "--agent",
    "--since",
    "--access-log",
    "--format",
    "--nonce-field",
    "--against",
    "--bundle",
    "--log-base",
    "--window",
    "--deadline",
    "--issuer",
    "--client-id",
    "--scope",
    "--key",
    "--key-id",
    "--method"
  ]);

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith("-")) {
      positionals.push(token);
      continue;
    }
    if (booleanFlags.has(token)) {
      flags[token.slice(2)] = true;
      continue;
    }
    if (token === "-h" || token === "--help") {
      flags.help = true;
      continue;
    }
    if (token === "-v" || token === "--version") {
      flags.version = true;
      continue;
    }
    if (valueFlags.has(token)) {
      const next = args[index + 1];
      if (!next || next.startsWith("-")) throw new Error(`Missing value for ${token}`);
      flags[token.slice(2)] = next;
      index += 1;
      continue;
    }
    throw new Error(`Unknown flag: ${token}`);
  }
  return { flags, positionals };
}

/**
 * @param {Flags} flags
 * @returns {void}
 */
function announcePrivateAccess(flags) {
  if (flags["allow-private"] === true) {
    console.error("WARNING: --allow-private permits private, link-local, and metadata targets for local development.");
  }
}

/**
 * @param {Flags} flags
 * @param {string} key
 * @returns {string | undefined}
 */
function stringFlag(flags, key) {
  const value = flags[key];
  return typeof value === "string" ? value : undefined;
}

/**
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
export async function runCli(argv) {
  let parsed;
  try {
    parsed = parseFlags(argv);
  } catch (error) {
    console.error(`${errorMessage(error)} Next action: run bna --help for supported options.`);
    return 2;
  }
  const { flags, positionals } = parsed;
  if (flags.version === true) {
    console.log(`bna ${CLI_VERSION}`);
    return 0;
  }
  const command = positionals[0];
  if (!command || flags.help === true) {
    if (flags.json === true) {
      console.error("Help is human-readable; remove --json and run bna --help.");
      return 2;
    }
    console.log(helpText().trim());
    return 0;
  }
  const args = positionals.slice(1);
  const json = flags.json === true;

  if (json && !["validate", "probe", "verify", "audit-score", "reconcile"].includes(command)) {
    console.error(`--json is not available for ${command}. Use validate, probe, verify, audit-score, or reconcile.`);
    return 2;
  }

  switch (command) {
    case "login":
      return login({
        org: stringFlag(flags, "org"),
        token: stringFlag(flags, "token"),
        issuer: stringFlag(flags, "issuer"),
        clientId: stringFlag(flags, "client-id"),
        scope: stringFlag(flags, "scope")
      });
    case "whoami":
      return whoami();
    case "validate":
      if (!args[0]) {
        console.error("validate requires <url|file>. Next action: supply an agent-card URL or JSON file.");
        return 2;
      }
      announcePrivateAccess(flags);
      return validateCommand(args[0], {
        strict: flags.strict === true,
        json,
        allowPrivateHosts: flags["allow-private"] === true
      });
    case "probe":
      if (!args[0]) {
        console.error("probe requires <url>. Next action: supply an http or https endpoint URL.");
        return 3;
      }
      announcePrivateAccess(flags);
      return probeCommand(args[0], {
        watch: flags.watch === true,
        json,
        sign: flags.sign === true,
        key: stringFlag(flags, "key"),
        keyId: stringFlag(flags, "key-id"),
        method: stringFlag(flags, "method"),
        window: Number(stringFlag(flags, "window") ?? 1),
        deadline: Number(stringFlag(flags, "deadline") ?? 30_000),
        allowPrivateHosts: flags["allow-private"] === true
      });
    case "verify":
      if (!args[0]) {
        console.error("verify requires <summary.json>. Next action: supply a signed probe summary file.");
        return 2;
      }
      return verifyCommand(args[0], { key: stringFlag(flags, "key"), json });
    case "reconcile":
      return reconcileCommand({
        agent: stringFlag(flags, "agent"),
        since: stringFlag(flags, "since"),
        accessLog: stringFlag(flags, "access-log"),
        format: stringFlag(flags, "format"),
        nonceField: stringFlag(flags, "nonce-field"),
        bundle: stringFlag(flags, "bundle"),
        logBase: stringFlag(flags, "log-base"),
        file: flags.file === true,
        json
      });

    case "audit-score":
      return auditScoreCommand(args[0], {
        period: stringFlag(flags, "period"),
        against: stringFlag(flags, "against"),
        bundle: stringFlag(flags, "bundle"),
        logBase: stringFlag(flags, "log-base"),
        json
      });

    case "diff":
      if (!args[0]) {
        console.error("diff requires <url|file>. Next action: supply an agent-card URL or JSON file.");
        return 2;
      }
      announcePrivateAccess(flags);
      return diffCommand(args[0], { update: flags.update === true, allowPrivateHosts: flags["allow-private"] === true });
    default:
      console.error(`Unknown command: ${command}. Next action: run bna --help for supported commands.`);
      return 2;
  }
}
