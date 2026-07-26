#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { runCli } from "../src/cli.js";

runCli(process.argv.slice(2))
  .then((code) => {
    if (typeof code === "number") {
      process.exitCode = code;
    }
  })
  .catch((err) => {
    console.error(`Unexpected error: ${err?.message ?? String(err)}`);
    process.exitCode = 2;
  });
