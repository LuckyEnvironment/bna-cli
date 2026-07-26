#!/usr/bin/env bash
# Runs INSIDE the container. Invoked by scripts/verify-container.sh.
#
# The container is started with --network none. That single condition proves
# three separate claims at once:
#
#   * the tarball is self-contained -- the install cannot reach any registry,
#     so it can only succeed if every runtime dependency is bundled
#   * there is no telemetry -- nothing external is reachable at all
#   * probe still works against loopback
#
# Exit status is 0 only if every check passes.
set -u

pass=0
fail=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf '  PASS  %-46s exit %s\n' "$1" "$3"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-46s expected %s, got %s\n' "$1" "$2" "$3"
    fail=$((fail + 1))
  fi
}

note() { # name ok
  if [ "$2" = "0" ]; then
    printf '  PASS  %s\n' "$1"
    pass=$((pass + 1))
  else
    printf '  FAIL  %s\n' "$1"
    fail=$((fail + 1))
  fi
}

echo "=============================================================="
echo " node $(node --version)  ·  $(uname -s)/$(uname -m)"
if getent hosts registry.npmjs.org >/dev/null 2>&1; then
  echo " network: REACHABLE — run with --network none or this proves little"
else
  echo " network: none (--network none confirmed)"
fi
echo "=============================================================="

echo
echo "--- install from tarball with no network ---"
mkdir -p /verify/app
cd /verify/app || exit 1
printf '{"name":"bna-cli-smoke","version":"1.0.0","private":true}' > package.json
if ! npm install --offline --no-audit --no-fund --no-package-lock /verify/package.tgz 2>&1 | tail -2; then
  echo "install: FAILED — the tarball is not self-contained"
  exit 1
fi
echo "install: OK"

BNA="node /verify/app/node_modules/@bna/cli/bin/bna.js"

echo
echo "--- first run: bna --help ---"
$BNA --help

echo
echo "--- first run: bna validate (complete card) ---"
$BNA validate /verify/fixtures/complete-card.json
check "exit 0 — valid card" 0 $?

echo
echo "--- first run: bna validate (incomplete card) ---"
$BNA validate /verify/fixtures/incomplete-card.json
check "exit 1 — card with warnings" 1 $?

echo
echo "--- documented exit codes ---"
$BNA validate /verify/fixtures/does-not-exist.json >/dev/null 2>&1
check "exit 2 — schema or command error" 2 $?

$BNA probe https://unreachable.invalid/a2a >/dev/null 2>&1
check "exit 3 — network or probe failure" 3 $?

$BNA probe https://example.invalid/a2a --sign >/dev/null 2>&1
check "exit 4 — signing context missing" 4 $?

echo
echo "--- probe against loopback ---"
node -e '
const http = require("http");
http.createServer((request, response) => {
  response.writeHead(200, { "content-type": "application/json" });
  response.end("{}");
}).listen(8099, "127.0.0.1");
' &
server=$!
sleep 1

$BNA probe http://127.0.0.1:8099/a2a --json --allow-private > /verify/probe.json 2>/verify/probe.err
check "exit 0 — successful local probe" 0 $?
kill $server 2>/dev/null

node -e '
const summary = JSON.parse(require("fs").readFileSync("/verify/probe.json", "utf8")).result.summary;
for (const key of ["specVersion", "vantagePoint", "attempted", "success", "failure", "notAttempted", "uptimePct", "method", "userAgent"]) {
  console.log("    " + key.padEnd(14) + " " + JSON.stringify(summary[key]));
}
'

echo
echo "--- --json emits exactly one JSON document on stdout ---"
node -e 'JSON.parse(require("fs").readFileSync("/verify/probe.json", "utf8"))' 2>/dev/null
note "stdout parses as a single JSON document" $?
if [ -s /verify/probe.err ]; then
  echo "        diagnostics correctly on stderr: $(head -c 58 /verify/probe.err)…"
fi

echo
echo "--- probe output conforms to the published schema ---"
node -e '
const fs = require("fs");
// Resolve from the installed CLI rather than assuming a path: bundled
// dependencies nest under the consumer package instead of being hoisted.
const entry = require.resolve("@bna/probe-protocol", { paths: ["/verify/app/node_modules/@bna/cli"] });
console.log("        bundled dependency at " + entry.replace(/\/src\/index\.js$/, ""));
const { validateSummary } = require(entry.replace(/index\.js$/, "summary.js"));
const summary = JSON.parse(fs.readFileSync("/verify/probe.json", "utf8")).result.summary;
const errors = validateSummary(summary);
if (errors.length > 0) {
  errors.forEach((error) => console.log("        - " + error));
  process.exit(1);
}
'
note "conformant to probe-summary-1.0.0" $?

echo
echo "=============================================================="
printf ' node %s: %s passed, %s failed\n' "$(node --version)" "$pass" "$fail"
echo "=============================================================="
[ "$fail" -eq 0 ]
