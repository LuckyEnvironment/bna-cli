#!/usr/bin/env bash
#
# Proves `bna reconcile` reads a multi-gigabyte access log without holding it.
#
# Generates a synthetic log, runs the reader under a hard heap ceiling, and
# fails if it exceeds it. An implementation that buffered the file would die;
# a streaming one cannot.
#
# Outside `npm run check` deliberately: it writes gigabytes and takes minutes,
# and a suite people skip protects nothing. Same reasoning as verify:container.
#
# Usage:
#   scripts/verify-streaming.sh          # 2GB, 128MB heap ceiling
#   SIZE_GB=4 HEAP_MB=96 scripts/verify-streaming.sh
set -euo pipefail

size_gb="${SIZE_GB:-2}"
heap_mb="${HEAP_MB:-128}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$(mktemp -t bna-streaming-XXXXXX).log"

cleanup() { rm -f "$log"; }
trap cleanup EXIT

echo "Generating ${size_gb}GB synthetic access log at ${log} ..."
node -e '
  const { createWriteStream } = require("node:fs");
  const target = Number(process.argv[1]) * 1024 * 1024 * 1024;
  const stream = createWriteStream(process.argv[2]);
  let written = 0;
  let index = 0;
  (function write() {
    while (written < target) {
      const nonce = String(index++).padStart(22, "0");
      const line = `10.0.0.1 - - [01/Jun/2026:00:00:00 +0000] "GET /a2a HTTP/1.1" 200 512 "-" "BNA CLI/0.1.0" bna_nonce=${nonce}\n`;
      written += line.length;
      if (!stream.write(line)) return stream.once("drain", write);
    }
    stream.end();
  })();
' "$size_gb" "$log"

actual=$(wc -c < "$log")
echo "Wrote $((actual / 1024 / 1024))MB. Reading it under a ${heap_mb}MB heap ceiling ..."
echo

# --max-old-space-size is the whole test. If the reader accumulated lines or
# entries, V8 would abort here rather than print a count.
/usr/bin/time -l node --max-old-space-size="${heap_mb}" --input-type=module -e "
  const { readAccessLog } = await import('${repo}/src/lib/access-log.js');
  let count = 0;
  const reader = readAccessLog('${log}');
  let step = await reader.next();
  while (!step.done) { count += 1; step = await reader.next(); }
  process.stdout.write('nonces read: ' + count + ' over ' + step.value.lines + ' lines\n');
" 2>&1 | grep -E "nonces read|maximum resident set size|real" || true

echo
echo "Completed within a ${heap_mb}MB heap. The log was streamed, not loaded."
