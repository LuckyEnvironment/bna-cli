#!/usr/bin/env bash
#
# Clean-container verification for @bna/cli.
#
# Packs the working tree exactly as it would be published, then installs and
# exercises that tarball inside a disposable Linux container with the network
# switched off. This answers the question CI on a dev machine cannot: does the
# artifact a stranger downloads actually work on a machine that has never seen
# this project?
#
# Usage:
#   scripts/verify-container.sh              # Node 20, 22, 24
#   scripts/verify-container.sh 22           # one version
#   KEEP_IMAGES=1 scripts/verify-container.sh
#
# Requires a working Docker daemon. On macOS the Docker CLI alone is not
# enough -- it needs a Linux VM (colima, Docker Desktop, OrbStack).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
context="$(mktemp -d)"
versions=("$@")
if [ ${#versions[@]} -eq 0 ]; then
  versions=(20 22 24)
fi

cleanup() {
  rm -rf "$context"
  if [ "${KEEP_IMAGES:-0}" != "1" ]; then
    for version in "${versions[@]}"; do
      docker image rm -f "bna-cli-verify:${version}" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
  cat >&2 <<'MESSAGE'
Docker daemon is not reachable.

On macOS the Docker CLI is only a client; it needs a Linux VM to run
containers. Start one first, for example:

  brew install colima && colima start

Note that a colima VM does not survive a reboot -- run `colima start` again,
or `brew services start colima` to have it come up automatically.
MESSAGE
  exit 1
fi

echo "==> packing the working tree"
tarball="$(cd "$repo" && npm pack --silent --pack-destination "$context")"
mv "$context/$tarball" "$context/package.tgz"
cp "$repo/scripts/container/Dockerfile" "$repo/scripts/container/verify.sh" "$context/"
cp -R "$repo/scripts/container/fixtures" "$context/fixtures"
echo "    $tarball ($(wc -c < "$context/package.tgz" | tr -d ' ') bytes)"

failed=0
for version in "${versions[@]}"; do
  echo
  echo "==> node ${version}"
  docker build --quiet --build-arg "NODE_VERSION=${version}" -t "bna-cli-verify:${version}" "$context" >/dev/null

  # --network none is the whole point: it makes the install prove the tarball
  # is self-contained, and makes any telemetry attempt impossible.
  if docker run --rm --network none "bna-cli-verify:${version}"; then
    echo "    node ${version}: OK"
  else
    echo "    node ${version}: FAILED"
    failed=$((failed + 1))
  fi
done

echo
if [ "$failed" -eq 0 ]; then
  echo "All ${#versions[@]} container verifications passed."
else
  echo "${failed} of ${#versions[@]} container verifications FAILED."
fi
exit "$failed"
