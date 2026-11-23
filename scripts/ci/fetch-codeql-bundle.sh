#!/usr/bin/env bash
# Reproducible, resumable *local image input*. Never download in the untrusted job.
set -euo pipefail
umask 077
version=2.27.4
expected='393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d'
bytes=418431999
root="$HOME/.local/share/local-ci/clawsweeper-selfhosted/cache/codeql-$version"
mkdir -p "$root"
chmod 0700 "$root"
archive="$root/codeql-linux64.zip"
if [[ ! -f "$archive" ]]; then
  partial="$archive.partial"
  url="https://github.com/github/codeql-cli-binaries/releases/download/v${version}/codeql-linux64.zip"
  curl --fail --location --silent --show-error --continue-at - \
    --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 25 \
    --max-time 2400 --output "$partial" "$url"
  [[ "$(stat -c '%s' "$partial")" == "$bytes" ]]
  printf '%s  %s\n' "$expected" "$partial" | sha256sum --check -
  mv -- "$partial" "$archive"
fi
[[ "$(stat -c '%s' "$archive")" == "$bytes" ]]
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check -
chmod 0600 "$archive"
printf 'Verified CodeQL bundle v%s: %s\n' "$version" "$archive"
