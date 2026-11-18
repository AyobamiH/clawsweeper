#!/usr/bin/env bash
# Keep transient/unknown failures retryable, but do not wait and repeat a
# frozen install which pnpm has explicitly rejected as a lockfile contract error.
set -euo pipefail
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
for attempt in 1 2 3; do
  if pnpm install --frozen-lockfile 2>&1 | tee "$log"; then
    exit 0
  else
    statuses=("${PIPESTATUS[@]}")
    status="${statuses[0]}"
    # A broken output sink must not be reported as a successful installation.
    if [[ "$status" -eq 0 ]]; then exit "${statuses[1]}"; fi
  fi
  if [[ "$status" -eq 130 || "$status" -eq 143 ]]; then exit "$status"; fi
  if grep -Eq 'ERR_PNPM_(OUTDATED_LOCKFILE|NO_LOCKFILE|LOCKFILE_CONFIG_MISMATCH)([^A-Z_]|$)' "$log"; then
    exit "$status"
  fi
  if [[ "$attempt" -eq 3 ]]; then exit "$status"; fi
  sleep "$((attempt * 10))"
done
