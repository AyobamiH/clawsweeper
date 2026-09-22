#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
workflow='sweep.yml'
run_id="${1:-}"
workflow_enabled_by_helper=false

retry_gh() {
  local attempt=1
  local max_attempts="${CLAWSWEEPER_GH_RETRY_ATTEMPTS:-5}"
  local delay=2
  local output rc
  while true; do
    set +e
    output="$(gh "$@" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      printf '%s' "$output"
      return 0
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      printf '%s\n' "$output" >&2
      return "$rc"
    fi
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

cleanup() {
  set +e
  if [ "$workflow_enabled_by_helper" = true ]; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null 2>&1 || true
    workflow_enabled_by_helper=false
  fi
}
trap cleanup EXIT

if ! [[ "$run_id" =~ ^[0-9]+$ ]]; then
  echo "usage: $0 <queued-observation-run-id>" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo 'ABORT: GitHub CLI (gh) is required.' >&2
  exit 1
fi

status="$(retry_gh run view "$run_id" --repo "$repo" --json status --jq '.status // ""')"
event="$(retry_gh run view "$run_id" --repo "$repo" --json event --jq '.event // ""')"
url="$(retry_gh run view "$run_id" --repo "$repo" --json url --jq '.url // ""')"

if [ "$event" != 'workflow_dispatch' ]; then
  echo "ABORT: run $run_id is not a manual workflow_dispatch run ($event)." >&2
  exit 1
fi

if [ "$status" != 'queued' ]; then
  echo "No recovery needed: run $run_id is already $status."
  echo "$url"
  exit 0
fi

actions_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
if [ "$actions_enabled" != 'true' ]; then
  echo "ABORT: repository Actions is not currently enabled by the parent observation runner." >&2
  echo "Leave the original observation terminal open and do not start an independent Actions window." >&2
  exit 1
fi

workflow_state="$(retry_gh api "repos/$repo/actions/workflows/$workflow" --jq '.state')"
if [ "$workflow_state" = 'active' ]; then
  echo "ABORT: $workflow is already active; refusing to change an unknown live state." >&2
  exit 1
fi

baseline_ids=()
while IFS= read -r id; do
  [ -n "$id" ] || continue
  baseline_ids+=("$id")
done < <(retry_gh run list --repo "$repo" --workflow "$workflow" --limit 100 --json databaseId --jq '.[].databaseId')

contains_id() {
  local needle="$1"
  shift
  local value
  for value in "$@"; do
    [ "$value" = "$needle" ] && return 0
  done
  return 1
}

safe_minute() {
  local minute
  minute="$(date -u +%M)"
  minute="$((10#$minute))"
  case "$minute" in
    0|1|2|9|10|11|15|16|17|18|19|25|26|27|28|29|30|31|32|33|34|45|46|47|48|49|55|56|57|58|59)
      return 0
      ;;
  esac
  return 1
}

while ! safe_minute; do
  echo "Waiting for a cron-safe minute before releasing queued run $run_id..."
  sleep 5
done

echo "Temporarily enabling $workflow to admit queued run $run_id."
retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/enable" >/dev/null
workflow_enabled_by_helper=true

started=false
for _ in $(seq 1 30); do
  status="$(retry_gh run view "$run_id" --repo "$repo" --json status --jq '.status // ""')"
  if [ "$status" != 'queued' ] && [ -n "$status" ]; then
    started=true
    break
  fi
  sleep 2
done

retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
workflow_enabled_by_helper=false

# Fail closed on any new sweep run that was not already present before the
# recovery window and is not the queued observation run we intended to release.
while IFS=$'\t' read -r id status event title; do
  [ -n "${id:-}" ] || continue
  if [ "$id" = "$run_id" ] || contains_id "$id" "${baseline_ids[@]}"; then
    continue
  fi
  case "$status" in
    queued|in_progress|pending|waiting|requested)
      echo "Containment: cancelling unexpected $event run $id ($status): $title"
      retry_gh run cancel "$id" --repo "$repo" >/dev/null 2>&1 || true
      ;;
  esac
done < <(retry_gh run list --repo "$repo" --workflow "$workflow" --limit 100 \
  --json databaseId,status,event,displayTitle \
  --jq '.[] | [.databaseId, .status, .event, .displayTitle] | @tsv')

if [ "$started" != true ]; then
  echo "FAIL: run $run_id remained queued after the bounded 60-second release window." >&2
  exit 1
fi

echo "PASS: run $run_id is now $status; $workflow is disabled again."
echo "$url"
