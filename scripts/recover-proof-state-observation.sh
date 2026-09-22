#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
workflow='sweep.yml'
stale_run_id="${1:-35794270775}"
target_repo='AyobamiH/proof-and-state'
item_numbers='17'

original_active_ids=()
new_run_id=''
repo_actions_enabled=false
restored=false

retry_gh() {
  local attempt=1 max_attempts="${CLAWSWEEPER_GH_RETRY_ATTEMPTS:-5}" delay=2 output rc
  while true; do
    set +e
    output="$(gh "$@" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then printf '%s' "$output"; return 0; fi
    if [ "$attempt" -ge "$max_attempts" ]; then printf '%s\n' "$output" >&2; return "$rc"; fi
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

restore_environment() {
  if [ "$restored" = true ]; then return 0; fi
  set +e
  if [ "$repo_actions_enabled" = true ]; then
    if retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null 2>&1; then
      repo_actions_enabled=false
    fi
  fi
  local id
  for id in "${original_active_ids[@]}"; do
    retry_gh api --method PUT "repos/$repo/actions/workflows/$id/enable" >/dev/null 2>&1 || true
  done
  if [ "$repo_actions_enabled" = false ]; then restored=true; fi
}
trap restore_environment EXIT

if ! command -v gh >/dev/null 2>&1; then
  echo 'ABORT: GitHub CLI (gh) is required.' >&2
  exit 1
fi
if ! [[ "$stale_run_id" =~ ^[0-9]+$ ]]; then
  echo "usage: $0 <stale-run-id>" >&2
  exit 2
fi

stale_status="$(retry_gh run view "$stale_run_id" --repo "$repo" --json status --jq '.status // ""')"
stale_event="$(retry_gh run view "$stale_run_id" --repo "$repo" --json event --jq '.event // ""')"
stale_jobs="$(retry_gh api "repos/$repo/actions/runs/$stale_run_id/jobs?per_page=1" --jq '.total_count')"
if [ "$stale_event" != 'workflow_dispatch' ]; then
  echo "ABORT: $stale_run_id is not a workflow_dispatch run ($stale_event)." >&2
  exit 1
fi
if [ "$stale_status" = 'queued' ] && [ "$stale_jobs" = '0' ]; then
  echo "Cancelling stale zero-job observation run $stale_run_id..."
  retry_gh run cancel "$stale_run_id" --repo "$repo" >/dev/null
else
  echo "Stale run no longer matches queued/zero-job state: status=$stale_status jobs=$stale_jobs"
fi

# The original observation runner is still watching the stale run. Let it see
# cancellation, finish its remaining already-completed watches, disable Actions,
# and restore the workflow set before this recovery takes ownership.
echo 'Waiting for the original observation runner to restore containment...'
ready=false
for _ in $(seq 1 90); do
  enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
  queued="$(retry_gh api "repos/$repo/actions/runs?status=queued&per_page=1" --jq '.total_count')"
  running="$(retry_gh api "repos/$repo/actions/runs?status=in_progress&per_page=1" --jq '.total_count')"
  pending="$(retry_gh api "repos/$repo/actions/runs?status=pending&per_page=1" --jq '.total_count')"
  waiting="$(retry_gh api "repos/$repo/actions/runs?status=waiting&per_page=1" --jq '.total_count')"
  requested="$(retry_gh api "repos/$repo/actions/runs?status=requested&per_page=1" --jq '.total_count')"
  if [ "$enabled" = 'false' ] && [ "$queued" = '0' ] && [ "$running" = '0' ] && [ "$pending" = '0' ] && [ "$waiting" = '0' ] && [ "$requested" = '0' ]; then
    ready=true
    break
  fi
  sleep 2
done
if [ "$ready" != true ]; then
  echo 'ABORT: original observation runner did not return the repository to idle/disabled containment within 3 minutes.' >&2
  exit 1
fi

# Give the parent runner a moment to finish restoring workflow activation after
# disabling repository Actions.
sleep 3

workflow_rows="$(retry_gh api --paginate "repos/$repo/actions/workflows?per_page=100" --jq '.workflows[] | select(.state == "active") | [.id, .path] | @tsv')"
while IFS=$'\t' read -r id path; do
  [ -n "${id:-}" ] || continue
  original_active_ids+=("$id")
done <<< "$workflow_rows"

if [ "${#original_active_ids[@]}" -eq 0 ]; then
  echo 'ABORT: no active workflows were visible after parent restoration; refusing to guess the prior workflow set.' >&2
  exit 1
fi

for id in "${original_active_ids[@]}"; do
  retry_gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
done

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true

# Use a minute window away from sweep.yml cron ticks. This keeps scheduled fanout
# from entering while the manual workflow is briefly active.
safe_minute() {
  local minute
  minute="$(date -u +%M)"
  minute="$((10#$minute))"
  case "$minute" in
    0|1|2|9|10|11|15|16|17|18|19|25|26|27|28|29|30|31|32|33|34|45|46|47|48|49|55|56|57|58|59) return 0 ;;
  esac
  return 1
}
while ! safe_minute; do
  echo 'Waiting for a cron-safe manual-dispatch window...'
  sleep 5
done

retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/enable" >/dev/null

before_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"

echo 'Dispatching fresh Proof & State #17 observation...'
gh workflow run "$workflow" \
  --repo "$repo" \
  --ref main \
  -f target_repo="$target_repo" \
  -f item_numbers="$item_numbers" \
  -f batch_size='1' \
  -f shard_count='1' \
  -f hot_intake='false' \
  -f apply_existing='false' \
  -f apply_after_review='false' \
  -f audit_dashboard='false'

for _ in $(seq 1 30); do
  latest_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
  if [ "$latest_id" != '0' ] && [ "$latest_id" != "$before_id" ]; then
    new_run_id="$latest_id"
    break
  fi
  sleep 2
done
if [ -z "$new_run_id" ]; then
  retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
  echo 'FAIL: fresh Proof & State dispatch was not observed.' >&2
  exit 1
fi

echo "Fresh observation run: $new_run_id"

started=false
for _ in $(seq 1 30); do
  status="$(retry_gh run view "$new_run_id" --repo "$repo" --json status --jq '.status // ""')"
  jobs="$(retry_gh api "repos/$repo/actions/runs/$new_run_id/jobs?per_page=1" --jq '.total_count')"
  if [ "$status" != 'queued' ] || [ "$jobs" != '0' ]; then
    started=true
    break
  fi
  sleep 2
done

retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null

if [ "$started" != true ]; then
  echo "Fresh run $new_run_id stayed queued with zero jobs; cancelling it before restoring containment." >&2
  retry_gh run cancel "$new_run_id" --repo "$repo" >/dev/null 2>&1 || true
  exit 1
fi

echo "Run admitted: $new_run_id (status=$status jobs=$jobs). sweep.yml is disabled again."

set +e
gh run watch "$new_run_id" --repo "$repo" --exit-status
watch_rc=$?
set -e
conclusion="$(retry_gh run view "$new_run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
url="$(retry_gh run view "$new_run_id" --repo "$repo" --json url --jq '.url')"

restore_environment
trap - EXIT

final_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
queued="$(retry_gh api "repos/$repo/actions/runs?status=queued&per_page=1" --jq '.total_count')"
running="$(retry_gh api "repos/$repo/actions/runs?status=in_progress&per_page=1" --jq '.total_count')"

if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ]; then
  echo "FAIL: fresh Proof & State #17 observation ended $conclusion: $url" >&2
  exit 1
fi
if [ "$final_enabled" != 'false' ] || [ "$queued" != '0' ] || [ "$running" != '0' ]; then
  echo "FAIL: observation succeeded but containment is not clean: Actions=$final_enabled queued=$queued running=$running" >&2
  exit 1
fi

echo "PASS: Proof & State #17 observation completed successfully: $url"
echo 'Actions enabled: false'
echo 'Queued runs: 0'
echo 'In-progress runs: 0'
