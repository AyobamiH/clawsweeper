#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
workflow='sweep.yml'
ghost_run_id='35794270775'
target_repo='AyobamiH/proof-and-state'
item_numbers='17'

original_active_ids=()
repo_actions_enabled=false
restored=false
fresh_run_id=''

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

restore_environment() {
  if [ "$restored" = true ]; then
    return 0
  fi
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
  if [ "$repo_actions_enabled" = false ]; then
    restored=true
  fi
}
trap restore_environment EXIT

if ! command -v gh >/dev/null 2>&1; then
  echo 'ABORT: GitHub CLI (gh) is required.' >&2
  exit 1
fi

echo 'Waiting for the original observation runner to finish cleanup...'
clean=false
for _ in $(seq 1 90); do
  enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
  running="$(retry_gh api "repos/$repo/actions/runs?status=in_progress&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
  pending="$(retry_gh api "repos/$repo/actions/runs?status=pending&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
  waiting="$(retry_gh api "repos/$repo/actions/runs?status=waiting&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
  requested="$(retry_gh api "repos/$repo/actions/runs?status=requested&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
  queued_non_ghost="$(retry_gh api "repos/$repo/actions/runs?status=queued&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
  if [ "$enabled" = 'false' ] &&
     [ "$running" = '0' ] &&
     [ "$pending" = '0' ] &&
     [ "$waiting" = '0' ] &&
     [ "$requested" = '0' ] &&
     [ "$queued_non_ghost" = '0' ]; then
    clean=true
    break
  fi
  sleep 2
done

if [ "$clean" != true ]; then
  echo 'ABORT: repository did not return to disabled/idle containment within 3 minutes.' >&2
  exit 1
fi

sleep 3

workflow_rows="$(retry_gh api --paginate "repos/$repo/actions/workflows?per_page=100" --jq '.workflows[] | select(.state == "active") | [.id, .path] | @tsv')"
while IFS=$'\t' read -r id path; do
  [ -n "${id:-}" ] || continue
  original_active_ids+=("$id")
done <<< "$workflow_rows"

if [ "${#original_active_ids[@]}" -eq 0 ]; then
  echo 'ABORT: no active workflows visible after cleanup; refusing to guess prior state.' >&2
  exit 1
fi

for id in "${original_active_ids[@]}"; do
  retry_gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
done

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true

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
  echo 'Waiting for a cron-safe manual-dispatch window...'
  sleep 5
done

retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/enable" >/dev/null

before_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"

echo 'Dispatching fresh Proof & State #17 observation only...'
gh workflow run "$workflow"   --repo "$repo"   --ref main   -f target_repo="$target_repo"   -f item_numbers="$item_numbers"   -f batch_size='1'   -f shard_count='1'   -f hot_intake='false'   -f apply_existing='false'   -f apply_after_review='false'   -f audit_dashboard='false'

for _ in $(seq 1 30); do
  latest_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
  if [ "$latest_id" != '0' ] && [ "$latest_id" != "$before_id" ] && [ "$latest_id" != "$ghost_run_id" ]; then
    fresh_run_id="$latest_id"
    break
  fi
  sleep 2
done

if [ -z "$fresh_run_id" ]; then
  retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
  echo 'FAIL: fresh Proof & State dispatch was not observed.' >&2
  exit 1
fi

echo "Fresh observation run: $fresh_run_id"

started=false
for _ in $(seq 1 30); do
  status="$(retry_gh run view "$fresh_run_id" --repo "$repo" --json status --jq '.status // ""')"
  jobs="$(retry_gh api "repos/$repo/actions/runs/$fresh_run_id/jobs?per_page=1" --jq '.total_count')"
  if [ "$jobs" != '0' ]; then
    started=true
    break
  fi
  if [ "$status" = 'completed' ]; then
    break
  fi
  sleep 2
done

retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null

if [ "$started" != true ]; then
  echo "Fresh run $fresh_run_id never created a job; cancelling the fresh dispatch before restoring containment." >&2
  retry_gh run cancel "$fresh_run_id" --repo "$repo" >/dev/null 2>&1 || true
  exit 1
fi

ghost_jobs="$(retry_gh api "repos/$repo/actions/runs/$ghost_run_id/jobs?per_page=1" --jq '.total_count' 2>/dev/null || printf '0')"
if [ "$ghost_jobs" != '0' ]; then
  echo "Containment: ghost run $ghost_run_id unexpectedly created jobs; requesting cancellation."
  retry_gh run cancel "$ghost_run_id" --repo "$repo" >/dev/null 2>&1 || true
fi

echo "Run admitted: $fresh_run_id (status=$status jobs=$jobs). sweep.yml is disabled again."

set +e
gh run watch "$fresh_run_id" --repo "$repo" --exit-status
watch_rc=$?
set -e

conclusion="$(retry_gh run view "$fresh_run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
url="$(retry_gh run view "$fresh_run_id" --repo "$repo" --json url --jq '.url')"

restore_environment
trap - EXIT

final_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
queued_non_ghost="$(retry_gh api "repos/$repo/actions/runs?status=queued&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"
running_non_ghost="$(retry_gh api "repos/$repo/actions/runs?status=in_progress&per_page=100" --jq '[.workflow_runs[] | select(.id != '"$ghost_run_id"')] | length')"

if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ]; then
  echo "FAIL: fresh Proof & State #17 observation ended $conclusion: $url" >&2
  exit 1
fi

if [ "$final_enabled" != 'false' ] || [ "$queued_non_ghost" != '0' ] || [ "$running_non_ghost" != '0' ]; then
  echo "FAIL: observation succeeded but containment is not clean: Actions=$final_enabled non-ghost-queued=$queued_non_ghost non-ghost-running=$running_non_ghost" >&2
  exit 1
fi

echo "PASS: Proof & State #17 observation completed successfully: $url"
echo 'Actions enabled: false'
echo 'Non-ghost queued runs: 0'
echo 'Non-ghost in-progress runs: 0'
echo "Known stale GitHub ghost run retained for audit: $ghost_run_id"
