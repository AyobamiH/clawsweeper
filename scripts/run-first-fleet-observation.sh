#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
workflow='sweep.yml'
workflow_path='.github/workflows/sweep.yml'

labels=(
  'DoneState #87 — Sandbox RPC reconciliation'
  'OpsTruth plugin #11 — least-privilege GitHub read lane'
  'Proof & State #17 — portfolio evidence packs'
  'Wagging Web #68 + PR #72 — design acceptance and dependency remediation'
)
targets=(
  'AyobamiH/donestate'
  'AyobamiH/opstruth-chatgpt-plugin'
  'AyobamiH/proof-and-state'
  'AyobamiH/wagging-web-wins'
)
items=(
  '87'
  '11'
  '17'
  '68,72'
)
shards=(
  '1'
  '1'
  '1'
  '2'
)

original_active_ids=()
original_active_paths=()
run_ids=()
repo_actions_enabled=false
workflow_initial_state=''
restored=false

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
    echo "GitHub CLI call failed (attempt $attempt/$max_attempts); retrying in ${delay}s: gh $*" >&2
    printf '%s\n' "$output" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

contains_id() {
  local needle="$1"
  shift
  local value
  for value in "$@"; do
    if [ "$value" = "$needle" ]; then
      return 0
    fi
  done
  return 1
}

safe_sweep_dispatch_minute() {
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

wait_for_safe_sweep_dispatch_window() {
  while ! safe_sweep_dispatch_minute; do
    echo "Waiting for a cron-safe sweep dispatch window..."
    sleep 5
  done
}

wait_for_run_to_start() {
  local run_id="$1"
  local status=''
  for _ in $(seq 1 30); do
    status="$(retry_gh run view "$run_id" --repo "$repo" --json status --jq '.status // ""')"
    if [ "$status" != 'queued' ] && [ -n "$status" ]; then
      printf '%s' "$status"
      return 0
    fi
    sleep 2
  done
  printf '%s' "$status"
  return 1
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

  # Restore workflow activation only after repository Actions is disabled.
  local id
  for id in "${original_active_ids[@]}"; do
    retry_gh api --method PUT "repos/$repo/actions/workflows/$id/enable" >/dev/null 2>&1 || true
  done

  if [ -n "$workflow_initial_state" ] && [ "$workflow_initial_state" != 'active' ]; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null 2>&1 || true
  fi

  if [ "$repo_actions_enabled" = false ]; then
    restored=true
  fi
}
trap restore_environment EXIT

if ! command -v gh >/dev/null 2>&1; then
  echo 'ABORT: GitHub CLI (gh) is required.' >&2
  exit 1
fi

secret_names="$(retry_gh secret list --repo "$repo" --json name --jq '.[].name')"
for required_secret in OPENAI_API_KEY CLAWSWEEPER_MODEL; do
  if ! grep -Fxq "$required_secret" <<<"$secret_names"; then
    echo "ABORT: required Codex review secret $required_secret is not configured." >&2
    echo "Run scripts/configure-codex-review-runtime.sh before starting observations." >&2
    exit 1
  fi
done

initial_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
if [ "$initial_enabled" != 'false' ]; then
  echo "ABORT: repository Actions is not currently disabled ($initial_enabled)." >&2
  exit 1
fi

for status in queued in_progress pending waiting requested; do
  count="$(retry_gh api "repos/$repo/actions/runs?status=$status&per_page=1" --jq '.total_count')"
  if [ "$count" != '0' ]; then
    echo "ABORT: found $count $status Actions run(s)." >&2
    exit 1
  fi
done

workflow_initial_state="$(retry_gh api "repos/$repo/actions/workflows/$workflow" --jq '.state')"

workflow_rows="$(retry_gh api --paginate "repos/$repo/actions/workflows?per_page=100" \
  --jq '.workflows[] | select(.state == "active") | [.id, .path] | @tsv')"
while IFS=$'\t' read -r id path; do
  [ -n "${id:-}" ] || continue
  original_active_ids+=("$id")
  original_active_paths+=("$path")
done <<< "$workflow_rows"

baseline_ids=()
while IFS= read -r id; do
  [ -n "$id" ] || continue
  baseline_ids+=("$id")
done < <(retry_gh run list --repo "$repo" --workflow "$workflow" --limit 100 \
  --json databaseId --jq '.[].databaseId')

# Keep every workflow disabled except for the seconds in which sweep.yml
# receives one of the explicitly selected manual review dispatches.
for id in "${original_active_ids[@]}"; do
  retry_gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
done

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true

echo 'Observation mode: repository Actions enabled with all workflows disabled.'
echo 'Each exact review temporarily enables sweep.yml only for its dispatch window.'
echo 'Review publication may update normal ClawSweeper review comments/evidence.'
echo 'No apply-after-review, close, repair, comment-router, cluster-repair, or issue-build workflow is enabled.'
echo

for index in "${!targets[@]}"; do
  label="${labels[$index]}"
  target="${targets[$index]}"
  item_set="${items[$index]}"
  shard_count="${shards[$index]}"

  echo "Dispatching: $label"

  # Keep the sweep workflow enabled only inside a minute window that is at
  # least ~60 seconds away from any configured sweep cron tick.
  wait_for_safe_sweep_dispatch_window
  retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/enable" >/dev/null

  before_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 \
    --json databaseId --jq '.[0].databaseId // 0')"

  set +e
  gh workflow run "$workflow" \
    --repo "$repo" \
    --ref main \
    -f target_repo="$target" \
    -f item_numbers="$item_set" \
    -f batch_size='1' \
    -f shard_count="$shard_count" \
    -f hot_intake='false' \
    -f apply_existing='false' \
    -f apply_after_review='false' \
    -f audit_dashboard='false'
  dispatch_rc=$?
  set -e

  run_id=''
  for _ in $(seq 1 30); do
    latest_id="$(retry_gh run list --repo "$repo" --workflow "$workflow" --event workflow_dispatch --limit 1 \
      --json databaseId --jq '.[0].databaseId // 0')"
    if [ "$latest_id" != '0' ] && [ "$latest_id" != "$before_id" ] && ! contains_id "$latest_id" "${run_ids[@]}"; then
      run_id="$latest_id"
      break
    fi
    sleep 2
  done

  if [ -z "$run_id" ]; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
    if [ "$dispatch_rc" -ne 0 ]; then
      echo "FAIL: dispatch failed for $label and no new run was observed." >&2
    else
      echo "FAIL: dispatch for $label was not observed within 60 seconds." >&2
    fi
    exit 1
  fi

  run_ids+=("$run_id")
  echo "  accepted run: $run_id"

  # A workflow_dispatch receipt is not proof that GitHub has admitted a job.
  # Keep sweep.yml enabled until this exact run leaves queued, then close the
  # workflow window immediately. Abort rather than holding the workflow open
  # across a cron boundary.
  if ! start_status="$(wait_for_run_to_start "$run_id")"; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
    echo "FAIL: $run_id stayed queued for more than 60 seconds; cancelling the zero-job dispatch before restoring containment." >&2
    retry_gh run cancel "$run_id" --repo "$repo" >/dev/null 2>&1 || true
    exit 1
  fi
  retry_gh api --method PUT "repos/$repo/actions/workflows/$workflow/disable" >/dev/null
  echo "  run admitted: $run_id ($start_status)"
done

# sweep.yml is now disabled again. Cancel any run created during the short
# enable windows that was not one of our exact workflow_dispatch runs.
unexpected=0
while IFS=$'\t' read -r id event status title url; do
  [ -n "${id:-}" ] || continue
  if contains_id "$id" "${baseline_ids[@]}" || contains_id "$id" "${run_ids[@]}"; then
    continue
  fi
  unexpected=$((unexpected + 1))
  echo "Containment: cancelling unexpected $event run $id ($status): $title"
  case "$status" in
    queued|in_progress|pending|waiting|requested)
      retry_gh run cancel "$id" --repo "$repo" >/dev/null 2>&1 || true
      ;;
  esac
done < <(retry_gh run list --repo "$repo" --workflow "$workflow" --limit 100 \
  --json databaseId,event,status,displayTitle,url \
  --jq '.[] | [.databaseId, .event, .status, .displayTitle, .url] | @tsv')

if [ "$unexpected" -gt 0 ]; then
  echo "Containment notice: $unexpected unexpected sweep run(s) were detected and cancellation was requested."
fi

echo
echo "All ${#run_ids[@]} observation reviews are dispatched. Waiting for completion..."
echo

failures=0
for index in "${!run_ids[@]}"; do
  run_id="${run_ids[$index]}"
  label="${labels[$index]}"

  set +e
  gh run watch "$run_id" --repo "$repo" --exit-status
  watch_rc=$?
  set -e

  conclusion="$(retry_gh run view "$run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
  url="$(retry_gh run view "$run_id" --repo "$repo" --json url --jq '.url')"
  review_total="$(retry_gh run view "$run_id" --repo "$repo" --json jobs --jq '[.jobs[] | select(.name | startswith("Review shard "))] | length')"
  review_bad="$(retry_gh run view "$run_id" --repo "$repo" --json jobs --jq '[.jobs[] | select((.name | startswith("Review shard ")) and (.conclusion != "success"))] | length')"

  if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ] || [ "$review_total" = '0' ] || [ "$review_bad" != '0' ]; then
    failures=$((failures + 1))
    printf 'OBSERVATION FAIL: %s | workflow=%s | review_shards=%s | failed_review_shards=%s | %s\n' \
      "$label" "$conclusion" "$review_total" "$review_bad" "$url"
  else
    printf 'OBSERVATION PASS: %s | review_shards=%s/%s | %s\n' "$label" "$review_total" "$review_total" "$url"
  fi
done

restore_environment
trap - EXIT

final_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
queued="$(retry_gh api "repos/$repo/actions/runs?status=queued&per_page=1" --jq '.total_count')"
running="$(retry_gh api "repos/$repo/actions/runs?status=in_progress&per_page=1" --jq '.total_count')"

missing_restored_workflows=0
for id in "${original_active_ids[@]}"; do
  state="$(retry_gh api "repos/$repo/actions/workflows/$id" --jq '.state')"
  if [ "$state" != 'active' ]; then
    missing_restored_workflows=$((missing_restored_workflows + 1))
    echo "RESTORE FAIL: workflow $id is $state; expected active." >&2
  fi
done

echo
echo "Observation cycle complete."
echo "Actions enabled: $final_enabled"
echo "Queued runs: $queued"
echo "In-progress runs: $running"
echo "Workflow restore failures: $missing_restored_workflows"

if [ "$final_enabled" != 'false' ]; then
  echo 'FAIL: repository Actions was not returned to disabled state.' >&2
  exit 1
fi

if [ "$missing_restored_workflows" -gt 0 ]; then
  echo 'FAIL: one or more previously active workflows were not restored.' >&2
  exit 1
fi

if [ "$failures" -gt 0 ]; then
  echo "Observation completed with $failures failed review run(s); inspect those receipts before expanding scope." >&2
  exit 1
fi

echo "PASS: all selected real ClawSweeper reviews completed and repository Actions returned to disabled containment."
