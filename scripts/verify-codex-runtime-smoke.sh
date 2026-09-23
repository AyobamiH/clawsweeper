#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
smoke='codex-runtime-smoke.yml'
smoke_path='.github/workflows/codex-runtime-smoke.yml'
ghost_run_id='35794270775'
original_active_ids=()
original_active_paths=()
repo_actions_enabled=false
smoke_initial_state=''
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
  if [ -n "$smoke_initial_state" ] && [ "$smoke_initial_state" != 'active' ]; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$smoke/disable" >/dev/null 2>&1 || true
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

initial_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
if [ "$initial_enabled" != 'false' ]; then
  echo "ABORT: repository Actions is not currently disabled ($initial_enabled)." >&2
  exit 1
fi

for status in queued in_progress pending waiting requested; do
  count="$(retry_gh api "repos/$repo/actions/runs?status=$status&per_page=100" \
    --jq "[.workflow_runs[] | select(.id != $ghost_run_id)] | length")"
  if [ "$count" != '0' ]; then
    echo "ABORT: found $count non-ghost $status Actions run(s)." >&2
    exit 1
  fi
done

smoke_initial_state="$(retry_gh api "repos/$repo/actions/workflows/$smoke" --jq '.state')"
workflow_rows="$(retry_gh api --paginate "repos/$repo/actions/workflows?per_page=100" \
  --jq '.workflows[] | select(.state == "active") | [.id, .path] | @tsv')"
while IFS=$'\t' read -r id path; do
  [ -n "${id:-}" ] || continue
  original_active_ids+=("$id")
  original_active_paths+=("$path")
done <<< "$workflow_rows"

for index in "${!original_active_ids[@]}"; do
  id="${original_active_ids[$index]}"
  path="${original_active_paths[$index]}"
  if [ "$path" = "$smoke_path" ]; then
    continue
  fi
  retry_gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
done

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true
retry_gh api --method PUT "repos/$repo/actions/workflows/$smoke/enable" >/dev/null

before_id="$(retry_gh run list --repo "$repo" --workflow "$smoke" --event workflow_dispatch --limit 1 \
  --json databaseId --jq '.[0].databaseId // 0')"

gh workflow run "$smoke" --repo "$repo" --ref main

run_id=''
for _ in $(seq 1 30); do
  latest_id="$(retry_gh run list --repo "$repo" --workflow "$smoke" --event workflow_dispatch --limit 1 \
    --json databaseId --jq '.[0].databaseId // 0')"
  if [ "$latest_id" != '0' ] && [ "$latest_id" != "$before_id" ]; then
    run_id="$latest_id"
    break
  fi
  sleep 2
done

if [ -z "$run_id" ]; then
  echo 'FAIL: Codex runtime smoke dispatch was not observed.' >&2
  exit 1
fi

echo "Codex runtime smoke run: $run_id"
set +e
gh run watch "$run_id" --repo "$repo" --exit-status
watch_rc=$?
set -e
conclusion="$(retry_gh run view "$run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
url="$(retry_gh run view "$run_id" --repo "$repo" --json url --jq '.url')"

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null
repo_actions_enabled=false

if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ]; then
  echo "FAIL: ClawSweeper Codex runtime smoke did not pass: $url" >&2
  exit 1
fi

restore_environment
trap - EXIT

final_enabled="$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
if [ "$final_enabled" != 'false' ]; then
  echo 'FAIL: repository Actions was not returned to disabled state.' >&2
  exit 1
fi

echo "PASS: ClawSweeper Codex runtime authenticated and executed successfully: $url"
echo 'Actions enabled: false'
echo "Known stale GitHub ghost run ignored for readiness: $ghost_run_id"
