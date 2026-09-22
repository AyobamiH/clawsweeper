#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
smoke='app-token-fleet-smoke.yml'
smoke_path='.github/workflows/app-token-fleet-smoke.yml'
original_active_ids=()
original_active_paths=()
repo_actions_enabled=false
smoke_initial_state=''
log_file=''

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

cleanup() {
  set +e
  if [ "$repo_actions_enabled" = true ]; then
    retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null 2>&1 || true
    repo_actions_enabled=false
  fi
  for id in "${original_active_ids[@]}"; do
    retry_gh api --method PUT "repos/$repo/actions/workflows/$id/enable" >/dev/null 2>&1 || true
  done
  if [ -n "$smoke_initial_state" ] && [ "$smoke_initial_state" != 'active' ]; then
    retry_gh api --method PUT "repos/$repo/actions/workflows/$smoke/disable" >/dev/null 2>&1 || true
  fi
  [ -z "$log_file" ] || rm -f "$log_file"
}
trap cleanup EXIT

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

smoke_was_active=0
if [ "$smoke_initial_state" = 'active' ]; then
  smoke_was_active=1
fi
echo "Isolated fleet smoke workflow; disabled $(( ${#original_active_ids[@]} - smoke_was_active )) other active workflow(s)."

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true
retry_gh api --method PUT "repos/$repo/actions/workflows/$smoke/enable" >/dev/null

before_id="$(retry_gh run list --repo "$repo" --workflow "$smoke" --event workflow_dispatch --limit 1 \
  --json databaseId --jq '.[0].databaseId // 0')"

set +e
gh workflow run "$smoke" --repo "$repo" --ref main
dispatch_rc=$?
set -e

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
  if [ "$dispatch_rc" -ne 0 ]; then
    echo "FAIL: workflow dispatch failed and no new fleet smoke run was observed." >&2
  else
    echo "FAIL: fleet smoke workflow dispatch was not observed." >&2
  fi
  exit 1
fi

echo "Fleet smoke run: $run_id"
set +e
gh run watch "$run_id" --repo "$repo" --exit-status
watch_rc=$?
set -e

conclusion="$(retry_gh run view "$run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
run_url="$(retry_gh run view "$run_id" --repo "$repo" --json url --jq '.url')"

retry_gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null
repo_actions_enabled=false

log_file="$(mktemp)"
retry_gh run view "$run_id" --repo "$repo" --log >"$log_file" || true

if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ]; then
  grep -E 'PASS fleet target:|permissions requested|level of access|not found|FAIL:' "$log_file" || cat "$log_file"
  echo "FAIL: ClawSweeper App fleet token smoke did not pass: $run_url" >&2
  exit 1
fi

expected_targets="$(grep -F 'Target count:' "$log_file" | tail -1 | sed 's/.*Target count: //' | tr -d '[:space:]')"
if ! printf '%s' "$expected_targets" | grep -Eq '^[1-9][0-9]*printf 'SUCCESS: %s\n' "$run_url"
printf 'Actions enabled: %s\n' "$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
; then
  cat "$log_file"
  echo "FAIL: could not recover the active target count from the fleet smoke logs: $run_url" >&2
  exit 1
fi

pass_count="$(grep -F 'PASS fleet target:' "$log_file" | sed 's/.*PASS fleet target: //' | sort -u | wc -l | tr -d ' ')"
if [ "$pass_count" != "$expected_targets" ]; then
  grep -F 'PASS fleet target:' "$log_file" || true
  echo "FAIL: workflow succeeded but found $pass_count unique target PASS markers; expected $expected_targets: $run_url" >&2
  exit 1
fi

grep -F 'PASS fleet target:' "$log_file" | sed 's/.*PASS fleet target: //' | sort -u
printf 'PASS: all %s active targets minted the full operator-capable installation token and completed read verification; no target mutation was performed.\n' "$pass_count"
printf 'SUCCESS: %s\n' "$run_url"
printf 'Actions enabled: %s\n' "$(retry_gh api "repos/$repo/actions/permissions" --jq '.enabled')"
