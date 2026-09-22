#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
target="${1:-AyobamiH/openclaw-operator}"
smoke='app-token-smoke.yml'
smoke_path='.github/workflows/app-token-smoke.yml'
disabled_ids=()
repo_actions_enabled=false
log_file=''

cleanup() {
  set +e
  if [ "$repo_actions_enabled" = true ]; then
    gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null 2>&1
    repo_actions_enabled=false
  fi
  for id in "${disabled_ids[@]}"; do
    gh api --method PUT "repos/$repo/actions/workflows/$id/enable" >/dev/null 2>&1
  done
  [ -z "$log_file" ] || rm -f "$log_file"
}
trap cleanup EXIT

initial_enabled="$(gh api "repos/$repo/actions/permissions" --jq '.enabled')"
if [ "$initial_enabled" != 'false' ]; then
  echo "ABORT: repository Actions is not currently disabled ($initial_enabled)." >&2
  exit 1
fi

for status in queued in_progress pending waiting requested; do
  count="$(gh api "repos/$repo/actions/runs?status=$status&per_page=1" --jq '.total_count')"
  if [ "$count" != '0' ]; then
    echo "ABORT: found $count $status Actions run(s)." >&2
    exit 1
  fi
done

# Isolate the smoke workflow while repository Actions is still globally disabled.
while IFS=$'\t' read -r id path; do
  [ -n "${id:-}" ] || continue
  if [ "$path" = "$smoke_path" ]; then
    continue
  fi
  gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
  disabled_ids+=("$id")
done < <(
  gh api --paginate "repos/$repo/actions/workflows?per_page=100" \
    --jq '.workflows[] | select(.state == "active") | [.id, .path] | @tsv'
)

echo "Isolated smoke workflow; disabled ${#disabled_ids[@]} other active workflow(s)."

# Open the Actions window only after all other active workflows are disabled.
gh api --method PUT "repos/$repo/actions/permissions" -F enabled=true >/dev/null
repo_actions_enabled=true
gh api --method PUT "repos/$repo/actions/workflows/$smoke/enable" >/dev/null

before_id="$(gh run list --repo "$repo" --workflow "$smoke" --event workflow_dispatch --limit 1 \
  --json databaseId --jq '.[0].databaseId // 0')"

gh workflow run "$smoke" --repo "$repo" --ref main -f target_repo="$target"

run_id=''
for _ in $(seq 1 30); do
  latest_id="$(gh run list --repo "$repo" --workflow "$smoke" --event workflow_dispatch --limit 1 \
    --json databaseId --jq '.[0].databaseId // 0')"
  if [ "$latest_id" != '0' ] && [ "$latest_id" != "$before_id" ]; then
    run_id="$latest_id"
    break
  fi
  sleep 2
done

if [ -z "$run_id" ]; then
  echo "FAIL: smoke workflow dispatch was not observed." >&2
  exit 1
fi

echo "Smoke run: $run_id"
set +e
gh run watch "$run_id" --repo "$repo" --exit-status
watch_rc=$?
set -e

conclusion="$(gh run view "$run_id" --repo "$repo" --json conclusion --jq '.conclusion // ""')"
run_url="$(gh run view "$run_id" --repo "$repo" --json url --jq '.url')"

# Close the Actions window immediately after this single run.
gh api --method PUT "repos/$repo/actions/permissions" -F enabled=false >/dev/null
repo_actions_enabled=false

log_file="$(mktemp)"
gh run view "$run_id" --repo "$repo" --log >"$log_file" 2>&1 || true

if [ "$watch_rc" -ne 0 ] || [ "$conclusion" != 'success' ]; then
  cat "$log_file"
  echo "FAIL: ClawSweeper App token smoke did not pass: $run_url" >&2
  exit 1
fi

if ! grep -Fq 'PASS: ClawSweeper App minted the apply-capable installation token' "$log_file"; then
  cat "$log_file"
  echo "FAIL: run succeeded but the token verification PASS marker was not found: $run_url" >&2
  exit 1
fi

grep -F 'PASS: ClawSweeper App minted the apply-capable installation token' "$log_file" | tail -1
printf 'SUCCESS: %s\n' "$run_url"
printf 'Actions enabled: %s\n' "$(gh api "repos/$repo/actions/permissions" --jq '.enabled')"
