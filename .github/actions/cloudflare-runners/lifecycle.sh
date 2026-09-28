#!/usr/bin/env bash
set -euo pipefail
case "${RUNNER_OPERATION:?}" in start|stop) ;; *) exit 2;; esac
: "${GH_TOKEN:?}"
# Stable across jobs and attempts. A cleanup-only rerun must target the runners
# created by the original attempt instead of deriving new, orphan-prone names.
nonce="$(printf '%s' "$GITHUB_REPOSITORY:$GITHUB_RUN_ID" | sha256sum | cut -c1-16)"
echo "attempt=$GITHUB_RUN_ATTEMPT" >> "$GITHUB_OUTPUT"
endpoint=https://ayobamih-clawsweeper-compute.woeinvests.workers.dev
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT
cleanup_failed=0
cloudflare_ready=1
probe_token=""
if [ "$RUNNER_OPERATION" = start ]; then
  : "${CLOUDFLARE_API_TOKEN:?}" "${CLOUDFLARE_ACCOUNT_ID:?}"
  npm ci --prefix cloudflare-repair --no-audit --no-fund >/dev/null
  probe_token="$(openssl rand -hex 32)"
  printf '\n::add-mask::%s\n' "$probe_token"
  printf '%s' "$probe_token" | (cd cloudflare-repair && npx wrangler secret put PROBE_TOKEN)
else
  if [ -z "${CLOUDFLARE_API_TOKEN:-}" ] || [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    echo "Cloudflare cleanup credentials are unavailable; continuing GitHub runner deregistration" >&2
    cloudflare_ready=0
    cleanup_failed=1
  elif ! npm ci --prefix cloudflare-repair --no-audit --no-fund >/dev/null; then
    echo "Cloudflare cleanup dependencies could not be installed; continuing GitHub runner deregistration" >&2
    cloudflare_ready=0
    cleanup_failed=1
  else
    probe_token="$(openssl rand -hex 32)"
    printf '\n::add-mask::%s\n' "$probe_token"
    if ! printf '%s' "$probe_token" | (cd cloudflare-repair && npx wrangler secret put PROBE_TOKEN); then
      echo "Cloudflare cleanup credential rotation failed; continuing GitHub runner deregistration" >&2
      cloudflare_ready=0
      cleanup_failed=1
    fi
  fi
fi
for lane in plan execute; do
  runner_name="csw-$nonce-$lane"
  echo "$lane=$runner_name" >> "$GITHUB_OUTPUT"
  if [ "$RUNNER_OPERATION" = start ]; then
    registration="$(gh api --method POST "repos/$GITHUB_REPOSITORY/actions/runners/generate-jitconfig" -f name="$runner_name" -F runner_group_id=1 -f 'labels[]=self-hosted' -f 'labels[]=Linux' -f 'labels[]=X64' -f "labels[]=$runner_name" --jq .encoded_jit_config)"
    printf '\n::add-mask::%s\n' "$registration"
    jq -n --arg name "$runner_name" --arg jit "$registration" '{name:$name,jit:$jit}' > "$scratch_dir/request.json"
    verb=POST
  else
    jq -n --arg name "$runner_name" '{name:$name}' > "$scratch_dir/request.json"
    verb=DELETE
  fi
  response_ok=0
  if [ "$cloudflare_ready" = 1 ] && curl --fail --silent --show-error --retry 6 --retry-all-errors --retry-delay 5 --retry-max-time 180 --max-time 45 --request "$verb" --header "Authorization: Bearer $probe_token" --header 'Content-Type: application/json' --data-binary @"$scratch_dir/request.json" --output "$scratch_dir/response.json" "$endpoint/runner"; then
    if jq -e --arg key "$([ "$verb" = POST ] && echo started || echo stopped)" '.[$key] == true' "$scratch_dir/response.json" >/dev/null; then response_ok=1; fi
  fi
  if [ "$response_ok" != 1 ]; then
    if [ "$RUNNER_OPERATION" = start ]; then exit 1; fi
    cleanup_failed=1
    echo "Container cleanup failed for $runner_name; continuing remaining cleanup" >&2
  fi
  if [ "$RUNNER_OPERATION" = start ]; then
    runner_status=offline
    for attempt in $(seq 1 18); do
      runner_status="$(gh api "repos/$GITHUB_REPOSITORY/actions/runners" --jq ".runners[] | select(.name == \"$runner_name\") | .status")"
      if [ "$runner_status" = online ]; then break; fi
      sleep 5
    done
    if [ "$runner_status" != online ]; then
      echo "Runner did not become online within the bounded startup window: $runner_name" >&2
      exit 1
    fi
  fi
  if [ "$RUNNER_OPERATION" = stop ]; then
    gh api "repos/$GITHUB_REPOSITORY/actions/runners" --jq ".runners[] | select(.name == \"$runner_name\") | .id" > "$scratch_dir/runner-ids" || cleanup_failed=1
    while read -r runner_id; do
      [ -z "$runner_id" ] || gh api --method DELETE "repos/$GITHUB_REPOSITORY/actions/runners/$runner_id" || cleanup_failed=1
    done < "$scratch_dir/runner-ids"
  fi
  if [ "$response_ok" = 1 ]; then echo "$RUNNER_OPERATION completed for $runner_name"; fi
done
exit "$cleanup_failed"
