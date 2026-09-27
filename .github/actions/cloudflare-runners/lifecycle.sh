#!/usr/bin/env bash
set -euo pipefail
case "${RUNNER_OPERATION:?}" in start|stop) ;; *) exit 2;; esac
: "${GH_TOKEN:?}" "${CLOUDFLARE_API_TOKEN:?}" "${CLOUDFLARE_ACCOUNT_ID:?}"
# Stable across jobs, distinct across retries. Cleanup does not depend on outputs
# from a partially failed start job.
nonce="$(printf '%s' "$GITHUB_REPOSITORY:$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT" | sha256sum | cut -c1-16)"
endpoint=https://ayobamih-clawsweeper-compute.woeinvests.workers.dev
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT
npm ci --prefix cloudflare-repair --no-audit --no-fund >/dev/null
probe_token="$(openssl rand -hex 32)"
printf '\n::add-mask::%s\n' "$probe_token"
printf '%s' "$probe_token" | (cd cloudflare-repair && npx wrangler secret put PROBE_TOKEN)
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
  curl --fail --silent --show-error --retry 6 --retry-all-errors --retry-delay 5 --retry-max-time 90 --max-time 180 --request "$verb" --header "Authorization: Bearer $probe_token" --header 'Content-Type: application/json' --data-binary @"$scratch_dir/request.json" --output "$scratch_dir/response.json" "$endpoint/runner"
  jq -e --arg key "$([ "$verb" = POST ] && echo started || echo stopped)" '.[$key] == true' "$scratch_dir/response.json" >/dev/null
  if [ "$RUNNER_OPERATION" = stop ]; then
    gh api "repos/$GITHUB_REPOSITORY/actions/runners" --jq ".runners[] | select(.name == \"$runner_name\") | .id" > "$scratch_dir/runner-ids"
    while read -r runner_id; do
      [ -z "$runner_id" ] || gh api --method DELETE "repos/$GITHUB_REPOSITORY/actions/runners/$runner_id"
    done < "$scratch_dir/runner-ids"
  fi
  echo "$RUNNER_OPERATION completed for $runner_name"
done
