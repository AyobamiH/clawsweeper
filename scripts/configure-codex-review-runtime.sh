#!/usr/bin/env bash
set -Eeuo pipefail

repo='AyobamiH/clawsweeper'
model="${CLAWSWEEPER_CODEX_MODEL:-gpt-5.6-sol}"

if ! command -v gh >/dev/null 2>&1; then
  echo 'ABORT: GitHub CLI (gh) is required.' >&2
  exit 1
fi

api_key="${OPENAI_API_KEY:-}"
prompted=false
if [ -z "$api_key" ]; then
  if [ ! -t 0 ]; then
    echo 'ABORT: OPENAI_API_KEY is not set and no interactive terminal is available.' >&2
    exit 1
  fi
  read -r -s -p 'OpenAI API key (input hidden): ' api_key
  echo
  prompted=true
fi

if [ -z "$api_key" ]; then
  echo 'ABORT: OpenAI API key cannot be empty.' >&2
  exit 1
fi

if [ -z "$model" ]; then
  echo 'ABORT: model identifier cannot be empty.' >&2
  exit 1
fi

printf '%s' "$api_key" | gh secret set OPENAI_API_KEY --repo "$repo"
printf '%s' "$model" | gh secret set CLAWSWEEPER_MODEL --repo "$repo"

# Drop only the local copy used by this helper. Do not print either secret.
api_key=''
unset api_key

names="$(gh secret list --repo "$repo" --json name --jq '.[].name')"
for required in OPENAI_API_KEY CLAWSWEEPER_MODEL; do
  if ! grep -Fxq "$required" <<<"$names"; then
    echo "FAIL: GitHub did not report required secret name $required after update." >&2
    exit 1
  fi
done

echo "PASS: configured ClawSweeper Codex review runtime secrets."
echo "Model: $model"
echo "Repository: $repo"
if [ "$prompted" = true ]; then
  echo 'The API key was read with terminal echo disabled and was not printed.'
fi
