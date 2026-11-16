#!/bin/sh
# Minimal local entrypoint. No Node code runs before triage selection.
# Production launchers must pin this exact shell entry and the Node bootstrap
# to the same reviewed, signed source revision.
set -eu

if [ "$#" -lt 1 ]; then
  printf '%s\n' 'ci-triage-launch: mode required' >&2
  exit 64
fi
mode=$1
shift

case "$mode" in
  notifier)
    case "${CLAWSWEEPER_CI_TRIAGE_ENABLED:-0}" in
      0)
        # Existing generic notification path remains unchanged when disabled.
        exec node dist/repair/notify-github-activity.js "$@"
        ;;
      1)
        mode=verified-notifier
        ;;
      *)
        printf '%s\n' 'ci-triage-launch: unrecognised triage mode' >&2
        exit 64
        ;;
    esac
    ;;
  observer|verified-notifier)
    ;;
  *)
    printf '%s\n' 'ci-triage-launch: unrecognised entrypoint' >&2
    exit 64
    ;;
esac

# Node processes NODE_OPTIONS before importing its first script. A Node
# bootstrap cannot prevent a --require/--import preload retroactively.
# The trusted shell launch therefore clears it BEFORE starting Node.
unset NODE_OPTIONS
if [ "$mode" = "observer" ]; then
  exec node scripts/analysis/ci-triage-preimport.mjs observer "$@"
fi
exec node scripts/analysis/ci-triage-preimport.mjs notifier "$@"
