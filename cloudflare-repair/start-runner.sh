#!/bin/bash
set -euo pipefail
exec >>/tmp/runner.log 2>&1
export RUNNER_ALLOW_RUNASROOT=1
cd /opt/actions-runner
trap 'rm -f /tmp/runner-jit' EXIT
jit="$(cat /tmp/runner-jit)"
rm -f /tmp/runner-jit
timeout --signal=TERM --kill-after=30s 10800 ./run.sh --jitconfig "$jit"
