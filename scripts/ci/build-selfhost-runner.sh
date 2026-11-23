#!/usr/bin/env bash
# Offline extension of the previously accepted one-job runner image.
set -euo pipefail
umask 077
base='sha256:758e03ab2a553cf20f71c3495515d6966f125ca7bc1d94197597c4b25067e9f9'
gh_sha256='2fd925d68889746976958342fb749bf102bc7dc8bcba3abfa533a80ad7791673'
source_binary='/usr/bin/gh'
expected_image='clawsweeper-selfhost-runner:node24-gh245'
test -f "$source_binary" && test ! -L "$source_binary"
printf '%s  %s\n' "$gh_sha256" "$source_binary" | sha256sum -c -
test "$(docker image inspect poststeward-ops-runner:node24 --format '{{.Id}}')" = "$base"
context="$(mktemp -d)"
trap 'rm -rf -- "$context"' EXIT
cp -- "$source_binary" "$context/gh"
cat > "$context/Dockerfile" <<'DOCKER'
FROM poststeward-ops-runner:node24
USER root
COPY --chmod=0755 gh /usr/local/bin/gh
RUN echo '2fd925d68889746976958342fb749bf102bc7dc8bcba3abfa533a80ad7791673  /usr/local/bin/gh' | sha256sum -c -
USER runner
DOCKER
docker build --network none --pull=false -t "$expected_image" "$context"
image="$(docker image inspect "$expected_image" --format '{{.Id}}')"
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]]
docker run --rm --network none --cpus 0.5 --memory 256m --cap-drop ALL --security-opt no-new-privileges "$image" bash -lc 'test "$(id -un)" = runner && command -v gh && gh --version && node --version && git --version'
printf 'CLAWSWEEPER_SELFHOST_RUNNER_IMAGE=%s\n' "$image"
