#!/usr/bin/env bash
# Offline image build from trusted source image and immutable CodeQL bundle.
set -euo pipefail
umask 077
version=2.27.4
expected_bundle_sha256='393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d'
base_id='sha256:c1f057b23404d71586056d3333e333099c3301e84cc2583c592907a8b56597d3'
base_tag='clawsweeper-selfhost-runner:node24-gh245'
target_tag='clawsweeper-codeql-runner:node24-codeql-2.27.4'
root="$HOME/.local/share/local-ci/clawsweeper-selfhosted/cache/codeql-$version"
bundle="$root/codeql-linux64.zip"
test -f "$bundle" && test ! -L "$bundle"
[[ "$(stat -c '%s' "$bundle")" == '418431999' ]]
printf '%s  %s\n' "$expected_bundle_sha256" "$bundle" | sha256sum --check -
[[ "$(docker image inspect "$base_tag" --format '{{.Id}}')" == "$base_id" ]]
context="$(mktemp -d)"
trap 'rm -rf -- "$context"' EXIT
install -m 0600 "$bundle" "$context/codeql-linux64.zip"
cat > "$context/Dockerfile" <<'DOCKER'
FROM clawsweeper-selfhost-runner:node24-gh245
USER root
COPY --chmod=0644 codeql-linux64.zip /opt/clawsweeper-codeql/codeql-linux64.zip
RUN chmod 0755 /opt/clawsweeper-codeql && echo '393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d  /opt/clawsweeper-codeql/codeql-linux64.zip' | sha256sum --check -
USER runner
DOCKER
docker build --network none --pull=false -t "$target_tag" "$context"
image="$(docker image inspect "$target_tag" --format '{{.Id}}')"
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]]
docker run --rm --network none --cpus=0.5 --memory=256m --cap-drop=ALL \
  --security-opt=no-new-privileges --entrypoint bash "$image" -lc \
  "test \"\$(id -un)\" = runner && echo '$expected_bundle_sha256  /opt/clawsweeper-codeql/codeql-linux64.zip' | sha256sum -c -"
python3 - "$root/image-provenance.json" "$image" "$base_id" "$expected_bundle_sha256" <<'PY'
import datetime, json, os, pathlib, sys
path=pathlib.Path(sys.argv[1]); tmp=path.with_name(path.name+'.new')
record={'schema':'clawsweeper.codeql-image.v1','built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'image_sha256':sys.argv[2], 'base_image_sha256':sys.argv[3], 'codeql_bundle_sha256':sys.argv[4],
        'codeql_version':'2.27.4', 'image_tag':'clawsweeper-codeql-runner:node24-codeql-2.27.4',
        'network_during_build':'none','runner_user':'runner'}
with tmp.open('x') as stream:
 os.fchmod(stream.fileno(),0o600);json.dump(record,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
os.replace(tmp,path)
print('CODEQL_IMAGE_SHA256='+sys.argv[2])
PY
