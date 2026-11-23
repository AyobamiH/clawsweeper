#!/usr/bin/env bash
# Offline derived CodeQL archive image; base, upstream ZIP and derived TAR are pinned.
set -euo pipefail
umask 077
version=2.27.4
upstream_sha256='393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d'
archive_sha256='ec7d95d9a25734ad9553aed70f04bb3394a79b86b9eee44c84fa7f92970a5176'
base_id='sha256:c1f057b23404d71586056d3333e333099c3301e84cc2583c592907a8b56597d3'
base_tag='clawsweeper-selfhost-runner:node24-gh245'
target_tag='clawsweeper-codeql-runner:node24-codeql-2.27.4'
root="$HOME/.local/share/local-ci/clawsweeper-selfhosted/cache/codeql-$version"
zipfile="$root/codeql-linux64.zip"
archive="$root/codeql-bundle-$version-linux64.tar.gz"
test -f "$zipfile" && test ! -L "$zipfile"
test -f "$archive" && test ! -L "$archive"
[[ "$(stat -c '%s' "$zipfile")" == '418431999' ]]
printf '%s  %s\n' "$upstream_sha256" "$zipfile" | sha256sum --check -
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check -
[[ "$(docker image inspect "$base_tag" --format '{{.Id}}')" == "$base_id" ]]
context="$(mktemp -d)"
trap 'rm -rf -- "$context"' EXIT
install -m 0600 "$archive" "$context/codeql-bundle.tar.gz"
cat > "$context/Dockerfile" <<'DOCKER'
FROM clawsweeper-selfhost-runner:node24-gh245
USER root
COPY --chmod=0644 codeql-bundle.tar.gz /opt/clawsweeper-codeql/codeql-bundle.tar.gz
RUN chmod 0755 /opt/clawsweeper-codeql && echo 'ec7d95d9a25734ad9553aed70f04bb3394a79b86b9eee44c84fa7f92970a5176  /opt/clawsweeper-codeql/codeql-bundle.tar.gz' | sha256sum --check -
USER runner
DOCKER
docker build --network none --pull=false -t "$target_tag" "$context"
image="$(docker image inspect "$target_tag" --format '{{.Id}}')"
[[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]]
docker run --rm --network none --cpus=0.5 --memory=256m --cap-drop=ALL \
  --security-opt=no-new-privileges --entrypoint bash "$image" -lc \
  "test \"\$(id -un)\" = runner && echo '$archive_sha256  /opt/clawsweeper-codeql/codeql-bundle.tar.gz' | sha256sum -c -"
python3 - "$root/image-provenance.json" "$image" "$base_id" "$upstream_sha256" "$archive_sha256" <<'PY'
import datetime,json,os,pathlib,sys
path=pathlib.Path(sys.argv[1]); tmp=path.with_name(path.name+'.new')
record={'schema':'clawsweeper.codeql-image.v2','built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'image_sha256':sys.argv[2], 'base_image_sha256':sys.argv[3],
 'codeql_bundle_sha256':sys.argv[4], 'codeql_archive_sha256':sys.argv[5],
 'codeql_version':'2.27.4', 'image_tag':'clawsweeper-codeql-runner:node24-codeql-2.27.4',
 'network_during_build':'none','runner_user':'runner'}
with tmp.open('x') as out:
 os.fchmod(out.fileno(),0o600);json.dump(record,out,sort_keys=True,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
os.replace(tmp,path)
print('CODEQL_IMAGE_SHA256='+sys.argv[2])
PY
