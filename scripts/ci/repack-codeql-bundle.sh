#!/usr/bin/env bash
# Repack a pinned, verified upstream ZIP into the tar.gz format CodeQL Action v4 accepts.
set -euo pipefail
umask 077
root="$HOME/.local/share/local-ci/clawsweeper-selfhosted/cache/codeql-2.27.4"
source="$root/codeql-linux64.zip"
archive="$root/codeql-bundle-2.27.4-linux64.tar.gz"
upstream_sha256='393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d'
expected_archive_sha256='ec7d95d9a25734ad9553aed70f04bb3394a79b86b9eee44c84fa7f92970a5176'
[[ "$(stat -c '%s' "$source")" == 418431999 ]]
printf '%s  %s\n' "$upstream_sha256" "$source" | sha256sum --check -
if [[ ! -f "$archive" ]]; then
  staging="$(mktemp -d "$root/verified-repack.XXXXXX")"
  trap 'rm -rf -- "$staging"' EXIT
  python3 - "$source" <<'PY'
import pathlib,sys,zipfile
p=pathlib.Path(sys.argv[1]);count=0
with zipfile.ZipFile(p) as archive:
 for entry in archive.infolist():
  name=pathlib.PurePosixPath(entry.filename)
  if (name.is_absolute() or '..' in name.parts or name.parts[0]!='codeql' or '\\' in entry.filename):
   raise ValueError('Unsafe CodeQL archive path')
  count += 1
assert count>1000, 'Unexpected CodeQL release content'
print('Verified '+str(count)+' archive paths are scoped to codeql/')
PY
  unzip -q "$source" -d "$staging"
  test -f "$staging/codeql/codeql" || { echo 'CodeQL CLI missing from bundle' >&2; exit 1; }
  # Fixed ownership/order/time, and gzip without source filename or timestamp.
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$staging" codeql | pigz -n -1 -p 4 > "$archive.partial"
  tar -tzf "$archive.partial" >/dev/null
  mv -- "$archive.partial" "$archive"
fi
chmod 0600 "$archive"
printf '%s  %s\n' "$expected_archive_sha256" "$archive" | sha256sum --check -
