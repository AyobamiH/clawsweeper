#!/usr/bin/env bash
# Signed-main-only estate cutover; never enables unapproved jobs.
set -euo pipefail
umask 077
mode="$1"
case "$mode" in --preflight|--install) ;; *) echo "usage: $0 --preflight|--install" >&2;exit 2;; esac
repo="$(cd "$(dirname "$0")/../.." && pwd -P)"
[[ "$(id -u)" != 0 ]] || { echo 'Refuse: user-session install only' >&2;exit 3; }
cd "$repo"
head="$(git rev-parse HEAD)"
if [[ ! "$head" =~ ^[0-9a-f]{40}$ ]] || [[ -n "$(git status --porcelain=v1)" ]]; then
 echo 'Refuse: source must be a clean signed release checkout' >&2;exit 3
fi
python3 -B - "$repo" <<'PY'
import hashlib,json,sys
from pathlib import Path
base=Path(sys.argv[1]);d=json.loads((base/'config/ci-workflow-estate.json').read_text())
assert d['schema']=='clawsweeper.workflow-estate.v2'
assert d['summary']['workflows']==41 and d['summary']['jobs']==88
assert d['summary']['github_hosted']==d['summary']['dynamic_hosted_fallback']==0
assert len(d['sources'])==41 and len(d['jobs'])==88
for item in d['sources']:
 file=base/item['path']
 assert file.is_file() and not file.is_symlink()
 assert hashlib.sha256(file.read_bytes()).hexdigest()==item['sha256']
print('manifest_byte_integrity_verified')
PY
if [[ "$mode" == --preflight ]]; then
 echo "source_preflight_passed_protected_release_not_verified $head"
 exit 0
fi
main="$(gh api repos/AyobamiH/clawsweeper/git/ref/heads/main --jq '.object.sha')"
[[ "$main" == "$head" ]] || { echo 'Refuse: source is not current protected main' >&2;exit 4; }
valid="$(gh api "repos/AyobamiH/clawsweeper/commits/$head" --jq '.commit.verification.verified')"
[[ "$valid" == true ]] || { echo 'Refuse: protected source signature unverified' >&2;exit 4; }
root="$HOME/.local/share/local-ci/clawsweeper-estate"
[[ ! -L "$root" ]] || { echo 'Refuse: estate root symlink' >&2;exit 4; }
controls="$root/controls.json"
[[ -f "$controls" && ! -L "$controls" && "$(stat -c '%a' "$controls")" == 600 ]] ||
 { echo 'Refuse: missing/unsafe owner-approved controls' >&2;exit 4; }
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$controls" <<'PY'
from pathlib import Path
import json,subprocess,sys
sys.path.insert(0,str(Path.cwd()/'scripts/ci'))
from estate_policy import AUTO_CODEQL_JOB,SAFE_AUTO_MODE,load_manifest,standing_codeql_profile_configured
ctl=json.loads(Path(sys.argv[1]).read_text())
entry=next(j for j in load_manifest()['jobs'] if j['workflow']+'#'+j['id']==AUTO_CODEQL_JOB)
approved=ctl.get('approved_jobs',{}).get(AUTO_CODEQL_JOB,{})
head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
if ctl.get('operating_mode')!=SAFE_AUTO_MODE or ctl.get('trusted_main_sha')!=head or not standing_codeql_profile_configured(ctl,approved,entry['source_sha256']):
 raise SystemExit('Refuse: standing CodeQL profile missing/changed')
print('codeql_class_scoped_controls_verified')
PY
mkdir -p "$root/releases"
chmod 0700 "$root" "$root/releases"
exec 9>"$root/installation.lock"
flock -n 9 || { echo 'Refuse: competing estate installation' >&2;exit 5; }
if systemctl --user is-active --quiet clawsweeper-estate.service;then
 echo 'Refuse: estate controller running' >&2;exit 5
fi
stage="$root/releases/.stage-$head-$$"
final="$root/releases/$head"
[[ ! -e "$stage" ]] || { echo 'Refuse: stale temporary release path' >&2;exit 5; }
if [[ -e "$root/active" || -L "$root/active" ]];then
 [[ -L "$root/active" && "$(readlink "$root/active")" == "releases/$head" ]] ||
  { echo 'Refuse: existing active release is different' >&2;exit 5; }
fi
# Existing exact-source installations are reusable after a crash. Never
# overwrite a different release or erase its receipts.
if [[ ! -e "$final" ]];then
 install -d -m 0700 "$stage/repo/scripts/ci" "$stage/repo/config"
 cleanup(){ [[ -d "$stage" ]] && rm -r -- "$stage" || true; }
 trap cleanup EXIT
 for file in estate_controller.py estate_policy.py estate_slots.py estate_fleet_lock.py estate_e2e_driver.py self_hosted_executor.py self_hosted_policy.py e2e_evidence_vault.py verify_codeql_release.py reconcile_selfhosted_receipt.py;do
  install -m 0600 "$repo/scripts/ci/$file" "$stage/repo/scripts/ci/$file"
 done
 install -m 0600 "$repo/config/ci-workflow-estate.json" "$stage/repo/config/ci-workflow-estate.json"
 release_to_verify="$stage"
else
 [[ -d "$final" && ! -L "$final" ]] ||
  { echo 'Refuse: existing release path unsafe' >&2;exit 6; }
 release_to_verify="$final"
fi
# Verify immutable Git blob bytes rather than trusting a mutable checkout
# copied between the initial status check and staging.
python3 -B - "$repo" "$release_to_verify" "$head" <<'PYVERIFY'
from pathlib import Path
import hashlib,subprocess,sys
repo=Path(sys.argv[1]);release=Path(sys.argv[2]);head=sys.argv[3]
files=['scripts/ci/'+name for name in (
'estate_controller.py','estate_policy.py','estate_slots.py',
'estate_fleet_lock.py','estate_e2e_driver.py','self_hosted_executor.py',
'self_hosted_policy.py','e2e_evidence_vault.py','verify_codeql_release.py',
'reconcile_selfhosted_receipt.py')]
files.append('config/ci-workflow-estate.json')
for file in files:
 target=release/'repo'/file
 assert target.is_file() and not target.is_symlink()
 authoritative=subprocess.check_output(
  ['git','-C',str(repo),'show',head+':'+file],timeout=30)
 assert hashlib.sha256(target.read_bytes()).digest()==hashlib.sha256(authoritative).digest()
print('immutable_git_source_bytes_match')
PYVERIFY
units="$HOME/.config/systemd/user"
mkdir -p "$units"
for unit in clawsweeper-estate.service clawsweeper-estate.timer;do
 dest="$units/$unit"
 [[ ! -e "$dest" ]] || cmp -s "$dest" "$repo/scripts/ci/$unit" ||
  { echo "Refuse: existing $unit differs" >&2;exit 6; }
done
if [[ "$release_to_verify" == "$stage" ]];then
 mv -- "$stage" "$final"
 trap - EXIT
fi
if [[ ! -L "$root/active" ]];then ln -s "releases/$head" "$root/active";fi
for unit in clawsweeper-estate.service clawsweeper-estate.timer;do
 install -m 0644 "$repo/scripts/ci/$unit" "$units/$unit"
done
systemctl --user daemon-reload
systemctl --user enable --now clawsweeper-estate.timer
echo "signed_source_estate_timer_installed $head"
