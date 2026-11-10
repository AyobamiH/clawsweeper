#!/usr/bin/env bash
# Deliberately does NOT admit any execution: absent controls default to disabled.
set -euo pipefail
umask 077
repository="$(cd "$(dirname "$0")/../.." && pwd -P)"
root="$HOME/.local/share/local-ci/clawsweeper-selfhosted"
units="$HOME/.config/systemd/user"
mkdir -p "$root" "$units"
chmod 0700 "$root"
for name in self_hosted_executor.py self_hosted_policy.py verify_codeql_release.py e2e_evidence_vault.py reconcile_selfhosted_receipt.py; do
  install -m 0600 "$repository/scripts/ci/$name" "$root/$name.new"
  mv -- "$root/$name.new" "$root/$name"
done
if [ ! -e "$root/controls.json" ]; then
  python3 - "$root/controls.json" <<'PY'
from pathlib import Path
import os,sys,json
p=Path(sys.argv[1]); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as out:
 json.dump({'repo':'AyobamiH/clawsweeper','enabled':False,'enabled_roles':[],
            'allowed_branches':[],'operations_accepted':False,'max_jobs_per_cycle':1},out,indent=2)
 out.write('\n');out.flush();os.fsync(out.fileno())
PY
fi
if [ -L "$root/controls.json" ] || [ "$(stat -c '%a' "$root/controls.json")" != 600 ]; then
  echo 'Refusing unsafe or externally controlled capability file' >&2; exit 1
fi
for name in service timer; do
  unit="clawsweeper-selfhosted.$name"
  target="$units/$unit"
  if [ -e "$target" ] && ! cmp -s "$target" "$repository/scripts/ci/$unit"; then
    echo "Existing $unit differs; preserve active unit for manual reconciliation" >&2
    exit 1
  fi
  install -m 0644 "$repository/scripts/ci/$unit" "$target"
done
systemctl --user daemon-reload
systemctl --user enable --now clawsweeper-selfhosted.timer
printf 'Runner installed disabled: %s\n' "$root"
systemctl --user is-enabled clawsweeper-selfhosted.timer
/usr/bin/python3 "$root/self_hosted_executor.py" inspect
