#!/usr/bin/env python3
"""Pin locally verified CodeQL image without admitting any GitHub job."""
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path.home() / '.local/share/local-ci/clawsweeper-selfhosted'
CONTROLS = ROOT / 'controls.json'
PROVENANCE = ROOT / 'cache/codeql-2.27.4/image-provenance.json'
DIGEST = '393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d'
BASE = 'sha256:c1f057b23404d71586056d3333e333099c3301e84cc2583c592907a8b56597d3'
TAG = 'clawsweeper-codeql-runner:node24-codeql-2.27.4'


def trusted_json(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise RuntimeError('not an owner-only file')
    return json.loads(path.read_text())


def main():
    os.umask(0o077)
    controls = trusted_json(CONTROLS)
    if controls.get('enabled') is not False:
        raise RuntimeError('disable admissions before changing the pinned image')
    data = trusted_json(PROVENANCE)
    assert data.get('schema') == 'clawsweeper.codeql-image.v1'
    assert data.get('codeql_bundle_sha256') == DIGEST
    assert data.get('base_image_sha256') == BASE
    assert data.get('image_tag') == TAG
    pin = data['image_sha256']
    if not isinstance(pin, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', pin):
        raise RuntimeError('invalid pinned image digest')
    current = subprocess.run(['docker', 'image', 'inspect', TAG, '--format', '{{.Id}}'],
                             check=True, text=True, capture_output=True, timeout=15).stdout.strip()
    if current != pin:
        raise RuntimeError('local image bytes do not match verified provenance')
    controls['security_image_sha256'] = pin
    tmp = CONTROLS.with_name('controls.json.pin-'+str(os.getpid()))
    fd = os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(controls, f, indent=2, sort_keys=True)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, CONTROLS)
    parent = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)
    print('Image pinned with admissions disabled: '+pin)

if __name__ == '__main__':
    main()
