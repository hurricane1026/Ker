#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

linux, manifest_path, imported, importer = map(Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())['files']
for name, digest in manifest.items():
    assert hashlib.sha256((linux / name).read_bytes()).hexdigest() == digest, name
provenance = json.loads((imported / 'provenance.json').read_text())
generated = (imported / 'linux_neighbor_event_send.c').read_text() + (imported / 'ker/linux_neighbor_event_send.h').read_text()
assert len(provenance) == 1
record = provenance[0]
raw = (linux / record['file']).read_bytes()
block = raw[record['start_offset']:record['start_offset'] + record['length']]
assert hashlib.sha256(block).hexdigest() == record['sha256']
assert block.decode() in generated
assert block.decode().startswith('int __neigh_event_send(')
with tempfile.TemporaryDirectory(prefix='ker-neighbor-event-send-import-') as temp:
    root = Path(temp)
    outputs = (root / 'first', root / 'second')
    for output in outputs:
        subprocess.run([sys.executable, str(importer), '--linux', str(linux),
                        '--manifest', str(manifest_path), '--out', str(output)], check=True)
    for name in ('linux_neighbor_event_send.c', 'provenance.json', 'ker/linux_neighbor_event_send.h'):
        assert (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes(), name
    changed = root / 'linux'
    for name in manifest:
        target = changed / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if name == 'net/core/neighbour.c':
            target.write_bytes((linux / name).read_bytes() + b'\n/* altered */\n')
        else:
            target.symlink_to(linux / name)
    result = subprocess.run([sys.executable, str(importer), '--linux', str(changed),
                             '--manifest', str(manifest_path), '--out', str(root / 'rejected')],
                            capture_output=True)
    assert result.returncode != 0
print('neighbor-event-send importer provenance passed')
