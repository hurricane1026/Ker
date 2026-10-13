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
generated = (imported / 'linux_neighbor_update.c').read_text() + (imported / 'ker/linux_neighbor_update.h').read_text()
required = ('static void neigh_update_flags(', 'static void neigh_update_hhs(',
            'static void neigh_suspect(', 'static void neigh_connect(',
            'static void neigh_update_process_arp_queue(',
            'static int __neigh_update(', 'int neigh_update(')
found = set()
for record in provenance:
    raw = (linux / record['file']).read_bytes()
    block = raw[record['start_offset']:record['start_offset'] + record['length']]
    assert hashlib.sha256(block).hexdigest() == record['sha256'], record['file']
    assert block.decode() in generated, record['file']
    first = block.decode().splitlines()[0].strip()
    found.add(first)
for anchor in required:
    assert any(line.startswith(anchor) for line in found), anchor
for filename, anchor in (('include/linux/types.h', 'typedef struct {'),
                         ('include/net/dst.h', 'struct dst_entry {')):
    assert any(record['file'] == filename and
               anchor in (linux / filename).read_text()[record['start_offset']:
                   record['start_offset'] + record['length']]
               for record in provenance), (filename, anchor)
for flag in ('NEIGH_UPDATE_F_OVERRIDE', 'NEIGH_UPDATE_F_ADMIN',
             'NEIGH_UPDATE_F_MANAGED', 'NEIGH_UPDATE_F_EXT_VALIDATED'):
    assert any(line.startswith('#define ' + flag) for line in generated.splitlines()), flag
with tempfile.TemporaryDirectory(prefix='ker-neighbor-update-import-') as temp:
    root = Path(temp)
    outputs = (root / 'first', root / 'second')
    for output in outputs:
        subprocess.run([sys.executable, str(importer), '--linux', str(linux),
                        '--manifest', str(manifest_path), '--out', str(output)], check=True)
    for name in ('linux_neighbor_update.c', 'provenance.json', 'ker/linux_neighbor_update.h'):
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
print('neighbor-update importer provenance passed')
