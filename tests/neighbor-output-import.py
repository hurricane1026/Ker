"""Verify pinned Linux neighbor output bodies and deterministic importer output."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

linux, manifest_path, imported, importer = map(Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())['files']
for name, digest in manifest.items():
    assert hashlib.sha256((linux / name).read_bytes()).hexdigest() == digest, name
records = json.loads((imported / 'provenance.json').read_text())
generated = ((imported / 'linux_neighbor_output.c').read_text() +
             (imported / 'ker/linux_neighbor_output.h').read_text())
assert len(records) == 5, records
for record in records:
    raw = (linux / record['file']).read_bytes()
    block = raw[record['start_offset']:record['start_offset'] + record['length']]
    assert hashlib.sha256(block).hexdigest() == record['sha256']
    assert block.decode() in generated
assert any((linux / r['file']).read_bytes()[r['start_offset']:r['start_offset']+r['length']].startswith(
    b'int neigh_resolve_output(') for r in records)
with tempfile.TemporaryDirectory(prefix='ker-neighbor-output-import-') as temporary:
    root = Path(temporary)
    outputs = (root / 'first', root / 'second')
    for output in outputs:
        subprocess.run([sys.executable, str(importer), '--linux', str(linux),
                        '--manifest', str(manifest_path), '--out', str(output)], check=True)
    paths = ('linux_neighbor_output.c', 'provenance.json', 'ker/linux_neighbor_output.h')
    for name in paths:
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
        '--manifest', str(manifest_path), '--out', str(root / 'rejected')], capture_output=True)
    assert result.returncode != 0 and not (root / 'rejected').exists()
print('neighbor-output importer provenance passed')
