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
generated = (imported / 'linux_arp_probe.c').read_text() + (imported / 'runtime/arp-probe-port.h').read_text()
required = {
    ('net/ipv4/arp.c', 'static void arp_solicit('),
    ('net/ipv4/arp.c', 'static void arp_send_dst('),
    ('net/ipv4/devinet.c', 'static __be32 in_dev_select_addr('),
    ('net/ipv4/devinet.c', '__be32 inet_select_addr('),
}
found = set()
for record in provenance:
    name = record['file']
    raw = (linux / name).read_bytes()
    block = raw[record['start_offset']:record['start_offset'] + record['length']]
    assert hashlib.sha256(block).hexdigest() == record['sha256'], name
    assert block.decode() in generated, name
    if name in ('net/ipv4/arp.c', 'net/ipv4/devinet.c'):
        found.add((name, block.decode().splitlines()[0].strip()))
for filename, anchor in required:
    assert any(name == filename and first.startswith(anchor) for name, first in found), (filename, anchor)
with tempfile.TemporaryDirectory(prefix='ker-arp-probe-import-') as temp:
    root = Path(temp)
    outputs = [root / 'first', root / 'second']
    for output in outputs:
        subprocess.run([sys.executable, str(importer), '--linux', str(linux),
                        '--manifest', str(manifest_path), '--out', str(output)], check=True)
    for name in ('linux_arp_probe.c', 'provenance.json', 'runtime/arp-probe-port.h'):
        assert (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes(), name
    changed_linux = root / 'linux'
    for name in manifest:
        target = changed_linux / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if name == 'net/ipv4/arp.c':
            target.write_bytes((linux / name).read_bytes() + b'\n/* altered */\n')
        else:
            target.symlink_to(linux / name)
    rejected = subprocess.run([sys.executable, str(importer), '--linux', str(changed_linux),
                               '--manifest', str(manifest_path), '--out', str(root / 'rejected')],
                              capture_output=True)
    assert rejected.returncode != 0
print('ARP probe importer provenance passed')
