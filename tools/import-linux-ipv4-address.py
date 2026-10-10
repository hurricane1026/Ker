#!/usr/bin/env python3
"""Import original IPv4 interface address layouts and prefix helpers verbatim."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--linux', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    texts = {}
    for name, digest in json.loads(a.manifest.read_text())['files'].items():
        raw = (a.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux IPv4 address source {name}')
        texts[name] = raw.decode()
    provenance = []
    def emit(name, start, end):
        block = texts[name][start:end]
        line = texts[name].count('\n', 0, start) + 1
        provenance.append(dict(file=name, start_line=line, start_offset=start,
                               length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {line} "third_party/linux/{name}"\n{block}\n'
    def definition(name, anchor, declaration=False):
        text = texts[name]
        match = re.search('^' + re.escape(anchor), text, re.M)
        if not match: raise ValueError(f'missing {name}: {anchor}')
        start = match.start()
        end = balanced_end(text, text.index('{', start))
        if declaration: end = text.index(';', end) + 1
        return emit(name, start, end)
    def line(name, anchor):
        text = texts[name]; start = text.index(anchor)
        return emit(name, start, text.index('\n', start))
    inet = 'include/linux/inetdevice.h'
    header = """/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_IPV4_ADDRESS_H
#define KER_IMPORTED_IPV4_ADDRESS_H
#pragma GCC system_header
#include "ker/linux_ethernet.h"
#include <linux/rcupdate.h>
#pragma push_macro("htonl")
#undef htonl
#define htonl rte_cpu_to_be_32
"""
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    header += definition('include/linux/types.h', 'struct callback_head {', True)
    header += line('include/linux/types.h', '#define rcu_head callback_head')
    header += definition('include/uapi/linux/ip.h', 'enum\n{\n\tIPV4_DEVCONF_FORWARDING=1,', True)
    header += line('include/uapi/linux/ip.h', '#define IPV4_DEVCONF_MAX')
    header += line('include/uapi/linux/if_addr.h', '#define IFA_F_PERMANENT')
    header += definition('include/uapi/linux/rtnetlink.h', 'enum rt_scope_t {', True)
    for anchor in ['struct ipv4_devconf {', 'struct in_device {', 'struct in_ifaddr {']:
        header += definition(inet, anchor, True)
    for anchor in ['static inline bool inet_ifa_match(', 'static __inline__ __be32 inet_make_mask(']:
        header += definition(inet, anchor)
    header += '#pragma pop_macro("htonl")\n#endif\n'
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header))
    configs.update(['CONFIG_IP_MULTICAST', 'CONFIG_SYSCTL'])
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported IPv4 address configuration {c}\n#endif\n'
                    for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#include <linux/rcupdate.h>', '#include <linux/rcupdate.h>\n' + guard)
    body = '/* Original IPv4 address helpers are inline in ker/linux_ipv4_address.h. */\n'
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'ker/linux_ipv4_address.h', header), (a.out / 'linux_ipv4_address.c', body),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
