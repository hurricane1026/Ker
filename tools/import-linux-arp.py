#!/usr/bin/env python3
"""Import pinned original ARP and Ethernet packet constructors verbatim."""
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
            raise ValueError(f'unreviewed Linux ARP source {name}')
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
    nd = 'include/linux/netdevice.h'; sk = 'include/linux/skbuff.h'; interface = 'include/uapi/linux/if.h'
    header = """/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_ARP_H
#define KER_IMPORTED_ARP_H
#pragma GCC system_header
#include "ker/linux_ethernet.h"
#include <linux/gfp.h>
#include <linux/errno.h>
struct neighbour;
struct hh_cache;
"""
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    # Namespace the original UAPI enum so a preceding glibc net/if.h cannot
    # substitute macros or collide with its enumerators. Restore all macros.
    flag_names = sorted(set(re.findall(r'\bIFF_[A-Z0-9_]+(?=\s*=)', texts[interface])))
    names = flag_names + ['net_device_flags', '__UAPI_DEF_IF_NET_DEVICE_FLAGS',
                           '__UAPI_DEF_IF_NET_DEVICE_FLAGS_LOWER_UP_DORMANT_ECHO']
    for name in names:
        header += f'#pragma push_macro("{name}")\n#undef {name}\n'
        header += f'#define {name} ' + ('1' if name.startswith('__UAPI_') else 'ker_linux_' + name) + '\n'
    header += definition(interface, 'enum net_device_flags {', True)
    for name in reversed(names): header += f'#pragma pop_macro("{name}")\n'
    for name, identifiers in [(nd, ['HH_DATA_MOD', 'LL_RESERVED_SPACE_EX', 'LL_RESERVED_SPACE']),
                              ('include/uapi/linux/if_arp.h', ['ARPOP_REQUEST', 'ARPOP_REPLY'])]:
        for identifier in identifiers:
            text = texts[name]; match = re.search(r'^#define[ \t]+'+identifier+r'(?=[ (\t])', text, re.M)
            start = match.start(); end = text.index('\n', start)
            while text[end - 1] == '\\': end = text.index('\n', end + 1)
            header += emit(name, start, end)
    header += definition(nd, 'struct header_ops {', True)
    header += definition('include/uapi/linux/if_arp.h', 'struct arphdr {', True)
    header += definition(nd, 'static inline int dev_hard_header(')
    header += definition(sk, 'static inline unsigned char *skb_network_header(')
    for anchor in ['static inline struct arphdr *arp_hdr(', 'static inline unsigned int arp_hdr_len(']:
        header += definition('include/linux/if_arp.h', anchor)
    header += definition('include/linux/etherdevice.h', 'static inline void eth_zero_addr(')
    header += """
struct sk_buff *alloc_skb(unsigned int, gfp_t) __asm__("ker_linux_arp_alloc_skb");
void kfree_skb(struct sk_buff *) __asm__("ker_linux_arp_kfree_skb");
struct sk_buff *arp_create(int, int, __be32, struct net_device *, __be32,
    const unsigned char *, const unsigned char *, const unsigned char *) __asm__("ker_linux_arp_create");
int eth_header(struct sk_buff *, struct net_device *, unsigned short,
    const void *, const void *, unsigned int) __asm__("ker_linux_arp_eth_header");
#endif
"""
    source = 'net/ipv4/arp.c'; body = emit(source, 0, texts[source].index('#include'))
    body += '\n#include "ker/linux_arp.h"\n#undef htons\n#define htons rte_cpu_to_be_16\n'
    for name in flag_names: body += f'#undef {name}\n#define {name} ker_linux_{name}\n'
    body += definition(source, 'struct sk_buff *arp_create(')
    source = 'net/ethernet/eth.c'; body += emit(source, 0, texts[source].index('#include'))
    body += definition(source, 'int eth_header(')
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header + body))
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported ARP configuration {c}\n#endif\n'
                    for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#include <linux/errno.h>', '#include <linux/errno.h>\n' + guard)
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'ker/linux_arp.h', header), (a.out / 'linux_arp.c', body),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
