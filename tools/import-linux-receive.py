#!/usr/bin/env python3
"""Import pinned packet_type layouts and receive delivery functions verbatim."""
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
            raise ValueError(f'unreviewed Linux receive source {name}')
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
    nd = 'include/linux/netdevice.h'; sk = 'include/linux/skbuff.h'
    header = """/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_RECEIVE_H
#define KER_IMPORTED_RECEIVE_H
#pragma GCC system_header
#include "ker/linux_napi.h"
#include "compat/receive-config.h"
"""
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    header += definition(nd, 'struct packet_type {', True)
    for name, anchors in [(nd, ['#define PTYPE_HASH_SIZE', '#define PTYPE_HASH_MASK', '#define NET_RX_SUCCESS', '#define NET_RX_DROP']),
                          ('include/uapi/linux/if_ether.h', ['#define ETH_P_ALL']), (sk, ['#define skb_uarg(SKB)']), ('include/linux/if_vlan.h', ['#define skb_vlan_tag_present(__skb)'])]:
        for anchor in anchors: header += line(name, anchor)
    header += definition(sk, 'enum {\n\t/* use zcopy routines */', True)
    header += definition(sk, 'static inline struct ubuf_info *skb_zcopy(')
    header += 'int skb_copy_ubufs(struct sk_buff *, gfp_t) __asm__("ker_linux_rx_copy_ubufs");\n'
    for anchor in ['static inline int skb_orphan_frags_rx(', 'static inline void skb_reset_mac_len(',
                   'static inline bool skb_transport_header_was_set(', 'static inline void skb_reset_transport_header(']:
        header += definition(sk, anchor)
    header += 'void ker_linux_deliver_ptype_list(struct sk_buff *, struct packet_type **, struct net_device *, __be16, struct list_head *);\n#endif\n'
    name = 'net/core/dev.c'
    body = emit(name, 0, texts[name].index('#include'))
    body += '\n#include "ker/linux_receive.h"\n'
    body += definition(name, 'static int deliver_skb(')
    body += definition(name, 'static inline void deliver_ptype_list_skb(')
    body += """
void ker_linux_deliver_ptype_list(struct sk_buff *skb, struct packet_type **pt,
    struct net_device *orig_dev, __be16 type, struct list_head *list)
{
    BUG_ON(!skb || !pt || !orig_dev || !list);
    deliver_ptype_list_skb(skb, pt, orig_dev, type, list);
}
"""
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header + body))
    configs.update(['CONFIG_NET_NS', 'CONFIG_NETFILTER', 'CONFIG_NET_INGRESS', 'CONFIG_NET_EGRESS',
                    'CONFIG_BPF_SYSCALL', 'CONFIG_NET_CLS_ACT', 'CONFIG_NET_TC_SKB_EXT', 'CONFIG_RPS', 'CONFIG_NETPOLL', 'CONFIG_VLAN_8021Q'])
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported receive configuration {c}\n#endif\n'
                    for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#include "compat/receive-config.h"', '#include "compat/receive-config.h"\n' + guard)
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'ker/linux_receive.h', header), (a.out / 'linux_receive.c', body),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
