#!/usr/bin/env python3
"""Import the pinned original ARP receive gate and skb ownership helpers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('linux', 'manifest', 'out'): p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); texts = {}; provenance = []
    for name, digest in json.loads(a.manifest.read_text())['files'].items():
        raw = (a.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest: raise ValueError(f'unreviewed Linux ARP receive source {name}')
        texts[name] = raw.decode()
    def emit(name, start, end):
        block = texts[name][start:end]; line = texts[name].count('\n', 0, start) + 1
        provenance.append(dict(file=name, start_line=line, start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {line} "third_party/linux/{name}"\n{block}\n'
    def definition(name, anchor, declaration=False):
        start = re.search('^' + re.escape(anchor), texts[name], re.M).start()
        end = balanced_end(texts[name], texts[name].index('{', start))
        if declaration: end = texts[name].index(';', end) + 1
        return emit(name, start, end)
    sk = 'include/linux/skbuff.h'; neigh = 'include/net/neighbour.h'
    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_ARP_RECEIVE_H
#define KER_IMPORTED_ARP_RECEIVE_H
#pragma GCC system_header
#include "ker/linux_arp.h"
#include "ker/linux_receive.h"
'''
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    header += definition('include/net/dropreason-core.h', 'enum skb_drop_reason {', True)
    header += definition(neigh, 'struct neighbour_cb {', True)
    arp = 'include/uapi/linux/if_arp.h'; start = re.search(r'^#define\s+ARPHRD_IEEE802\s', texts[arp], re.M).start(); header += emit(arp, start, texts[arp].index('\n', start))
    packet = 'include/uapi/linux/if_packet.h'; start = texts[packet].index('#define PACKET_LOOPBACK'); header += emit(packet, start, texts[packet].index('\n', start))
    start = texts[neigh].index('#define NEIGH_CB(skb)'); header += emit(neigh, start, texts[neigh].index('\n', start))
    header += '''
struct sk_buff *ker_arp_rx_clone(struct sk_buff *, gfp_t);
void ker_arp_rx_free(struct sk_buff *);
void ker_arp_rx_free_reason(struct sk_buff *, enum skb_drop_reason);
int ker_arp_rx_process(struct sk_buff *, struct net_device *);
int ker_linux_arp_receive(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
#endif
'''
    name = 'net/ipv4/arp.c'; body = emit(name, 0, texts[name].index('#include'))
    body += '''
#include "ker/linux_arp_receive.h"
/* Worker profile accepts only GFP_ATOMIC. Unsupported linearization is fatal
 * if reached after bridge validation, never an invented successful pull. */
#define might_sleep_if(condition) BUG_ON(condition)
#define skb_clone ker_arp_rx_clone
#define consume_skb ker_arp_rx_free
#define kfree_skb ker_arp_rx_free
#define kfree_skb_reason ker_arp_rx_free_reason
void *ker_arp_rx_pull_tail(struct sk_buff *, int);
#define __pskb_pull_tail ker_arp_rx_pull_tail
'''
    body += definition('include/linux/gfp.h', 'static inline bool gfpflags_allow_blocking(')
    body += definition(sk, 'static inline void skb_might_realloc(')
    body += definition(sk, 'static inline struct sk_buff *skb_share_check(')
    body += definition(sk, 'static __always_inline enum skb_drop_reason\npskb_may_pull_reason(')
    body += '''
#define IFF_NOARP ker_linux_IFF_NOARP
/* Explicit private post-validation handoff. CONFIG_NETFILTER is rejected;
 * this does not implement NF_HOOK or the original arp_process state machine. */
#define NF_HOOK(pf, hook, net, sk, skb, in, out, okfn) ker_arp_rx_process(skb, in)
'''
    body += definition(name, 'static int arp_rcv(')
    body += '''
int ker_linux_arp_receive(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *original)
{
    return arp_rcv(skb, dev, pt, original);
}
'''
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header + body))
    configs.update(['CONFIG_NETFILTER', 'CONFIG_FAIL_SKB_REALLOC', 'CONFIG_DEBUG_NET'])
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported ARP receive configuration {c}\n#endif\n' for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#pragma GCC system_header', '#pragma GCC system_header\n' + guard)
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out/'ker/linux_arp_receive.h', header), (a.out/'linux_arp_receive.c', body), (a.out/'provenance.json', json.dumps(provenance, indent=2)+'\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
