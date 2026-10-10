#!/usr/bin/env python3
"""Import original neighbor layouts, ARP hash, lookup and snapshot helpers."""
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
            raise ValueError(f'unreviewed Linux neighbor source {name}')
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
    nh = 'include/net/neighbour.h'; nd = 'include/linux/netdevice.h'; seq = 'include/linux/seqlock_types.h'
    header = """/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NEIGHBOR_H
#define KER_IMPORTED_NEIGHBOR_H
#pragma GCC system_header
#include "ker/linux_ipv4_address.h"
#include "ker/linux_napi.h"
#include "compat/neighbor-config.h"
struct netlink_ext_ack;
struct pneigh_entry;
struct workqueue_struct;
"""
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    header += definition(seq, 'typedef struct seqcount {', True)
    text = texts[seq]; start = text.index('#if defined(CONFIG_LOCKDEP) || defined(CONFIG_PREEMPT_RT)')
    end = text.index('/*\n * Sequential locks (seqlock_t)', start)
    header += emit(seq, start, end)
    header += definition(seq, 'context_lock_struct(seqlock) {', True)
    header += line(seq, 'typedef struct seqlock seqlock_t;')
    # LL_MAX_HEADER's complete original configuration block, not a replacement constant.
    text = texts[nd]; start = text.index('#if defined(CONFIG_HYPERV_NET)')
    end = text.index('#if !IS_ENABLED(CONFIG_NET_IPIP)', start)
    header += emit(nd, start, end)
    header += definition(nd, 'struct hh_cache {', True)
    text = texts['include/linux/stddef.h']; start = text.index('#define struct_group_tagged(')
    end = text.index('\n', start)
    while text[end - 1] == '\\': end = text.index('\n', end + 1)
    header += emit('include/linux/stddef.h', start, end)
    header += definition('include/linux/skbuff.h', 'struct sk_buff_head {', True)
    header += definition('include/linux/workqueue.h', 'struct delayed_work {', True)
    header += definition(nh, 'enum {\n\tNEIGH_VAR_MCAST_PROBES,', True)
    for anchor in ['struct neigh_parms {', 'struct neigh_statistics {', 'struct neighbour {', 'struct neigh_ops {']:
        header += definition(nh, anchor, True)
    header += line(nh, '#define NEIGH_NUM_HASH_RND')
    header += definition(nh, 'struct neigh_hash_table {', True)
    header += definition(nh, 'struct neigh_table {', True)
    header += line(nh, '#define NEIGH_PRIV_ALIGN')
    header += line(nh, '#define NEIGH_ENTRY_SIZE(size)')
    header += line('include/uapi/linux/neighbour.h', '#define NUD_PERMANENT')
    header += definition('include/linux/hash.h', 'static inline u32 hash32_ptr(')
    header += definition('include/net/arp.h', 'static inline u32 arp_hashfn(')
    header += definition(nh, 'static inline bool neigh_key_eq32(')
    header += '#define neigh_for_each_in_bucket_rcu(pos, head) ker_neigh_for_each(pos, head)\n'
    for anchor in ['static inline struct neighbour *___neigh_lookup_noref(',
                   'static inline struct neighbour *__neigh_lookup_noref(',
                   'static inline struct neighbour * neigh_clone(',
                   'static inline struct neigh_parms *neigh_parms_clone(',
                   'static inline void __neigh_parms_put(']:
        header += definition(nh, anchor)
    header += '#include "compat/neighbor-sequence.h"\n'
    header += definition(nh, 'static inline void neigh_ha_snapshot(')
    for anchor in ['static inline void __skb_queue_head_init(', 'static inline void skb_queue_head_init(',
                   'static inline struct sk_buff *skb_peek(', 'static inline void __skb_insert(',
                   'static inline void __skb_queue_before(', 'static inline void __skb_queue_tail(',
                   'static inline void __skb_unlink(', 'static inline struct sk_buff *__skb_dequeue(']:
        header += definition('include/linux/skbuff.h', anchor)
    header += '\n#endif\n'
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header))
    configs.update(['CONFIG_RANDSTRUCT', 'CONFIG_NET_NS', 'CONFIG_DEBUG_LOCK_ALLOC', 'CONFIG_HAVE_ARCH_HASH'])
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported neighbor configuration {c}\n#endif\n'
                    for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#include "compat/neighbor-config.h"', '#include "compat/neighbor-config.h"\n' + guard)
    body = '/* Original neighbor lookup and snapshot helpers are inline. */\n'
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'ker/linux_neighbor.h', header), (a.out / 'linux_neighbor.c', body),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
