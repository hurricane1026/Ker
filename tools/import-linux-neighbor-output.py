#!/usr/bin/env python3
"""Import pinned Linux neighbor output and event-send inline semantics."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('linux', 'manifest', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    texts = {}
    for name, digest in json.loads(args.manifest.read_text())['files'].items():
        raw = (args.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux neighbor output source {name}')
        texts[name] = raw.decode()
    provenance = []
    def definition(name, anchor, sig_end=None):
        text = texts[name]
        match = re.search('^' + re.escape(anchor), text, re.M)
        if not match: raise ValueError(f'missing {name}: {anchor}')
        start = match.start()
        end = balanced_end(text, text.index('{', start))
        block = text[start:end]
        provenance.append(dict(file=name, start_line=text.count('\n', 0, start) + 1,
            start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {text.count(chr(10), 0, start) + 1} "third_party/linux/{name}"\n{block}\n'
    def line(name, anchor):
        text=texts[name]; start=text.index(anchor); end=text.index('\n',start)
        block=text[start:end]
        provenance.append(dict(file=name,start_line=text.count('\n',0,start)+1,
            start_offset=start,length=len(block),sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {text.count(chr(10),0,start)+1} "third_party/linux/{name}"\n{block}\n'
    source = '''/* SPDX-License-Identifier: GPL-2.0 */
#include "compat/neighbor-output-port.h"
#include "compat/neighbor-timer-port.h"
#include "compat/neighbor-event-send-port.h"
#include "compat/neighbor-sequence.h"
#include "runtime/tx-export.h"
#include "runtime/arp.h"
#include <linux/bug.h>
#include <linux/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#define neigh_hh_init(n) ker_neighbor_output_unsupported_hh()
#define dev_queue_xmit(skb) ker_neighbor_output_xmit((skb))
#define kfree_skb_reason(skb, reason) ker_neighbor_output_free((skb))
#define dev_hard_header(skb, dev, type, daddr, saddr, len) \\
    ((dev)->header_ops->create((skb), (dev), (type), (daddr), (saddr), (len)))
void ker_neighbor_output_free(struct sk_buff *);
int ker_neighbor_output_xmit(struct sk_buff *);
void ker_neighbor_output_unsupported_hh(void);
int __neigh_event_send(struct neighbour *, struct sk_buff *, bool);
'''
    source += line('include/net/neighbour.h', '#define NUD_CONNECTED')
    source += definition('include/linux/skbuff.h', 'static inline int skb_network_offset(')
    source += definition('include/net/neighbour.h', 'static __always_inline int neigh_event_send_probe(')
    source += definition('include/net/neighbour.h', 'static inline int neigh_event_send(')
    source += definition('net/core/neighbour.c', 'int neigh_resolve_output(')
    source += '''\nint ker_linux_neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb)
{ return neigh_resolve_output(neigh, skb); }
'''
    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NEIGHBOR_OUTPUT_H
#define KER_IMPORTED_NEIGHBOR_OUTPUT_H
#include "runtime/neighbor.h"
int ker_linux_neigh_resolve_output(struct neighbour *, struct sk_buff *);
#endif
'''
    args.out.mkdir(parents=True, exist_ok=True)
    outputs = ((args.out / 'linux_neighbor_output.c', source),
        (args.out / 'ker/linux_neighbor_output.h', header),
        (args.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n'))
    for path, value in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != value: path.write_text(value)

if __name__ == '__main__': main()
