#!/usr/bin/env python3
"""Import pinned Linux __neigh_event_send for Ker's monitored profile."""
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
    files = json.loads(args.manifest.read_text())['files']
    texts = {}
    for name, digest in files.items():
        raw = (args.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux neighbor event-send source {name}')
        texts[name] = raw.decode()
    name = 'net/core/neighbour.c'
    text = texts[name]
    anchor = 'int __neigh_event_send('
    match = re.search('^' + re.escape(anchor), text, re.M)
    if not match:
        raise ValueError(f'missing {name}: {anchor}')
    start = match.start()
    end = balanced_end(text, text.index('{', start))
    block = text[start:end]
    provenance = [dict(file=name, start_line=text.count('\n', 0, start) + 1,
        start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest())]
    source = '''/* SPDX-License-Identifier: GPL-2.0 */
#include "compat/neighbor-event-send-port.h"
#include <linux/bug.h>
#include <string.h>
#undef write_unlock
#undef NEIGH_CACHE_STAT_INC
#define write_lock_bh(l) ker_neigh_event_write_lock_bh(l)
#define write_unlock_bh(l) ker_neigh_event_write_unlock_bh(l)
#define write_unlock(l) ker_neigh_event_write_unlock(l)
#define local_bh_enable() ker_neigh_event_local_bh_enable()
#define neigh_add_timer(n, when) ker_linux_neigh_start((n), (when))
#define neigh_del_timer(n) ker_linux_neigh_cancel(n)
#define neigh_probe(n) ker_neigh_event_unsupported()
#define skb_dst_force(s) ker_neigh_event_unsupported()
#define __skb_dequeue(q) ker_neigh_event_unsupported_skb()
#define __skb_queue_tail(q, s) ker_neigh_event_unsupported()
#define kfree_skb_reason(s, r) ker_neigh_event_unsupported()
#define NEIGH_CACHE_STAT_INC(t, f) ker_neigh_event_unsupported()
#define trace_neigh_event_send_done(n, rc) ker_neigh_event_trace_done((n), (rc))
#define trace_neigh_event_send_dead(n, rc) ker_neigh_event_trace_dead((n), (rc))
static void ker_neigh_event_unsupported(void) { BUG_ON(true); }
static struct sk_buff *ker_neigh_event_unsupported_skb(void) { BUG_ON(true); return NULL; }
'''
    source += f'\n#line {text.count(chr(10), 0, start) + 1} "third_party/linux/{name}"\n{block}\n'
    source += '\nint ker_linux_neigh_event_send(struct neighbour *n, struct sk_buff *skb, bool immediate_ok)\n{ return __neigh_event_send(n, skb, immediate_ok); }\n'
    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NEIGHBOR_EVENT_SEND_H
#define KER_IMPORTED_NEIGHBOR_EVENT_SEND_H
#include "runtime/neighbor-timer.h"
int ker_linux_neigh_event_send(struct neighbour *, struct sk_buff *, bool);
#endif
'''
    args.out.mkdir(parents=True, exist_ok=True)
    outputs = ((args.out / 'linux_neighbor_event_send.c', source),
               (args.out / 'ker/linux_neighbor_event_send.h', header),
               (args.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n'))
    for path, value in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != value:
            path.write_text(value)

if __name__ == '__main__':
    main()
