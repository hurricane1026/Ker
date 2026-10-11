#!/usr/bin/env python3
"""Import pinned Linux neighbor-update routines for Ker's monitored profile."""
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
            raise ValueError(f'unreviewed Linux neighbor-update source {name}')
        texts[name] = raw.decode()
    provenance = []

    def emit(name, anchor, declaration=False):
        text = texts[name]
        match = re.search('^' + re.escape(anchor), text, re.M)
        if not match:
            raise ValueError(f'missing {name}: {anchor}')
        start = match.start()
        end = balanced_end(text, text.index('{', start))
        if declaration:
            end = text.index(';', end) + 1
        block = text[start:end]
        provenance.append(dict(file=name, start_line=text.count('\n', 0, start) + 1,
            start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {text.count(chr(10), 0, start) + 1} "third_party/linux/{name}"\n{block}\n'

    def native_line(name, anchor):
        text = texts[name]
        start = text.index(anchor)
        end = text.index('\n', start)
        block = text[start:end]
        provenance.append(dict(file=name, start_line=text.count('\n', 0, start) + 1,
            start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return block

    nh = 'include/net/neighbour.h'
    uapi = 'include/uapi/linux/neighbour.h'
    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NEIGHBOR_UPDATE_H
#define KER_IMPORTED_NEIGHBOR_UPDATE_H
#include "runtime/neighbor-timer.h"
#include "ker/linux_arp.h"
'''
    for macro in ('NEIGH_UPDATE_F_OVERRIDE', 'NEIGH_UPDATE_F_WEAK_OVERRIDE',
                  'NEIGH_UPDATE_F_OVERRIDE_ISROUTER', 'NEIGH_UPDATE_F_USE',
                  'NEIGH_UPDATE_F_MANAGED', 'NEIGH_UPDATE_F_EXT_LEARNED',
                  'NEIGH_UPDATE_F_ISROUTER', 'NEIGH_UPDATE_F_ADMIN',
                  'NEIGH_UPDATE_F_EXT_VALIDATED'):
        header += native_line(nh, '#define ' + macro) + '\n'
    for macro in ('NTF_ROUTER', 'NTF_EXT_MANAGED', 'NTF_EXT_LEARNED', 'NTF_EXT_EXT_VALIDATED'):
        header += native_line(uapi, '#define ' + macro) + '\n'
    for macro in ('NTF_EXT_SHIFT', 'NTF_EXT_MASK', 'NTF_MANAGED', 'NTF_EXT_VALIDATED'):
        header += native_line(nh, '#define ' + macro)
        header += '\n'
    header += '''
void ker_neighbor_update_seq_write_lock(seqlock_t *);
void ker_neighbor_update_seq_write_unlock(seqlock_t *);
int ker_linux_neigh_update(struct neighbour *, const unsigned char *, u8, u32);
#endif
'''
    source = '''/* SPDX-License-Identifier: GPL-2.0 */
#include "compat/neighbor-update-port.h"
#include <linux/bug.h>
#include <string.h>
#define neigh_add_timer(n, when) ker_linux_neigh_start((n), (when))
#define neigh_del_timer(n) ker_linux_neigh_cancel(n)
#define neigh_update_gc_list(n) ker_neighbor_update_unsupported()
#define neigh_update_managed_list(n) ker_neighbor_update_unsupported()
#define neigh_invalidate(n) ker_neighbor_update_unsupported()
#define neigh_update_process_arp_queue(n) ker_neighbor_update_unsupported()
#define neigh_update_is_router(n, f, p) ker_neighbor_update_unsupported()
#define write_lock_bh(l) ker_neigh_write_lock(l)
#define write_unlock_bh(l) ker_neigh_write_unlock(l)
#define write_seqlock(l) ker_neighbor_update_seq_write_lock(l)
#define write_sequnlock(l) ker_neighbor_update_seq_write_unlock(l)
#define write_seqlock_bh(l) ker_neighbor_update_seq_write_lock(l)
#define write_sequnlock_bh(l) ker_neighbor_update_seq_write_unlock(l)
#define trace_neigh_update(...) ((void)0)
#define trace_neigh_update_done(...) ((void)0)
#define NL_SET_ERR_MSG(extack, msg) do { (void)(extack); (void)(msg); } while (0)
static void ker_neighbor_update_unsupported(void) { BUG_ON(true); }
#define neigh_update ker_linux_neigh_update_raw
'''
    nc = 'net/core/neighbour.c'
    for anchor in ('static void neigh_update_flags(', 'static void neigh_update_hhs(',
                   'static void neigh_suspect(', 'static void neigh_connect(',
                   'static int __neigh_update(', 'int neigh_update('):
        source += emit(nc, anchor)
    source += '''
int ker_linux_neigh_update(struct neighbour *neigh, const unsigned char *mac,
                           u8 state, u32 flags)
{
    return neigh_update(neigh, mac, state, flags, 0);
}
'''
    args.out.mkdir(parents=True, exist_ok=True)
    outputs = ((args.out / 'linux_neighbor_update.c', source),
               (args.out / 'ker/linux_neighbor_update.h', header),
               (args.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n'))
    for path, value in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != value:
            path.write_text(value)

if __name__ == '__main__':
    main()
