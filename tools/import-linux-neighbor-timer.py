#!/usr/bin/env python3
"""Import unchanged Linux neighbor timeout routines for a bounded worker profile."""
import argparse, hashlib, json, re, runpy
from pathlib import Path
balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']
def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('linux','manifest','out'): p.add_argument('--'+n, type=Path, required=True)
    a=p.parse_args(); texts={}; provenance=[]
    for n,d in json.loads(a.manifest.read_text())['files'].items():
        raw=(a.linux/n).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=d: raise ValueError(f'unreviewed Linux neighbor timer source {n}')
        texts[n]=raw.decode()
    def emit(n,start,end):
        block=texts[n][start:end];line=texts[n].count('\n',0,start)+1
        provenance.append(dict(file=n,start_line=line,start_offset=start,length=len(block),sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {line} "third_party/linux/{n}"\n{block}\n'
    def definition(n,anchor):
        start=re.search('^'+re.escape(anchor),texts[n],re.M).start()
        return emit(n,start,balanced_end(texts[n],texts[n].index('{',start)))
    def line(n,anchor):
        start=texts[n].index(anchor);return emit(n,start,texts[n].index('\n',start))
    nh='include/net/neighbour.h'; u='include/uapi/linux/neighbour.h'; nc='net/core/neighbour.c'
    header='''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NEIGHBOR_TIMER_H
#define KER_IMPORTED_NEIGHBOR_TIMER_H
#pragma GCC system_header
#include "ker/linux_neighbor.h"
#include "ker/linux_timer_list.h"
'''
    for name in ('NUD_INCOMPLETE','NUD_REACHABLE','NUD_STALE','NUD_DELAY','NUD_PROBE','NUD_FAILED','NUD_NOARP'):
        header+=line(u,'#define '+name)
    for name in ('NUD_IN_TIMER','NUD_VALID','NUD_CONNECTED'):
        header+=line(nh,'#define '+name)
    header+=line(u,'#define NTF_EXT_EXT_VALIDATED')+line(nh,'#define NTF_EXT_SHIFT')+line(nh,'#define NTF_EXT_VALIDATED')
    header+=definition(nh,'static inline void neigh_confirm(')
    header+='void ker_linux_neigh_timeout(struct timer_list *);\nvoid ker_linux_neigh_start(struct neighbour *, unsigned long);\n#endif\n'
    body='''/* SPDX-License-Identifier: GPL-2.0 */
#include "compat/neighbor-timer-port.h"
'''
    body+=emit(nc,0,texts[nc].index('#include'))
    body+=line(nh,'#define neigh_hold(n)')
    for anchor in ('static void neigh_add_timer(', 'static void neigh_suspect(', 'static void neigh_connect(',
                   'static __inline__ int neigh_max_probes(', 'static void neigh_invalidate(', 'static void neigh_probe(',
                   'static void neigh_timer_handler('):
        if anchor.endswith('neigh_timer_handler('):
            start=texts[nc].index('static void neigh_timer_handler(struct timer_list *t)\n{')
            body+=emit(nc,start,balanced_end(texts[nc],texts[nc].index('{',start)))
        else:body+=definition(nc,anchor)
    body+='''\nvoid ker_linux_neigh_timeout(struct timer_list *t) { neigh_timer_handler(t); }
void ker_linux_neigh_start(struct neighbour *n, unsigned long when) { neigh_add_timer(n, when); }
'''
    (a.out/'ker').mkdir(parents=True,exist_ok=True)
    for path,data in ((a.out/'ker/linux_neighbor_timer.h',header),(a.out/'linux_neighbor_timer.c',body),(a.out/'provenance.json',json.dumps(provenance,indent=2)+'\n')):
        if not path.exists() or path.read_text()!=data:path.write_text(data)
if __name__=='__main__':main()
