#!/usr/bin/env python3
"""Import pinned NAPI layouts and scheduling/completion functions verbatim."""
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
            raise ValueError(f'unreviewed Linux NAPI source {name}')
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
    nd = 'include/linux/netdevice.h'
    header = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_NAPI_H
#define KER_IMPORTED_NAPI_H
#pragma GCC system_header
#include "ker/linux_ethernet.h"
#include <linux/timerqueue_types.h>
#include "compat/napi-config.h"
struct hrtimer_clock_base;
struct work_struct;
'''
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    header += line('include/linux/cpumask_types.h', 'typedef struct cpumask {')
    header += line('include/linux/workqueue_types.h', 'typedef void (*work_func_t)')
    header += definition('include/linux/workqueue_types.h', 'struct work_struct {', True)
    header += definition('include/linux/interrupt.h', 'struct irq_affinity_notify {', True)
    header += definition('include/linux/hrtimer_types.h', 'enum hrtimer_restart {', True)
    header += definition('include/linux/hrtimer_types.h', 'struct hrtimer {', True)
    header += line(nd, '#define GRO_HASH_BUCKETS')
    for anchor in ['struct gro_list {', 'struct gro_node {', 'struct napi_config {', 'struct napi_struct {',
                   'enum {\n\tNAPI_STATE_SCHED,', 'enum {\n\tNAPIF_STATE_SCHED']:
        header += definition(nd, anchor, True)
    header += '''
bool napi_schedule_prep(struct napi_struct *) __asm__("ker_linux_napi_schedule_prep");
bool napi_complete_done(struct napi_struct *, int) __asm__("ker_linux_napi_complete_done");
void __napi_schedule(struct napi_struct *) __asm__("ker_linux___napi_schedule");
'''
    for anchor in ['static inline bool napi_disable_pending(', 'static inline bool napi_is_scheduled(',
                   'static inline bool napi_schedule(', 'static inline bool napi_if_scheduled_mark_missed(']:
        header += definition(nd, anchor)
    header += '\n#endif\n'
    name = 'net/core/dev.c'
    body = emit(name, 0, texts[name].index('#include'))
    body += '\n#include "ker/linux_napi.h"\n#include "compat/napi-support.h"\n'
    body += definition(name, 'bool napi_schedule_prep(')
    body += definition(name, 'bool napi_complete_done(')
    # Pin the raw getters, avoiding unrelated dev.h dependencies.
    getters = definition('net/core/dev.h', 'static inline u32 napi_get_defer_hard_irqs(')
    getters += definition('net/core/dev.h', 'static inline unsigned long\nnapi_get_gro_flush_timeout(')
    body = body.replace('#include "compat/napi-support.h"', getters + '\n#include "compat/napi-support.h"')
    configs = set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b', header + body))
    configs.update(['CONFIG_NET_RX_BUSY_POLL', 'CONFIG_PREEMPT_RT', 'CONFIG_NETPOLL', 'CONFIG_BPF_SYSCALL'])
    guard = ''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported NAPI configuration {c}\n#endif\n'
                    for c in sorted(configs) if not c.endswith('_MODULE'))
    header = header.replace('#include "compat/napi-config.h"', '#include "compat/napi-config.h"\n' + guard)
    (a.out / 'ker').mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'ker/linux_napi.h', header), (a.out / 'linux_napi.c', body),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        if not path.exists() or path.read_text() != value: path.write_text(value)
if __name__ == '__main__': main()
