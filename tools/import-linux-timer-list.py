#!/usr/bin/env python3
"""Import original timer_list helpers and wrap-aware tick predicates."""
import argparse, hashlib, json, re, runpy
from pathlib import Path
balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']
def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('linux', 'manifest', 'out'): p.add_argument('--'+name, type=Path, required=True)
    a=p.parse_args();texts={};provenance=[]
    for name,digest in json.loads(a.manifest.read_text())['files'].items():
        raw=(a.linux/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError(f'unreviewed Linux timer list source {name}')
        texts[name]=raw.decode()
    def emit(name,start,end):
        block=texts[name][start:end];line=texts[name].count('\n',0,start)+1
        provenance.append(dict(file=name,start_line=line,start_offset=start,length=len(block),sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {line} "third_party/linux/{name}"\n{block}\n'
    def definition(name,anchor):
        start=re.search('^'+re.escape(anchor),texts[name],re.M).start()
        return emit(name,start,balanced_end(texts[name],texts[name].index('{',start)))
    def macro(name,identifier):
        start=re.search(r'^#define[ \t]+'+re.escape(identifier)+r'(?=[ (\t])',texts[name],re.M).start();end=texts[name].index('\n',start)
        while texts[name][end-1]=='\\':end=texts[name].index('\n',end+1)
        return emit(name,start,end)
    header='''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KER_IMPORTED_TIMER_LIST_H
#define KER_IMPORTED_TIMER_LIST_H
#pragma GCC system_header
#include "ker/linux_ethernet.h"
#if defined(HZ) && HZ != 1000
#error Unsupported timer list HZ
#endif
#ifndef HZ
#define HZ 1000
#endif
struct lock_class_key;
void timer_init_key(struct timer_list *, void (*)(struct timer_list *), unsigned int,
    const char *, struct lock_class_key *) __asm__("ker_linux_timer_init_key");
int mod_timer(struct timer_list *, unsigned long) __asm__("ker_linux_timer_mod");
int mod_timer_pending(struct timer_list *, unsigned long) __asm__("ker_linux_timer_mod_pending");
int timer_reduce(struct timer_list *, unsigned long) __asm__("ker_linux_timer_reduce");
int ker_linux_timer_delete_native(struct timer_list *) __asm__("ker_linux_timer_delete");
int timer_shutdown(struct timer_list *) __asm__("ker_linux_timer_shutdown");
void add_timer(struct timer_list *) __asm__("ker_linux_timer_add");
unsigned long ker_linux_timer_jiffies(void);
#define jiffies ker_linux_timer_jiffies()
'''
    for name,text in texts.items():
        directive=re.search(r'^#(?:ifndef|define|include)',text,re.M)
        if directive and directive.start():header+=emit(name,0,directive.start())
    name='include/linux/list.h'
    for anchor in ['static inline void INIT_HLIST_NODE(', 'static inline int hlist_unhashed(',
                   'static inline int hlist_unhashed_lockless(', 'static inline void __hlist_del(',
                   'static inline void hlist_del_init(', 'static inline void hlist_add_head(']:header+=definition(name,anchor)
    name='include/linux/timer.h'
    header+=macro(name,'TIMER_PINNED')
    # Disabled lockdep branch; guards below reject unsupported configurations.
    start=texts[name].index('#else\n#define __timer_init(_timer, _fn, _flags)')+len('#else\n')
    end=texts[name].index('#define __timer_init_on_stack',start)
    header+=emit(name,start,end)
    header+=macro(name,'timer_setup');header+=macro(name,'timer_container_of');header+=definition(name,'static inline int timer_pending(')
    header+=macro('include/linux/typecheck.h','typecheck')
    for identifier in ['time_after','time_before','time_after_eq','time_before_eq','time_in_range','time_in_range_open']:
        header+=macro('include/linux/jiffies.h',identifier)
    configs=['CONFIG_LOCKDEP','CONFIG_DEBUG_OBJECTS_TIMERS','CONFIG_PREEMPT_RT','CONFIG_TIMER_MIGRATION']
    guard=''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported timer list configuration {c}\n#endif\n' for c in configs)
    header=header.replace('#pragma GCC system_header','#pragma GCC system_header\n'+guard)+'\n#endif\n'
    (a.out/'ker').mkdir(parents=True,exist_ok=True)
    for path,value in [(a.out/'ker/linux_timer_list.h',header),(a.out/'provenance.json',json.dumps(provenance,indent=2)+'\n')]:
        if not path.exists() or path.read_text()!=value:path.write_text(value)
if __name__=='__main__':main()
