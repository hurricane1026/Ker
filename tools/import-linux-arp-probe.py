#!/usr/bin/env python3
"""Import the pinned native ARP solicitation and IPv4 source selectors."""
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
    manifest = json.loads(a.manifest.read_text())
    texts = {}
    for name, digest in manifest['files'].items():
        raw = (a.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux ARP probe source {name}')
        texts[name] = raw.decode()
    provenance = []
    def emit(name, anchor):
        text = texts[name]
        match = re.search('^' + re.escape(anchor), text, re.M)
        if not match: raise ValueError(f'missing {name}: {anchor}')
        start = match.start()
        while True:
            brace = text.find('{', start)
            semicolon = text.find(';', start)
            if brace < 0 or (semicolon >= 0 and semicolon < brace):
                match = re.search('^' + re.escape(anchor), text[match.end():], re.M)
                if not match: raise ValueError(f'missing definition {name}: {anchor}')
                start = text.find(anchor, start + 1)
                continue
            break
        end = balanced_end(text, brace)
        block = text[start:end]
        provenance.append(dict(file=name, start_line=text.count('\n', 0, start) + 1,
            start_offset=start, length=len(block), sha256=hashlib.sha256(block.encode()).hexdigest()))
        return f'\n#line {text.count(chr(10), 0, start) + 1} "third_party/linux/{name}"\n{block}\n'
    source = '''/* SPDX-License-Identifier: GPL-2.0 */
/* Exact native functions are pinned by the importer manifest. */
#include "runtime/arp-probe-port.h"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#define arp_xmit ker_arp_probe_xmit
#define inet_select_addr ker_linux_inet_select_addr
'''
    source += emit('net/ipv4/devinet.c', 'static __be32 in_dev_select_addr(')
    source += emit('net/ipv4/devinet.c', '__be32 inet_select_addr(')
    source += emit('net/ipv4/arp.c', 'static void arp_send_dst(')
    source += emit('net/ipv4/arp.c', 'static void arp_solicit(')
    source += '''
void ker_linux_arp_solicit(struct neighbour *neigh)
{
    arp_solicit(neigh, NULL);
}
'''
    header = '''#ifndef KER_IMPORTED_ARP_PROBE_H
#define KER_IMPORTED_ARP_PROBE_H
#include "runtime/neighbor-timer.h"
#include "runtime/ipv4-address.h"
#include "runtime/arp.h"
#include <linux/rcupdate.h>
#include <linux/errno.h>
#include <linux/bug.h>
struct net;
struct dst_entry;
struct net *dev_net(struct net_device *);
struct net *dev_net_rcu(const struct net_device *);
int inet_addr_type_dev_table(struct net *, struct net_device *, __be32);
bool inet_addr_onlink(struct in_device *, __be32, __be32);
void neigh_app_ns(struct neighbour *);
struct dst_entry *dst_clone(struct dst_entry *);
void ker_arp_probe_xmit(struct sk_buff *);
void ker_arp_capture_bug(void);
int ker_arp_capture_begin(struct ker_eth_device *);
int ker_arp_capture_end(void);
void ker_arp_probe_rcu_enter(void);
void ker_arp_probe_rcu_exit(void);
struct net_device *ker_arp_probe_for_each_netdev(struct net *);
void ker_linux_arp_solicit(struct neighbour *);
#define l3mdev_master_ifindex_rcu(d) (ker_arp_capture_bug(), 0)
#define dev_get_by_index_rcu(n, i) (ker_arp_capture_bug(), (struct net_device *)NULL)
#define IFF_NOARP ker_linux_IFF_NOARP
#define skb_dst(skb) (ker_arp_capture_bug(), (struct dst_entry *)NULL)
#define skb_dst_set(skb, dst) do { if (dst) ker_arp_capture_bug(); } while (0)
#define dst_clone(dst) (dst ? (ker_arp_capture_bug(), (struct dst_entry *)NULL) : (struct dst_entry *)NULL)
#define IN_DEV_ARP_ANNOUNCE(d) ((d)->cnf.data[IPV4_DEVCONF_ARP_ANNOUNCE - 1])
#define IN_DEV_ROUTE_LOCALNET(d) ((d)->cnf.data[IPV4_DEVCONF_ROUTE_LOCALNET - 1])
#define in_dev_for_each_ifa_rcu(ifa, in_dev) \\
    for ((ifa) = rcu_dereference_raw((in_dev)->ifa_list); (ifa); \\
         (ifa) = rcu_dereference_raw((ifa)->ifa_next))
#define for_each_netdev_rcu(net, dev) for ((dev) = ker_arp_probe_for_each_netdev(net); (dev); (dev) = NULL)
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#define pr_debug(...) ((void)0)
#define rcu_read_lock() ker_arp_probe_rcu_enter()
#define rcu_read_unlock() ker_arp_probe_rcu_exit()
#define rcu_dereference(ptr) rcu_dereference_raw(ptr)
#define neigh_ha_snapshot(dst, n, dev) neigh_ha_snapshot((char *)(dst), (n), (dev))
#endif
'''
    header = header[:-len('#endif\n')] + '''#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#else
#define __BIG_ENDIAN_BITFIELD
#endif
''' + emit('include/uapi/linux/ip.h', 'struct iphdr {') + ';\n'
    header += emit('include/linux/ip.h', 'static inline struct iphdr *ip_hdr(') + '#endif\n'
    native_macro = texts['include/linux/inetdevice.h']
    macro = re.search(r'^#define in_dev_for_each_ifa_rcu\(ifa, in_dev\)[\s\S]*?\n\n', native_macro, re.M)
    if not macro: raise ValueError('missing in_dev_for_each_ifa_rcu')
    custom = ('#define in_dev_for_each_ifa_rcu(ifa, in_dev) \\\n'
              '    for ((ifa) = rcu_dereference_raw((in_dev)->ifa_list); (ifa); \\\n'
              '         (ifa) = rcu_dereference_raw((ifa)->ifa_next))')
    header = header.replace(custom, macro.group(0).rstrip())
    prefix, suffix = header.rsplit('#endif', 1)
    header = prefix + emit('include/linux/inetdevice.h',
        'static inline struct in_device *__in_dev_get_rcu(') + '#endif' + suffix
    if_addr = texts['include/uapi/linux/if_addr.h']
    flag = re.search(r'^#define[ \t]+IFA_F_SECONDARY[^\n]*', if_addr, re.M)
    if not flag: raise ValueError('missing IFA_F_SECONDARY')
    prefix, suffix = header.rsplit('#endif', 1)
    header = prefix + '\n' + flag.group(0) + '\n#ifndef BIT_ULL\n#define BIT_ULL(n) (1ULL << (n))\n#endif\n' + emit('include/linux/netdevice.h', 'enum netdev_priv_flags {') + ';\n' + emit('include/uapi/linux/rtnetlink.h', 'enum {\n\tRTN_UNSPEC,') + ';\n#endif' + suffix
    a.out.mkdir(parents=True, exist_ok=True)
    for path, value in [(a.out / 'linux_arp_probe.c', source),
                        (a.out / 'runtime/arp-probe-port.h', header),
                        (a.out / 'provenance.json', json.dumps(provenance, indent=2) + '\n')]:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != value: path.write_text(value)

if __name__ == '__main__': main()
