#!/usr/bin/env python3
"""Import reviewed original Ethernet functions and complete net_device layouts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

balanced_end = runpy.run_path(str(Path(__file__).with_name('import-linux-skb.py')))['balanced_end']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    texts = {}
    for name, digest in json.loads(args.manifest.read_text())['files'].items():
        raw = (args.linux/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'unreviewed Linux Ethernet source {name}')
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
        found = re.search('^'+re.escape(anchor), text, re.M)
        if not found: raise ValueError(f'missing {name}: {anchor}')
        start = found.start()
        end = balanced_end(text, text.index('{', start))
        if declaration: end = text.index(';', end)+1
        return emit(name, start, end)
    def macro(name, identifier):
        text = texts[name]
        match = re.search(r'^#define[ \t]+'+re.escape(identifier)+r'(?=[ (\t])', text, re.M)
        if not match: raise ValueError(f'missing macro {identifier}')
        end = text.index('\n', match.start())
        while text[end-1]=='\\': end=text.index('\n',end+1)
        if text[match.start():end].rfind('/*') > text[match.start():end].rfind('*/'):
            end = text.index('\n', text.index('*/', end)+2)
        return emit(name,match.start(),end)
    def line(name, anchor):
        text=texts[name];start=text.index(anchor);return emit(name,start,text.index('\n',start))
    nd='include/linux/netdevice.h';sk='include/linux/skbuff.h';ed='include/linux/etherdevice.h'
    header='''/* SPDX-License-Identifier: GPL-2.0 */
/* Generated original layouts and Ethernet slice; see linux-ethernet-manifest.json. */
#ifndef KER_IMPORTED_ETHERNET_H
#define KER_IMPORTED_ETHERNET_H
#pragma GCC system_header
#include "ker/linux_skb.h"
#include "compat/ethernet-config.h"
#pragma push_macro("__BIG_ENDIAN")
#pragma push_macro("htons")
#undef __BIG_ENDIAN
#undef htons
#define htons rte_cpu_to_be_16
struct device;
struct net_device;
struct net;
'''
    # Retain the original SPDX/copyright prefaces of every projected header.
    for name, text in texts.items():
        if name.endswith('.h'):
            directive = re.search(r'^#(?:ifndef|define|include)', text, re.M)
            if directive and directive.start(): header += emit(name, 0, directive.start())
    for source,names in [('include/uapi/linux/if.h',['IFNAMSIZ']),
        ('include/uapi/linux/netdevice.h',['MAX_ADDR_LEN']),
        ('include/uapi/linux/if_arp.h',['ARPHRD_ETHER']),
        ('include/vdso/cache.h',['____cacheline_aligned']),
        ('include/linux/cache.h',['__cacheline_group_begin','__cacheline_group_end']),
        (nd,['TC_MAX_QUEUE','TC_BITMASK','NET_DEV_STAT']),
        ('include/linux/types.h',['DECLARE_BITMAP']),
        ('include/uapi/linux/if_ether.h',['ETH_ALEN','ETH_HLEN','ETH_DATA_LEN','ETH_P_IP','ETH_P_ARP','ETH_P_IPV6',
          'ETH_P_802_3_MIN','ETH_P_XDSA','ETH_P_802_3','ETH_P_802_2','ETH_P_8021Q','ETH_P_8021AD']),
        ('include/uapi/linux/if_packet.h',['PACKET_HOST','PACKET_BROADCAST','PACKET_MULTICAST','PACKET_OTHERHOST'])]:
        for name in names: header+=macro(source,name)
    header+=definition('include/linux/types.h','typedef struct {\n\ts64 counter;',True)
    header+=line('include/linux/atomic/atomic-long.h','typedef atomic64_t atomic_long_t;')
    for source,anchor in [('include/linux/types.h','struct hlist_head {'),
        ('include/linux/types.h','struct hlist_node {'),('include/linux/kref.h','struct kref {'),
        ('include/linux/kobject.h','struct kobject {'),('include/asm-generic/device.h','struct dev_archdata {'),
        ('include/linux/pm.h','typedef struct pm_message {'),('include/linux/pm.h','struct dev_pm_info {'),
        ('include/linux/device.h','enum dl_dev_state {'),('include/linux/device.h','enum device_removable {'),
        ('include/linux/device.h','enum struct_device_flags {'),('include/linux/device.h','struct dev_links_info {'),
        ('include/linux/device.h','struct dev_msi_info {'),('include/linux/ref_tracker.h','struct ref_tracker_dir {'),
        ('include/linux/timer_types.h','struct timer_list {')]:
        header+=definition(source,anchor,True)
    # Kernel dev_t is 32-bit, unlike libc dev_t. Keep the original typedef and
    # declaration text, with a private token namespace only inside this slice.
    header+='#define dev_t ker_linux_dev_t\n'
    header+=line('include/linux/types.h','typedef u32 __kernel_dev_t;')
    header+=line('include/linux/types.h','typedef __kernel_dev_t')
    header+=definition('include/linux/device.h','struct device {',True)
    header+='#undef dev_t\n'
    header+=definition('include/net/net_namespace.h','typedef struct {\n#ifdef CONFIG_NET_NS',True)
    header+=line('include/net/net_trackers.h','typedef struct {} netdevice_tracker;')
    header+=line('include/linux/netdev_features.h','typedef u64 netdev_features_t;')
    header+=line(nd,'typedef u32 xdp_features_t;')
    for anchor in ['struct net_device_stats {','struct netdev_hw_addr_list {','struct netdev_tc_txq {',
                   'enum netdev_ml_priv_type {','enum netdev_stat_type {','enum netdev_reg_state {',
                   'enum bpf_xdp_mode {','struct bpf_xdp_entity {','enum rx_handler_result {']:
        header+=definition(nd,anchor,True)
    header+=line(nd,'typedef enum rx_handler_result rx_handler_result_t;')
    header+=line(nd,'typedef rx_handler_result_t rx_handler_func_t(')
    header+=definition('include/net/neighbour_tables.h','enum {',True)
    header+=definition(nd,'struct net_device {',True)
    header+='#undef NET_DEV_STAT\n'
    header+=definition('include/uapi/linux/if_ether.h','struct ethhdr {',True)
    for anchor in ['static inline unsigned char *skb_mac_header(', 'static inline void skb_reset_mac_header(', 'static inline void skb_reset_network_header(']:
        header+=definition(sk,anchor)
    header+='\n#include "compat/ethernet-linear.h"\n'
    header+=definition(sk,'static inline void * __must_check\n__skb_header_pointer(')
    header+=definition(sk,'static __always_inline void * __must_check\nskb_header_pointer(')
    header+=definition('include/linux/if_ether.h','static inline struct ethhdr *eth_hdr(')
    for anchor in ['static inline bool is_multicast_ether_addr(', 'static inline bool is_multicast_ether_addr_64bits(',
                   'static inline bool ether_addr_equal(', 'static inline bool ether_addr_equal_64bits(',
                   'static inline bool eth_proto_is_802_3(', 'static inline void eth_skb_pkt_type(',
                   'static inline struct ethhdr *eth_skb_pull_mac(']:
        header+=definition(ed,anchor)
    header+=definition('include/net/dsa.h','static inline bool netdev_uses_dsa(')
    header+='\n__be16 eth_type_trans(struct sk_buff *, struct net_device *) __asm__("ker_linux_eth_type_trans");\n'
    header+='__be16 eth_header_parse_protocol(const struct sk_buff *) __asm__("ker_linux_eth_header_parse_protocol");\n#pragma pop_macro("htons")\n#pragma pop_macro("__BIG_ENDIAN")\n#endif\n'
    source='net/ethernet/eth.c';body=texts[source][:texts[source].index('#include')]
    body+='\n#include "ker/linux_ethernet.h"\n#undef htons\n#define htons rte_cpu_to_be_16\n'
    body+=definition(source,'__be16 eth_type_trans(')
    body+=definition(source,'__be16 eth_header_parse_protocol(')
    configs=sorted(set(re.findall(r'\bCONFIG_[A-Z0-9_]+\b',header+body)))
    guard=''.join(f'#if defined({c}) || defined({c}_MODULE)\n#error Unsupported Ethernet configuration {c}\n#endif\n' for c in configs if not c.endswith('_MODULE'))
    # Tracker typedef is the exact original disabled branch; reject activation.
    guard+='#if defined(CONFIG_NET_DEV_REFCNT_TRACKER) || defined(CONFIG_NET_DEV_REFCNT_TRACKER_MODULE)\n#error Unsupported Ethernet configuration CONFIG_NET_DEV_REFCNT_TRACKER\n#endif\n'
    header=header.replace('#include "compat/ethernet-config.h"','#include "compat/ethernet-config.h"\n'+guard)
    (args.out/'ker').mkdir(parents=True,exist_ok=True)
    for path,value in [(args.out/'ker/linux_ethernet.h',header),(args.out/'linux_ethernet.c',body),
                       (args.out/'provenance.json',json.dumps(provenance,indent=2)+'\n')]:
        if not path.exists() or path.read_text()!=value:path.write_text(value)
if __name__=='__main__': main()
