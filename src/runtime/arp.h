#ifndef KER_RUNTIME_ARP_H
#define KER_RUNTIME_ARP_H
#include "ker/linux_arp.h"
#include "runtime/ethernet.h"
/* Install original Ethernet create/parse_protocol operations on an existing
 * private device view. No registration, ARP receive, routing or neighbour state. */
int ker_arp_device_setup(struct ker_eth_device *device);
/* Original Linux ARP request/reply constructor, initialized memory worker only.
 * IP addresses in wire order. NULL destination selects broadcast; NULL source
 * selects device MAC; NULL target writes zero target MAC. All six-byte MAC
 * arrays are borrowed for this call. Reply requires destination and target.
 * Success returns one caller-owned skb with Ethernet header included; failure
 * leaves output untouched. No arp_xmit/NF_HOOK, PMD, padding or automatic reply. */
int ker_arp_create(struct ker_eth_device *device, unsigned int operation,
    __be32 source_ip, __be32 target_ip, const unsigned char *destination_mac,
    const unsigned char *source_mac, const unsigned char *target_mac,
    struct sk_buff **result);
#endif
