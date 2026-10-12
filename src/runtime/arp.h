#ifndef KER_RUNTIME_ARP_H
#define KER_RUNTIME_ARP_H
#include "ker/linux_arp.h"
#include "runtime/ethernet.h"
struct ker_neighbor_monitor;
struct ker_neighbor_event;
struct ker_ipv4_address;
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
/* Construct a request/reply from one live configured static IPv4 address.
 * Destination and target MACs are explicit six-byte borrowed inputs (requests
 * may use broadcast destination and an all-zero target). Source IP/MAC are
 * snapshotted from the associated device/address before allocation. Success
 * returns one caller-owned Ethernet+ARP skb; failure leaves output unchanged.
 * This selects no route, neighbor, ARP response, or NIC transmission. */
int ker_arp_create_configured(struct ker_ipv4_address *address,
    unsigned int operation, __be32 target_ip,
    const unsigned char destination_mac[ETH_ALEN],
    const unsigned char target_mac[ETH_ALEN], struct sk_buff **result);
/* Construct the native probe packet only for the exact active native-neighbor
 * probe callback. No NIC transmit occurs; success transfers one caller-owned skb. */
int ker_arp_probe_create(struct ker_neighbor_monitor *, const struct ker_neighbor_event *, struct sk_buff **result);
#endif
