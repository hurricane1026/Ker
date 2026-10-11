#ifndef KER_RUNTIME_UDP_CREATE_H
#define KER_RUNTIME_UDP_CREATE_H
#include "runtime/skb.h"

/* Construct a caller-owned Ethernet + IPv4 + UDP packet. Addresses and ports
 * are in wire order; payload is copied and borrowed only for this call. A
 * fixed 128-byte headroom is retained. TTL must be nonzero. DSCP/ECN, IP ID,
 * and fragment fields are zero. The constructor sets no TX offload metadata
 * and performs no address policy or routing. */
int ker_udp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
