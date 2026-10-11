#ifndef KER_RUNTIME_TCP_CREATE_H
#define KER_RUNTIME_TCP_CREATE_H
#include "runtime/skb.h"

/* Build a caller-owned Ethernet + fixed IPv4/TCP packet with 128-byte
 * headroom. MACs are copied literally; IPs, ports, seq/ack and window are
 * wire order. Payload is copied and borrowed only for this call. TTL must be
 * nonzero. TCP flags are byte 13 (NS/reserved bits stay zero); URG is rejected
 * because urgent pointer is fixed zero. IP ID/DSCP/fragment fields and TCP
 * options are absent. Checksums are software-computed; a valid zero TCP
 * checksum remains zero. No address policy, routing, TCP state or TX offload
 * is provided. */
int ker_tcp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
