#ifndef KER_RUNTIME_ICMPV4_CREATE_H
#define KER_RUNTIME_ICMPV4_CREATE_H
#include "runtime/skb.h"

/* Construct a typed ICMPv4 message over explicit Ethernet/IPv4 endpoints.
 * Address and rest fields are wire-order bytes. Payload is copied. This is a
 * packet constructor; callers emitting errors must apply ICMP suppression,
 * destination validity, routing and rate-limit policy separately. */
int ker_icmpv4_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, uint8_t type, uint8_t code,
    const unsigned char rest[4], uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);

/* Construct an ICMP error with a bounded quote. Quoted IPv4 bytes must begin
 * at the original IP header; capture padding is excluded at the call site.
 * The output IP length is bounded by min(path_mtu,576); a zero path_mtu
 * selects the 576-byte baseline. The service supplies its actual path limit. */
int ker_icmpv4_ipv4_error_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, uint8_t type, uint8_t code,
    const unsigned char rest[4], uint8_t ttl, const void *quoted_ipv4,
    unsigned int quoted_length, uint16_t path_mtu, struct sk_buff **result);
#endif
