#ifndef KER_RUNTIME_ICMP_ECHO_CREATE_H
#define KER_RUNTIME_ICMP_ECHO_CREATE_H
#include "runtime/skb.h"

/* Explicit-address Ethernet/IPv4 ICMP echo request/reply constructor. MACs,
 * IPs, identifier and sequence are wire order. Payload/options are borrowed
 * for the call and copied. No routing, automatic reply, ping, socket or NIC. */
int ker_icmp_echo_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);

/* As above with opaque copied IPv4 options, 0..40 bytes in multiples of four. */
int ker_icmp_echo_ipv4_create_ip_options(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
