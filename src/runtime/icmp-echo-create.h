#ifndef KER_RUNTIME_ICMP_ECHO_CREATE_H
#define KER_RUNTIME_ICMP_ECHO_CREATE_H
#include "runtime/skb.h"
#include "runtime/ipv4-fields.h"
struct ker_ipv4_address;

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
/* As above with a required copied IPv4 field profile. DS is opaque, ID is
 * copied verbatim, and frag_off is restricted to zero or DF. */
int ker_icmp_echo_ipv4_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
/* Configured-source variants snapshot source IPv4/MAC from one live
 * single-address Ethernet device and use destination MAC/IP literally. Only
 * echo request/reply types (8/0) are supported. Options are opaque copied
 * bytes; checksums cover the full IPv4 and ICMP messages. No neighbor lookup,
 * routing, automatic reply, socket delivery or NIC/offload path is provided. */
int ker_icmp_echo_ipv4_create_configured(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 identifier, __be16 sequence, uint8_t type, uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result);
int ker_icmp_echo_ipv4_create_configured_fields(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 identifier, __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
