#ifndef KER_RUNTIME_UDP_CREATE_H
#define KER_RUNTIME_UDP_CREATE_H
#include "runtime/skb.h"
#include "runtime/ipv4-fields.h"
struct ker_ipv4_address;

/* Construct a caller-owned Ethernet + fixed 20-byte IPv4 + UDP packet.
 * Addresses and ports are in wire order; payload is copied and borrowed only for this call.
 * A fixed 128-byte headroom is retained. TTL must be nonzero. DSCP/ECN, IP ID,
 * and fragment fields are zero. The constructor sets no TX offload metadata
 * and performs no address policy or routing. */
int ker_udp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
/* As above with a 20..60-byte IPv4 header. The optional 0..40-byte option area
 * is copied byte-for-byte but is not interpreted, normalized, or executed;
 * its length must be a multiple of four and a nonzero length requires options. */
int ker_udp_ipv4_create_ip_options(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result);
/* As above with a required copied IPv4 field profile. The DS byte is opaque;
 * identification and permitted zero/DF fragment field are in wire order. */
int ker_udp_ipv4_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);

/* Build with one live configured static IPv4 address on an Ethernet device.
 * Source IP/MAC are snapshotted from that association; destination MAC/IP and
 * ports are copied literally, with no neighbor lookup, subnet decision, FIB or
 * routing. The 0..40-byte IPv4 option area is opaque and copied as supplied.
 * A fixed 128-byte headroom is retained. Failure leaves result unchanged. */
int ker_udp_ipv4_create_configured(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result);
int ker_udp_ipv4_create_configured_fields(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result);
#endif
