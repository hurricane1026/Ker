#ifndef KER_RUNTIME_ICMP_ECHO_PACKET_VIEW_H
#define KER_RUNTIME_ICMP_ECHO_PACKET_VIEW_H
#include "runtime/ipv4-packet-view.h"

/* ICMP echo header/payload are borrowed until skb mutation/free. Type, code,
 * identifier, sequence and checksum retain wire values; lengths are host order. */
struct ker_icmp_echo_packet_view {
    const unsigned char *header;
    const unsigned char *payload;
    uint8_t type;
    uint8_t code;
    __be16 icmp_checksum;
    __be16 identifier;
    __be16 sequence;
    unsigned int icmp_length;
    unsigned int payload_length;
};

/* Validates a classified, uniquely-owned linear IPv4 ICMP echo request/reply:
 * code must be zero, only types 0/8 are admitted, and the complete ICMP
 * message checksum is verified without a pseudoheader. IPv4 Ethernet padding
 * is excluded by the parent view. Fragment reassembly and other ICMP types
 * are unsupported. */
int ker_icmp_echo_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_icmp_echo_packet_view *result);
#endif
