#ifndef KER_RUNTIME_IPV4_PACKET_VIEW_H
#define KER_RUNTIME_IPV4_PACKET_VIEW_H
#include "runtime/skb.h"

/* Immutable IPv4 header view into a validated, classified skb. Header bytes
 * are borrowed until the skb is freed or mutated. frag_off remains wire-order;
 * lengths are host-order. Ethernet padding is excluded from packet_length. */
struct ker_ipv4_packet_view {
    const unsigned char *header;
    unsigned int header_length;
    unsigned int packet_length;
    unsigned int payload_length;
    uint16_t frag_off;
};

/* Validates a live unique skb owned by context, already classified as IPv4.
 * Does not mutate or consume it. No fragment reassembly or IP input pipeline. */
int ker_ipv4_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_ipv4_packet_view *result);
#endif
