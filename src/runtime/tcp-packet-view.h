#ifndef KER_RUNTIME_TCP_PACKET_VIEW_H
#define KER_RUNTIME_TCP_PACKET_VIEW_H
#include "runtime/ipv4-packet-view.h"

/* TCP bytes and payload are borrowed until skb mutation/free. Ports and
 * checksum remain wire order; lengths are host order. Header options remain
 * opaque bytes: this view does not interpret TCP options or connection state. */
struct ker_tcp_packet_view {
    const unsigned char *header;
    const unsigned char *payload;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t checksum;
    unsigned int tcp_header_length;
    unsigned int segment_length;
    unsigned int payload_length;
};

/* Software-validates the complete TCP segment in an owned, classified,
 * unfragmented IPv4 skb. The TCP checksum is mandatory and always verified,
 * including a wire value of zero. Does not consume/deliver the packet. */
int ker_tcp_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_tcp_packet_view *result);
#endif
