#ifndef KER_RUNTIME_UDP_PACKET_VIEW_H
#define KER_RUNTIME_UDP_PACKET_VIEW_H
#include "runtime/ipv4-packet-view.h"

/* UDP bytes and payload are borrowed until skb mutation/free. Ports/checksum
 * remain wire order; lengths are host order. No synthetic Linux udphdr is
 * introduced when that native header is not part of this compatibility port. */
struct ker_udp_packet_view {
    const unsigned char *header;
    const unsigned char *payload;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t checksum;
    unsigned int udp_length;
    unsigned int payload_length;
};

/* Software-validates a complete unfragmented IPv4 UDP datagram in a unique,
 * owned, classified linear skb. IPv4 UDP checksum zero is accepted as omitted.
 * Does not mutate/consume the skb or deliver it to a socket. */
int ker_udp_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_udp_packet_view *result);
#endif
