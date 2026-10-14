#ifndef KER_RUNTIME_TCP_PACKET_VIEW_H
#define KER_RUNTIME_TCP_PACKET_VIEW_H
#include "runtime/ipv4-packet-view.h"

/* TCP bytes and payload are borrowed until skb mutation/free. Ports and
 * checksum remain wire order; lengths and control fields are host order.
 * Header options remain opaque bytes: this view does not interpret TCP options or connection state. */
enum ker_tcp_flags {
    KER_TCP_FIN = 0x001, KER_TCP_SYN = 0x002, KER_TCP_RST = 0x004,
    KER_TCP_PSH = 0x008, KER_TCP_ACK = 0x010, KER_TCP_URG = 0x020,
    KER_TCP_ECE = 0x040, KER_TCP_CWR = 0x080, KER_TCP_AE = 0x100,
};
struct ker_tcp_packet_view {
    const unsigned char *header;
    const unsigned char *payload;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t checksum;
    unsigned int tcp_header_length;
    unsigned int segment_length;
    unsigned int payload_length;
    uint32_t sequence, acknowledgment;
    /* Modulo 2^32: payload bytes plus one each for SYN and FIN. This is
     * descriptive only; a connection state machine must validate the flags. */
    uint32_t end_sequence;
    uint16_t flags, window, urgent_pointer;
};

/* Software-validates the complete TCP segment in an owned, classified,
 * unfragmented IPv4 skb. The TCP checksum is mandatory and always verified,
 * including a wire value of zero. Does not consume/deliver the packet. */
int ker_tcp_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_tcp_packet_view *result);
#endif
