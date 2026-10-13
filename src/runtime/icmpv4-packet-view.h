#ifndef KER_RUNTIME_ICMPV4_PACKET_VIEW_H
#define KER_RUNTIME_ICMPV4_PACKET_VIEW_H
#include "runtime/ipv4-packet-view.h"

/* Borrowed view of a complete, validated ICMPv4 message. Lengths are host
 * order; all byte fields retain wire representation. */
struct ker_icmpv4_packet_view {
    const unsigned char *header;
    const unsigned char *payload;
    uint8_t type;
    uint8_t code;
    __be16 checksum;
    unsigned char rest[4];
    unsigned int message_length;
    unsigned int payload_length;
    const unsigned char *quoted_ipv4;
    unsigned int quoted_length;
    const unsigned char *extension;
    unsigned int extension_length;
};

/* Accepts modern Linux ICMPv4 types/codes implemented by Ker: echo 0/8 code
 * 0, destination unreachable 3 codes 0..15, redirect 5 codes 0..3, time
 * exceeded 11 codes 0..1, parameter problem 12 codes 0..2, timestamp
 * 13/14 code 0, RFC 8335 extended echo request 42, and reply 43 codes 0..4.
 * Type 42 Code is ignored as specified by RFC 8335. Other values are
 * explicitly unsupported. */
int ker_icmpv4_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_icmpv4_packet_view *result);

/* A bounded view of the IPv4 header and quoted transport prefix carried by
 * ICMP errors. `available` is the quote length, which can be shorter than the
 * original IPv4 total length. `flow_available` is set only for an initial
 * fragment and an eight-byte transport prefix. */
struct ker_icmpv4_quoted_ipv4_view {
    const unsigned char *header;
    const unsigned char *transport;
    unsigned int header_length;
    unsigned int quoted_length;
    unsigned int transport_length;
    uint16_t total_length;
    uint16_t fragment_offset;
    uint8_t protocol;
    bool flow_available;
};

int ker_icmpv4_quoted_ipv4_view_init(const unsigned char *bytes,
    unsigned int available, struct ker_icmpv4_quoted_ipv4_view *result);

/* RFC 8335 request metadata and its one interface-identification object.
 * identifier_data is borrowed from the packet; address data includes only
 * significant address bytes, name data excludes zero padding. */
struct ker_icmpv4_extended_echo_view {
    __be16 identifier;
    uint8_t sequence;
    uint8_t local;
    uint8_t object_type;
    uint8_t address_reserved;
    const unsigned char *identifier_data;
    unsigned int identifier_length;
};

int ker_icmpv4_extended_echo_view_init(
    const struct ker_icmpv4_packet_view *packet,
    struct ker_icmpv4_extended_echo_view *result);
#endif
