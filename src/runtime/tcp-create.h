#ifndef KER_RUNTIME_TCP_CREATE_H
#define KER_RUNTIME_TCP_CREATE_H
#include "runtime/skb.h"
#include "runtime/ipv4-fields.h"
struct ker_ipv4_address;

/* Build caller-owned Ethernet + fixed IPv4 and TCP headers with 128-byte headroom.
 * MACs are copied literally; IPs, ports, seq/ack and window are wire order.
 * Payload and opaque TCP option bytes are copied and borrowed only for this
 * call. The options API uses a 20..60-byte TCP header; the legacy API uses
 * exactly 20-byte IPv4 and TCP headers. Options must be 0..40 bytes, a
 * multiple of four, and non-NULL when nonempty; they are not interpreted. TTL must be nonzero. TCP flags are byte
 * 13 (NS/reserved bits stay zero); URG is rejected because urgent pointer is
 * fixed zero. IP ID/DSCP/fragment fields and IP options are absent. Checksums
 * are software-computed; a valid zero TCP checksum remains zero. No address
 * policy, routing, TCP state or TX offload is provided. */
int ker_tcp_ipv4_create_options(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result);
/* As above with independently supplied opaque IPv4 and TCP option bytes.
 * Each length is 0..40, a multiple of four, and requires a non-NULL pointer
 * when nonzero. Neither option area is interpreted or executed. The resulting
 * IPv4 header is 20..60 bytes and TCP header is 20..60 bytes. */
int ker_tcp_ipv4_create_headers(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *ip_options,
    unsigned int ip_options_length, const void *tcp_options,
    unsigned int tcp_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
/* As above with a required copied IPv4 field profile. DS is opaque, ID is
 * copied verbatim, and frag_off is restricted to zero or DF. */
int ker_tcp_ipv4_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *tcp_options,
    unsigned int tcp_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
int ker_tcp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
/* Configured-source variants snapshot the source address/device MAC from one
 * live single-address Ethernet device and use the destination MAC/IP literally.
 * Both option areas are opaque copied bytes (0..40, multiple of four); TTL is
 * nonzero and URG is unsupported because urgent pointer is zero. TCP checksum
 * zero is preserved. Allocation is transactional. No neighbour lookup,
 * routing, TCP state, socket delivery or NIC/offload path is provided. */
int ker_tcp_ipv4_create_configured(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, __be32 sequence,
    __be32 acknowledgment, __be16 window, uint8_t flags, uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length,
    const void *tcp_options, unsigned int tcp_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result);
/* As above with a required copied IPv4 field profile. */
int ker_tcp_ipv4_create_configured_fields(struct ker_ipv4_address *address,
    const unsigned char destination_mac[6], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, __be32 sequence,
    __be32 acknowledgment, __be16 window, uint8_t flags, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *tcp_options,
    unsigned int tcp_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
