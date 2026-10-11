#include "runtime/tcp-packet-view.h"
#include <errno.h>
#include <net/checksum.h>

int ker_tcp_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_tcp_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;

    struct ker_ipv4_packet_view ip;
    int error = ker_ipv4_packet_view_init(context, skb, &ip);
    if (error)
        return error;
    if (ip.header[9] != 6) /* IPPROTO_TCP */
        return -EPROTONOSUPPORT;

    /* MF and nonzero fragment offset require reassembly, outside this view. */
    if (rte_be_to_cpu_16(ip.frag_off) & 0x3fff)
        return -ENOTSUP;
    if (ip.payload_length < 20)
        return -EMSGSIZE;

    const unsigned char *tcp = ip.header + ip.header_length;
    unsigned int data_offset = tcp[12] >> 4;
    if (data_offset < 5)
        return -EINVAL;
    unsigned int tcp_header_length = data_offset * 4;
    if (tcp_header_length > ip.payload_length)
        return -EMSGSIZE;

    __be32 source, destination;
    memcpy(&source, ip.header + 12, sizeof(source));
    memcpy(&destination, ip.header + 16, sizeof(destination));
    /* Verify the complete segment including its checksum field. A wire zero
     * is not an omission marker for TCP; it is accepted only if arithmetic
     * over the full pseudoheader and segment validates it. */
    __wsum sum = csum_partial(tcp, (int)ip.payload_length, 0);
    if (csum_tcpudp_magic(source, destination, ip.payload_length, 6, sum) != 0)
        return -EBADMSG;

    uint16_t source_port, destination_port, checksum;
    memcpy(&source_port, tcp, sizeof(source_port));
    memcpy(&destination_port, tcp + 2, sizeof(destination_port));
    memcpy(&checksum, tcp + 16, sizeof(checksum));
    *result = (struct ker_tcp_packet_view){
        .header = tcp,
        .payload = tcp + tcp_header_length,
        .source_port = source_port,
        .destination_port = destination_port,
        .checksum = checksum,
        .tcp_header_length = tcp_header_length,
        .segment_length = ip.payload_length,
        .payload_length = ip.payload_length - tcp_header_length,
    };
    return 0;
}
