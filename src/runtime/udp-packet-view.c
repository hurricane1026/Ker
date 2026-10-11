#include "runtime/udp-packet-view.h"
#include <errno.h>
#include <net/checksum.h>

int ker_udp_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_udp_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;
    struct ker_ipv4_packet_view ip;
    int error = ker_ipv4_packet_view_init(context, skb, &ip);
    if (error)
        return error;
    if (ip.header[9] != 17) /* IPPROTO_UDP */
        return -EPROTONOSUPPORT;

    /* MF (bit 13) and the 13-bit fragment offset require reassembly, which
     * this view does not provide. DF is permitted. frag_off is wire-order. */
    uint16_t fragment = rte_be_to_cpu_16(ip.frag_off);
    if (fragment & 0x3fff)
        return -ENOTSUP;
    if (ip.payload_length < 8)
        return -EMSGSIZE;

    const unsigned char *udp = ip.header + ip.header_length;
    unsigned int udp_length = ((unsigned int)udp[4] << 8) | udp[5];
    if (udp_length < 8 || udp_length != ip.payload_length)
        return -EINVAL;
    uint16_t checksum;
    memcpy(&checksum, udp + 6, sizeof(checksum));
    if (checksum) {
        __be32 source, destination;
        memcpy(&source, ip.header + 12, sizeof(source));
        memcpy(&destination, ip.header + 16, sizeof(destination));
        /* Verify the checksum including its wire field against the IPv4
         * pseudoheader. Do not trust RX checksum metadata to bypass software. */
        __wsum sum = csum_partial(udp, (int)udp_length, 0);
        if (csum_tcpudp_magic(source, destination, udp_length, 17, sum) != 0)
            return -EBADMSG;
    }

    uint16_t source_port, destination_port;
    memcpy(&source_port, udp, sizeof(source_port));
    memcpy(&destination_port, udp + 2, sizeof(destination_port));
    *result = (struct ker_udp_packet_view){
        .header = udp,
        .payload = udp + 8,
        .source_port = source_port,
        .destination_port = destination_port,
        .checksum = checksum,
        .udp_length = udp_length,
        .payload_length = udp_length - 8,
    };
    return 0;
}
