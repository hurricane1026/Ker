#include "runtime/icmp-echo-packet-view.h"
#include <errno.h>
#include <net/checksum.h>

int ker_icmp_echo_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_icmp_echo_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;
    struct ker_ipv4_packet_view ip;
    int error = ker_ipv4_packet_view_init(context, skb, &ip);
    if (error)
        return error;
    if (ip.header[9] != 1)
        return -EPROTONOSUPPORT;
    if ((ip.header[6] & 0x3fU) || ip.header[7])
        return -ENOTSUP;
    if (ip.payload_length < 8)
        return -EMSGSIZE;

    const unsigned char *icmp = ip.header + ip.header_length;
    if (icmp[0] != 0 && icmp[0] != 8)
        return -ENOTSUP;
    if (icmp[1] != 0)
        return -EINVAL;
    if (csum_fold(csum_partial(icmp, (int)ip.payload_length, 0)) != 0)
        return -EBADMSG;

    struct ker_icmp_echo_packet_view value = {
        .header = icmp,
        .payload = icmp + 8,
        .type = icmp[0],
        .code = icmp[1],
        .icmp_checksum = 0,
        .identifier = 0,
        .sequence = 0,
        .icmp_length = ip.payload_length,
        .payload_length = ip.payload_length - 8,
    };
    memcpy(&value.icmp_checksum, icmp + 2, sizeof(value.icmp_checksum));
    memcpy(&value.identifier, icmp + 4, sizeof(value.identifier));
    memcpy(&value.sequence, icmp + 6, sizeof(value.sequence));
    *result = value;
    return 0;
}
