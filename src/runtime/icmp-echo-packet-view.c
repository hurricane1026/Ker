#include "runtime/icmp-echo-packet-view.h"
#include "runtime/icmpv4-packet-view.h"
#include <errno.h>

int ker_icmp_echo_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_icmp_echo_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;
    struct ker_icmpv4_packet_view icmp;
    int error = ker_icmpv4_packet_view_init(context, skb, &icmp);
    if (error)
        return error;
    if (icmp.type != 0 && icmp.type != 8)
        return -ENOTSUP;

    struct ker_icmp_echo_packet_view value = {
        .header = icmp.header,
        .payload = icmp.payload,
        .type = icmp.type,
        .code = icmp.code,
        .icmp_checksum = icmp.checksum,
        .identifier = 0,
        .sequence = 0,
        .icmp_length = icmp.message_length,
        .payload_length = icmp.payload_length,
    };
    memcpy(&value.identifier, icmp.header + 4, sizeof(value.identifier));
    memcpy(&value.sequence, icmp.header + 6, sizeof(value.sequence));
    *result = value;
    return 0;
}
