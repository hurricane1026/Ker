#include "runtime/tcp-mss.h"
#include <ker/linux_tcp_mss.h>
#include <errno.h>
#include <string.h>

int ker_tcp_syn_mss(struct ker_skb_context *context, struct sk_buff *skb,
                    uint16_t user_mss, uint16_t *result)
{
    if (!result) return -EINVAL;
    struct ker_tcp_packet_view view;
    int error = ker_tcp_packet_view_init(context, skb, &view);
    if (error) return error;
    if (!(view.flags & KER_TCP_SYN)) return -EINVAL;
    /* Linux accesses tcphdr bitfields; never cast the possibly unaligned
     * borrowed packet bytes to a native header. */
    union {
        struct tcphdr header;
        unsigned char bytes[60];
    } copy = {0};
    _Static_assert(sizeof(struct tcphdr) == 20, "native TCP header size");
    memcpy(copy.bytes, view.header, view.tcp_header_length);
    *result = ker_linux_tcp_parse_mss_option(&copy.header, user_mss);
    return 0;
}
