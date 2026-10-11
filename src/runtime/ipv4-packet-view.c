#include "runtime/ipv4-packet-view.h"
#include "runtime/ethernet.h"
#include <errno.h>
#include <net/checksum.h>

int ker_ipv4_packet_view_init(struct ker_skb_context *context,
    struct sk_buff *skb, struct ker_ipv4_packet_view *result)
{
    if (!context || !skb || !result)
        return -EINVAL;
    int error = ker_skb_validate(skb, context);
    if (error)
        return error;
    if (skb_shared(skb) || skb_cloned(skb))
        return -EBUSY;
    if (skb_is_nonlinear(skb))
        return -ENOTSUP;
    if (skb->protocol != rte_cpu_to_be_16(ETH_P_IP))
        return -EPROTONOSUPPORT;
    if (!skb->dev || !skb_mac_header_was_set(skb) ||
        skb->mac_header > skb->network_header ||
        skb->network_header - skb->mac_header != ETH_HLEN ||
        skb->network_header != skb_headroom(skb) ||
        skb->head + skb->network_header != skb->data)
        return -EINVAL;
    if (((uintptr_t)skb->data & 1) != 0)
        return -EINVAL;
    if (skb->len < 20)
        return -EMSGSIZE;

    const unsigned char *header = skb->data;
    unsigned int version = header[0] >> 4;
    unsigned int ihl = header[0] & 0x0f;
    if (version != 4 || ihl < 5)
        return -EINVAL;
    unsigned int header_length = ihl * 4;
    if (header_length > skb->len)
        return -EMSGSIZE;
    unsigned int packet_length = ((unsigned int)header[2] << 8) | header[3];
    if (packet_length < header_length)
        return -EINVAL;
    if (packet_length > skb->len)
        return -EMSGSIZE;
    /* The pinned Linux ip_fast_csum implementation validates the complete
     * header, including options. Its target access requires aligned input. */
    if (ip_fast_csum(header, ihl) != 0)
        return -EBADMSG;

    uint16_t frag_off;
    memcpy(&frag_off, header + 6, sizeof(frag_off));
    *result = (struct ker_ipv4_packet_view){
        .header = header,
        .header_length = header_length,
        .packet_length = packet_length,
        .payload_length = packet_length - header_length,
        .frag_off = frag_off,
    };
    return 0;
}
