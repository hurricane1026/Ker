#include "runtime/icmpv4-create.h"
#include "runtime/icmpv4-packet-view.h"
#include "runtime/ethernet.h"
#include <errno.h>
#include <net/checksum.h>

#define ICMPV4_HEADROOM 128U
#define ICMPV4_IP_HEADER 20U
#define ICMPV4_HEADER 8U

static bool valid_type_code(uint8_t type, uint8_t code)
{
    switch (type) {
    case 0: case 8: case 13: case 14: return code == 0;
    case 3: return code <= 15;
    case 5: return code <= 3;
    case 11: return code <= 1;
    case 12: return code <= 2;
    case 42: return code == 0;
    case 43: return code <= 4;
    default: return false;
    }
}

static int validate_rest(uint8_t type, uint8_t code,
    const unsigned char rest[4], const void *payload, unsigned int payload_length)
{
    if (!valid_type_code(type, code)) return -ENOTSUP;
    if (type == 13 || type == 14) return payload_length == 12 ? 0 : -EINVAL;
    if (type == 42) {
        if (rest[3] & 0xfeU) return -EINVAL;
        struct ker_icmpv4_packet_view packet = {
            .type = type, .payload = payload, .payload_length = payload_length,
        };
        struct ker_icmpv4_extended_echo_view request;
        packet.rest[3] = rest[3];
        memcpy(packet.rest, rest, 3);
        int error = ker_icmpv4_extended_echo_view_init(&packet, &request);
        if (error) return error;
        return request.address_reserved ? -EINVAL : 0;
    }
    if (type == 43) {
        if ((rest[3] & 0x18U) || (rest[3] >> 5) > 6 ||
            (code && rest[3]) || (!(rest[3] & 0x04U) && (rest[3] & 0x03U)))
            return -EINVAL;
        return payload_length ? -EINVAL : 0;
    }
    if (type == 11 && (rest[0] || rest[1] || rest[2] || rest[3])) return -EINVAL;
    if (type == 12 && code && (rest[0] || rest[1] || rest[2] || rest[3])) return -EINVAL;
    if (type == 12 && !code && (rest[1] || rest[2] || rest[3])) return -EINVAL;
    if (type == 3 && code == 4 && (rest[0] || rest[1])) return -EINVAL;
    if (type == 3 && code != 4 && (rest[0] || rest[1] || rest[2] || rest[3]))
        return -EINVAL;
    if (type == 5 || type == 3 || type == 11 || type == 12) {
        struct ker_icmpv4_quoted_ipv4_view quote;
        if (!payload && !payload_length) return -EINVAL;
        return ker_icmpv4_quoted_ipv4_view_init(payload, payload_length, &quote);
    }
    return 0;
}

int ker_icmpv4_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, uint8_t type, uint8_t code,
    const unsigned char rest[4], uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!context || !source_mac || !destination_mac || !rest || !result || !ttl ||
        (!payload && payload_length)) return -EINVAL;
    if (type == 43 && ttl != 255) return -EINVAL;
    uint64_t icmp_length64 = (uint64_t)ICMPV4_HEADER + payload_length;
    uint64_t ip_length64 = ICMPV4_IP_HEADER + icmp_length64;
    if (ip_length64 > UINT16_MAX) return -EMSGSIZE;
    int error = validate_rest(type, code, rest, payload, payload_length);
    if (error) return error;
    unsigned int icmp_length = (unsigned int)icmp_length64;
    unsigned int ip_length = (unsigned int)ip_length64;
    struct sk_buff *skb = NULL;
    error = ker_skb_alloc(context, ETH_HLEN + ip_length, ICMPV4_HEADROOM, &skb);
    if (error) return error;
    uint8_t *frame = NULL;
    error = ker_skb_put(skb, ETH_HLEN + ip_length, &frame);
    if (error) { BUG_ON(ker_skb_free(skb)); return error; }
    memcpy(frame, destination_mac, ETH_ALEN);
    memcpy(frame + ETH_ALEN, source_mac, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x00;
    unsigned char *ip = frame + ETH_HLEN;
    memset(ip, 0, ICMPV4_IP_HEADER);
    ip[0] = 0x45;
    if (type == 43) ip[6] = 0x40; /* RFC 8335 requires DF in the reply. */
    ip[2] = (unsigned char)(ip_length >> 8); ip[3] = (unsigned char)ip_length;
    ip[8] = ttl; ip[9] = 1;
    memcpy(ip + 12, &source_ip, sizeof(source_ip));
    memcpy(ip + 16, &destination_ip, sizeof(destination_ip));
    __sum16 sum = csum_fold(csum_partial(ip, ICMPV4_IP_HEADER, 0));
    memcpy(ip + 10, &sum, sizeof(sum));
    unsigned char *icmp = ip + ICMPV4_IP_HEADER;
    icmp[0] = type; icmp[1] = code; icmp[2] = icmp[3] = 0;
    memcpy(icmp + 4, rest, 4);
    if (payload_length) memcpy(icmp + ICMPV4_HEADER, payload, payload_length);
    sum = csum_fold(csum_partial(icmp, (int)icmp_length, 0));
    memcpy(icmp + 2, &sum, sizeof(sum));
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb); skb->network_header += ETH_HLEN;
    skb->transport_header = skb_headroom(skb) + ETH_HLEN + ICMPV4_IP_HEADER;
    skb->mac_len = ETH_HLEN;
    skb->protocol = rte_cpu_to_be_16(ETH_P_IP);
    *result = skb;
    return 0;
}

int ker_icmpv4_ipv4_error_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, uint8_t type, uint8_t code,
    const unsigned char rest[4], uint8_t ttl, const void *quoted_ipv4,
    unsigned int quoted_length, uint16_t path_mtu, struct sk_buff **result)
{
    if (type != 3 && type != 5 && type != 11 && type != 12) return -EINVAL;
    struct ker_icmpv4_quoted_ipv4_view quote;
    int error = ker_icmpv4_quoted_ipv4_view_init(quoted_ipv4, quoted_length, &quote);
    if (error) return error;
    unsigned int limit = path_mtu && path_mtu < 576 ? path_mtu : 576;
    if (limit < ICMPV4_IP_HEADER + ICMPV4_HEADER + quote.header_length)
        return -EMSGSIZE;
    unsigned int max_quote = limit - ICMPV4_IP_HEADER - ICMPV4_HEADER;
    unsigned int copy_length = quote.quoted_length < max_quote ? quote.quoted_length : max_quote;
    unsigned int minimum_quote = quote.header_length +
        (quote.total_length - quote.header_length < 8 ?
            quote.total_length - quote.header_length : 8);
    if (copy_length < minimum_quote) return -EMSGSIZE;
    return ker_icmpv4_ipv4_create(context, source_mac, destination_mac,
        source_ip, destination_ip, type, code, rest, ttl, quoted_ipv4,
        copy_length, result);
}
