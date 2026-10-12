#include "runtime/icmp-echo-create.h"
#include "runtime/ethernet.h"
#include <net/checksum.h>
#include <errno.h>

#define ECHO_HEADROOM 128U
#define IP_BASE 20U
#define ICMP_ECHO_HEADER 8U

static void put_be16(unsigned char *p, unsigned int value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static int icmp_echo_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!context || !source_mac || !destination_mac || !result || !ttl ||
        (type != 0 && type != 8) || (!ip_options && ip_options_length) ||
        (!payload && payload_length))
        return -EINVAL;
    if (ip_options_length > 40 || (ip_options_length & 3U))
        return -EINVAL;
    uint64_t icmp_length_wide = (uint64_t)ICMP_ECHO_HEADER + payload_length;
    uint64_t ip_length_wide = (uint64_t)IP_BASE + ip_options_length + icmp_length_wide;
    if (ip_length_wide > UINT16_MAX)
        return -EMSGSIZE;
    int fields_error = ker_ipv4_header_fields_validate(fields);
    if (fields_error)
        return fields_error;
    unsigned int ip_header_length = IP_BASE + ip_options_length;
    unsigned int icmp_length = (unsigned int)icmp_length_wide;
    unsigned int ip_length = (unsigned int)ip_length_wide;
    unsigned int frame_length = ETH_HLEN + ip_length;
    struct sk_buff *skb = NULL;
    int error = ker_skb_alloc(context, frame_length, ECHO_HEADROOM, &skb);
    if (error)
        return error;
    uint8_t *frame = NULL;
    error = ker_skb_put(skb, frame_length, &frame);
    if (error) {
        BUG_ON(ker_skb_free(skb));
        return error;
    }
    memcpy(frame, destination_mac, 6);
    memcpy(frame + 6, source_mac, 6);
    put_be16(frame + 12, ETH_P_IP);
    unsigned char *ip = frame + ETH_HLEN;
    memset(ip, 0, ip_header_length);
    ip[0] = (unsigned char)(0x40U | (ip_header_length / 4U));
    ker_ipv4_header_fields_apply(ip, fields);
    put_be16(ip + 2, ip_length);
    ip[8] = ttl;
    ip[9] = 1;
    memcpy(ip + 12, &source_ip, sizeof(source_ip));
    memcpy(ip + 16, &destination_ip, sizeof(destination_ip));
    if (ip_options_length)
        memcpy(ip + IP_BASE, ip_options, ip_options_length);
    __sum16 ip_checksum = csum_fold(csum_partial(ip, (int)ip_header_length, 0));
    memcpy(ip + 10, &ip_checksum, sizeof(ip_checksum));

    unsigned char *icmp = ip + ip_header_length;
    memset(icmp, 0, ICMP_ECHO_HEADER);
    icmp[0] = type;
    memcpy(icmp + 4, &identifier, sizeof(identifier));
    memcpy(icmp + 6, &sequence, sizeof(sequence));
    if (payload_length)
        memcpy(icmp + ICMP_ECHO_HEADER, payload, payload_length);
    __sum16 icmp_checksum = csum_fold(csum_partial(icmp, (int)icmp_length, 0));
    memcpy(icmp + 2, &icmp_checksum, sizeof(icmp_checksum));

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb->network_header += ETH_HLEN;
    skb->transport_header = skb_headroom(skb) + ETH_HLEN + ip_header_length;
    skb->mac_len = ETH_HLEN;
    skb->protocol = rte_cpu_to_be_16(ETH_P_IP);
    *result = skb;
    return 0;
}

int ker_icmp_echo_ipv4_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    return icmp_echo_create_fields(context, source_mac, destination_mac,
        source_ip, destination_ip, identifier, sequence, type, ttl, fields,
        ip_options, ip_options_length, payload, payload_length, result);
}

int ker_icmp_echo_ipv4_create_ip_options(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl, const void *ip_options,
    unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    const struct ker_ipv4_header_fields fields = {0};
    return icmp_echo_create_fields(context, source_mac, destination_mac,
        source_ip, destination_ip, identifier, sequence, type, ttl, &fields,
        ip_options, ip_options_length, payload, payload_length, result);
}

int ker_icmp_echo_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[6], const unsigned char destination_mac[6],
    __be32 source_ip, __be32 destination_ip, __be16 identifier,
    __be16 sequence, uint8_t type, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    return ker_icmp_echo_ipv4_create_ip_options(context, source_mac, destination_mac,
        source_ip, destination_ip, identifier, sequence, type, ttl, NULL, 0,
        payload, payload_length, result);
}
