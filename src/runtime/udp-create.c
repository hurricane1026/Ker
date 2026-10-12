#include "runtime/udp-create.h"
#include "runtime/ethernet.h"
#include <net/checksum.h>
#include <errno.h>

#define KER_UDP_CREATE_HEADROOM 128U
#define IPV4_BASE_HEADER_LENGTH 20U
#define UDP_HEADER_LENGTH 8U
#define MAX_IPV4_OPTIONS_LENGTH 40U
#define KER_IPPROTO_UDP 17U

static void put_be16(unsigned char *p, unsigned int value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static int udp_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const struct ker_ipv4_header_fields *fields,
    const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result)
{
    if (!context || !source_mac || !destination_mac || !result || !ttl ||
        (!options && options_length) || (!payload && payload_length))
        return -EINVAL;
    if (options_length > MAX_IPV4_OPTIONS_LENGTH || (options_length & 3U))
        return -EINVAL;

    const unsigned int ip_header_length = IPV4_BASE_HEADER_LENGTH + options_length;
    const uint64_t ip_length_wide = (uint64_t)ip_header_length + UDP_HEADER_LENGTH +
        payload_length;
    if (ip_length_wide > UINT16_MAX)
        return -EMSGSIZE;
    int fields_error = ker_ipv4_header_fields_validate(fields);
    if (fields_error)
        return fields_error;
    const struct ker_ipv4_header_fields field_snapshot = *fields;

    const unsigned int udp_length = UDP_HEADER_LENGTH + payload_length;
    const unsigned int ip_length = (unsigned int)ip_length_wide;
    const unsigned int frame_length = ETH_HLEN + ip_length;
    struct sk_buff *skb = NULL;
    int error = ker_skb_alloc(context, frame_length, KER_UDP_CREATE_HEADROOM, &skb);
    if (error)
        return error;
    uint8_t *frame = NULL;
    error = ker_skb_put(skb, frame_length, &frame);
    if (error) {
        BUG_ON(ker_skb_free(skb));
        return error;
    }

    memcpy(frame, destination_mac, ETH_ALEN);
    memcpy(frame + ETH_ALEN, source_mac, ETH_ALEN);
    put_be16(frame + 12, ETH_P_IP);
    unsigned char *ip = frame + ETH_HLEN;
    memset(ip, 0, ip_header_length);
    ip[0] = (unsigned char)(0x40U | (ip_header_length / 4U));
    ker_ipv4_header_fields_apply(ip, &field_snapshot);
    put_be16(ip + 2, ip_length);
    ip[8] = ttl;
    ip[9] = KER_IPPROTO_UDP;
    memcpy(ip + 12, &source_ip, sizeof(source_ip));
    memcpy(ip + 16, &destination_ip, sizeof(destination_ip));
    if (options_length)
        memcpy(ip + IPV4_BASE_HEADER_LENGTH, options, options_length);
    __sum16 ip_checksum = csum_fold(csum_partial(ip, (int)ip_header_length, 0));
    memcpy(ip + 10, &ip_checksum, sizeof(ip_checksum));

    unsigned char *udp = ip + ip_header_length;
    memset(udp, 0, UDP_HEADER_LENGTH);
    memcpy(udp, &source_port, sizeof(source_port));
    memcpy(udp + 2, &destination_port, sizeof(destination_port));
    put_be16(udp + 4, udp_length);
    if (payload_length)
        memcpy(udp + UDP_HEADER_LENGTH, payload, payload_length);
    __wsum sum = csum_partial(udp, (int)udp_length, 0);
    __sum16 udp_checksum = csum_tcpudp_magic(source_ip, destination_ip,
        udp_length, KER_IPPROTO_UDP, sum);
    if (!udp_checksum)
        udp_checksum = CSUM_MANGLED_0;
    memcpy(udp + 6, &udp_checksum, sizeof(udp_checksum));

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb->network_header += ETH_HLEN;
    skb->transport_header = skb_headroom(skb) + ETH_HLEN + ip_header_length;
    skb->mac_len = ETH_HLEN;
    skb->protocol = rte_cpu_to_be_16(ETH_P_IP);
    *result = skb;
    return 0;
}

int ker_udp_ipv4_create_fields(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    return udp_create_fields(context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, ttl, fields, ip_options,
        ip_options_length, payload, payload_length, result);
}

int ker_udp_ipv4_create_ip_options(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result)
{
    const struct ker_ipv4_header_fields fields = {0};
    return udp_create_fields(context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, ttl, &fields, options,
        options_length, payload, payload_length, result);
}

int ker_udp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    return ker_udp_ipv4_create_ip_options(context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, ttl, NULL, 0,
        payload, payload_length, result);
}
