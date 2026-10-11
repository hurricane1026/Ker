#include "runtime/udp-create.h"
#include "runtime/ethernet.h"
#include <net/checksum.h>
#include <errno.h>

#define KER_UDP_CREATE_HEADROOM 128U
#define IPV4_HEADER_LENGTH 20U
#define UDP_HEADER_LENGTH 8U
#define MAX_UDP_PAYLOAD (UINT16_MAX - IPV4_HEADER_LENGTH - UDP_HEADER_LENGTH)
#define KER_IPPROTO_UDP 17U

static void put_be16(unsigned char *p, unsigned int value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

int ker_udp_ipv4_create(struct ker_skb_context *context,
    const unsigned char source_mac[ETH_ALEN], const unsigned char destination_mac[ETH_ALEN],
    __be32 source_ip, __be32 destination_ip, __be16 source_port,
    __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!context || !source_mac || !destination_mac || !result || !ttl ||
        (!payload && payload_length))
        return -EINVAL;
    if (payload_length > MAX_UDP_PAYLOAD)
        return -EMSGSIZE;

    const unsigned int udp_length = UDP_HEADER_LENGTH + payload_length;
    const unsigned int ip_length = IPV4_HEADER_LENGTH + udp_length;
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
    memset(ip, 0, IPV4_HEADER_LENGTH);
    ip[0] = 0x45;
    put_be16(ip + 2, ip_length);
    ip[8] = ttl;
    ip[9] = KER_IPPROTO_UDP;
    memcpy(ip + 12, &source_ip, sizeof(source_ip));
    memcpy(ip + 16, &destination_ip, sizeof(destination_ip));
    __sum16 ip_checksum = csum_fold(csum_partial(ip, IPV4_HEADER_LENGTH, 0));
    memcpy(ip + 10, &ip_checksum, sizeof(ip_checksum));

    unsigned char *udp = ip + IPV4_HEADER_LENGTH;
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
    skb->transport_header = skb_headroom(skb) + ETH_HLEN + IPV4_HEADER_LENGTH;
    skb->mac_len = ETH_HLEN;
    skb->protocol = rte_cpu_to_be_16(ETH_P_IP);
    *result = skb;
    return 0;
}
