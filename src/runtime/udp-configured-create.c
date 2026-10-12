#include "runtime/udp-create.h"
#include "runtime/configured-packet.h"
#include "runtime/ethernet.h"
#include <errno.h>

#define IPV4_BASE_HEADER_LENGTH 20U
#define UDP_HEADER_LENGTH 8U
#define MAX_IPV4_OPTIONS_LENGTH 40U

static int validate_args(const unsigned char destination_mac[ETH_ALEN], uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    if (!destination_mac || !result || !ttl || (!ip_options && ip_options_length) ||
        (!payload && payload_length))
        return -EINVAL;
    if (ip_options_length > MAX_IPV4_OPTIONS_LENGTH || (ip_options_length & 3U))
        return -EINVAL;
    uint64_t length = IPV4_BASE_HEADER_LENGTH + (uint64_t)ip_options_length +
        UDP_HEADER_LENGTH + payload_length;
    return length > UINT16_MAX ? -EMSGSIZE : 0;
}

static int configured_create(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    int error = validate_args(destination_mac, ttl, ip_options, ip_options_length,
        payload, payload_length, result);
    if (error) return error;
    error = ker_ipv4_header_fields_validate(fields);
    if (error) return error;
    const struct ker_ipv4_header_fields profile =
        ker_ipv4_header_fields_snapshot(fields);
    unsigned char destination_snapshot[ETH_ALEN];
    memcpy(destination_snapshot, destination_mac, ETH_ALEN);

    struct ker_configured_packet_source source;
    error = ker_configured_packet_source_snapshot(address, destination_snapshot, &source);
    if (error) return error;
    return ker_udp_ipv4_create_fields(source.context, source.source_mac,
        source.destination_mac, source.source_ip, destination_ip, source_port,
        destination_port, ttl, &profile, ip_options, ip_options_length,
        payload, payload_length, result);
}

int ker_udp_ipv4_create_configured(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    const struct ker_ipv4_header_fields zero_profile = {0};
    return configured_create(address, destination_mac, destination_ip,
        source_port, destination_port, ttl, &zero_profile, ip_options,
        ip_options_length, payload, payload_length, result);
}

int ker_udp_ipv4_create_configured_fields(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    return configured_create(address, destination_mac, destination_ip,
        source_port, destination_port, ttl, fields, ip_options,
        ip_options_length, payload, payload_length, result);
}
