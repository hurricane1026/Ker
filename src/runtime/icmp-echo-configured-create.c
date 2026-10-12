#include "runtime/icmp-echo-create.h"
#include "runtime/configured-packet.h"
#include <errno.h>

#define IP_BASE_LENGTH 20U
#define ICMP_HEADER_LENGTH 8U
#define MAX_IP_OPTIONS 40U

static int validate_args(const unsigned char *destination_mac, uint8_t type,
    uint8_t ttl, const void *options, unsigned int options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    if (!destination_mac || !result || !ttl || (type != 0 && type != 8) ||
        (!options && options_length) || (!payload && payload_length))
        return -EINVAL;
    if (options_length > MAX_IP_OPTIONS || (options_length & 3U)) return -EINVAL;
    uint64_t ip_length = IP_BASE_LENGTH + (uint64_t)options_length +
        ICMP_HEADER_LENGTH + payload_length;
    return ip_length > UINT16_MAX ? -EMSGSIZE : 0;
}

static int configured_create(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 identifier, __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *options,
    unsigned int options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    int error = validate_args(destination_mac, type, ttl, options,
        options_length, payload, payload_length, result);
    if (error) return error;
    error = ker_ipv4_header_fields_validate(fields);
    if (error) return error;
    const struct ker_ipv4_header_fields profile =
        ker_ipv4_header_fields_snapshot(fields);
    unsigned char destination_snapshot[ETH_ALEN];
    memcpy(destination_snapshot, destination_mac, ETH_ALEN);
    struct ker_configured_packet_source source;
    error = ker_configured_packet_source_snapshot(address, destination_snapshot,
        &source);
    if (error) return error;
    return ker_icmp_echo_ipv4_create_fields(source.context, source.source_mac,
        source.destination_mac, source.source_ip, destination_ip, identifier,
        sequence, type, ttl, &profile, options, options_length, payload,
        payload_length, result);
}

int ker_icmp_echo_ipv4_create_configured(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 identifier, __be16 sequence, uint8_t type, uint8_t ttl,
    const void *options, unsigned int options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    const struct ker_ipv4_header_fields zero_profile = {0};
    return configured_create(address, destination_mac, destination_ip,
        identifier, sequence, type, ttl, &zero_profile, options,
        options_length, payload, payload_length, result);
}

int ker_icmp_echo_ipv4_create_configured_fields(struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN], __be32 destination_ip,
    __be16 identifier, __be16 sequence, uint8_t type, uint8_t ttl,
    const struct ker_ipv4_header_fields *fields, const void *options,
    unsigned int options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    return configured_create(address, destination_mac, destination_ip,
        identifier, sequence, type, ttl, fields, options, options_length,
        payload, payload_length, result);
}
