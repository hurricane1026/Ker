#include "runtime/tcp-neighbor-create.h"
#include "runtime/neighbor-packet.h"
#include <errno.h>

int ker_tcp_ipv4_create_neighbor(struct ker_neighbor_table *table, __be32 destination_ip,
    __be16 source_port, __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result)
{
    if (!result || !ttl || (!options && options_length) || (!payload && payload_length))
        return -EINVAL;
    struct ker_neighbor_packet_source snapshot;
    int error = ker_neighbor_packet_source_snapshot(table, destination_ip, &snapshot);
    if (error)
        return error;
    return ker_tcp_ipv4_create_options(snapshot.context, snapshot.source_mac,
        snapshot.destination_mac, snapshot.source_ip, destination_ip, source_port,
        destination_port, sequence, acknowledgment, window, flags, ttl, options,
        options_length, payload, payload_length, result);
}

int ker_tcp_ipv4_create_neighbor_headers(struct ker_neighbor_table *table,
    __be32 destination_ip, __be16 source_port, __be16 destination_port,
    __be32 sequence, __be32 acknowledgment, __be16 window, uint8_t flags,
    uint8_t ttl, const void *ip_options, unsigned int ip_options_length,
    const void *tcp_options, unsigned int tcp_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!result || !ttl || (!ip_options && ip_options_length) ||
        (!tcp_options && tcp_options_length) || (!payload && payload_length))
        return -EINVAL;
    if (flags & 0x20U)
        return -ENOTSUP;
    if (ip_options_length > 40 || (ip_options_length & 3U) ||
        tcp_options_length > 40 || (tcp_options_length & 3U))
        return -EINVAL;
    uint64_t ip_length = 20U + (uint64_t)ip_options_length + 20U +
        tcp_options_length + payload_length;
    if (ip_length > UINT16_MAX)
        return -EMSGSIZE;

    struct ker_neighbor_packet_source snapshot;
    int error = ker_neighbor_packet_source_snapshot(table, destination_ip, &snapshot);
    if (error)
        return error;
    return ker_tcp_ipv4_create_headers(snapshot.context, snapshot.source_mac,
        snapshot.destination_mac, snapshot.source_ip, destination_ip, source_port,
        destination_port, sequence, acknowledgment, window, flags, ttl, ip_options,
        ip_options_length, tcp_options, tcp_options_length, payload, payload_length,
        result);
}

int ker_tcp_ipv4_create_neighbor_fields(struct ker_neighbor_table *table,
    __be32 destination_ip, __be16 source_port, __be16 destination_port,
    __be32 sequence, __be32 acknowledgment, __be16 window, uint8_t flags,
    uint8_t ttl, const struct ker_ipv4_header_fields *fields,
    const void *ip_options, unsigned int ip_options_length,
    const void *tcp_options, unsigned int tcp_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    if (!result || !ttl || (!ip_options && ip_options_length) ||
        (!tcp_options && tcp_options_length) || (!payload && payload_length))
        return -EINVAL;
    if (flags & 0x20U)
        return -ENOTSUP;
    if (ip_options_length > 40 || (ip_options_length & 3U) ||
        tcp_options_length > 40 || (tcp_options_length & 3U))
        return -EINVAL;
    uint64_t ip_length = 20U + (uint64_t)ip_options_length + 20U +
        tcp_options_length + payload_length;
    if (ip_length > UINT16_MAX)
        return -EMSGSIZE;
    int error = ker_ipv4_header_fields_validate(fields);
    if (error)
        return error;
    const struct ker_ipv4_header_fields profile =
        ker_ipv4_header_fields_snapshot(fields);

    struct ker_neighbor_packet_source snapshot;
    error = ker_neighbor_packet_source_snapshot(table, destination_ip, &snapshot);
    if (error)
        return error;
    return ker_tcp_ipv4_create_fields(snapshot.context, snapshot.source_mac,
        snapshot.destination_mac, snapshot.source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, flags,
        ttl, &profile, ip_options, ip_options_length, tcp_options,
        tcp_options_length, payload, payload_length, result);
}
