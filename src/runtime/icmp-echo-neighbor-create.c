#include "runtime/icmp-echo-neighbor-create.h"
#include "runtime/neighbor-packet.h"
#include <errno.h>

int ker_icmp_echo_ipv4_create_neighbor_ip_options(struct ker_neighbor_table *table,
    __be32 destination_ip, __be16 identifier, __be16 sequence, uint8_t type,
    uint8_t ttl, const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result)
{
    if (!result || !ttl || (type != 0 && type != 8) ||
        (!ip_options && ip_options_length) || (!payload && payload_length))
        return -EINVAL;
    if (ip_options_length > 40 || (ip_options_length & 3U))
        return -EINVAL;
    uint64_t ip_length = 20U + (uint64_t)ip_options_length + 8U + payload_length;
    if (ip_length > UINT16_MAX)
        return -EMSGSIZE;

    struct ker_neighbor_packet_source snapshot;
    int error = ker_neighbor_packet_source_snapshot(table, destination_ip, &snapshot);
    if (error)
        return error;
    return ker_icmp_echo_ipv4_create_ip_options(snapshot.context,
        snapshot.source_mac, snapshot.destination_mac, snapshot.source_ip,
        destination_ip, identifier, sequence, type, ttl, ip_options,
        ip_options_length, payload, payload_length, result);
}
