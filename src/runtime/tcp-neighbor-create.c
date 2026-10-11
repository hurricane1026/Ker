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
