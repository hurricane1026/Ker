#include "runtime/udp-neighbor-create.h"
#include "runtime/neighbor-packet.h"
#include <errno.h>

int ker_udp_ipv4_create_neighbor(struct ker_neighbor_table *table, __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!result || !ttl ||
        (!payload && payload_length))
        return -EINVAL;
    struct ker_neighbor_packet_source snapshot;
    int error = ker_neighbor_packet_source_snapshot(table, destination_ip, &snapshot);
    if (error)
        return error;
    return ker_udp_ipv4_create(snapshot.context, snapshot.source_mac, snapshot.destination_mac,
        snapshot.source_ip, destination_ip, source_port, destination_port,
        ttl, payload, payload_length, result);
}
