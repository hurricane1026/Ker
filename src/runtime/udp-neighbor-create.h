#ifndef KER_RUNTIME_UDP_NEIGHBOR_CREATE_H
#define KER_RUNTIME_UDP_NEIGHBOR_CREATE_H
#include "runtime/neighbor.h"
#include "runtime/udp-create.h"

/* Build using the table's one configured local IPv4 address/device and an
 * existing NUD_PERMANENT destination mapping. The worker-owned lookup
 * reference is released before packet allocation. Missing destinations return
 * -ENOENT; non-permanent mappings return -ENOTSUP. No ARP resolution, queueing,
 * FIB lookup, source-address selection, routing, socket or NIC service occurs.
 * Payload is copied by the underlying UDP constructor and borrowed only for
 * this call. The output slot is unchanged on failure. */
int ker_udp_ipv4_create_neighbor(struct ker_neighbor_table *table, __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
/* As above with a 20..60-byte IPv4 header. Options are opaque and copied
 * unchanged; a nonzero length requires a pointer and lengths are 4-byte aligned. */
int ker_udp_ipv4_create_neighbor_ip_options(struct ker_neighbor_table *table,
    __be32 destination_ip, __be16 source_port, __be16 destination_port, uint8_t ttl,
    const void *ip_options, unsigned int ip_options_length, const void *payload,
    unsigned int payload_length, struct sk_buff **result);
#endif
