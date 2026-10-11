#ifndef KER_RUNTIME_TCP_NEIGHBOR_CREATE_H
#define KER_RUNTIME_TCP_NEIGHBOR_CREATE_H
#include "runtime/neighbor.h"
#include "runtime/tcp-create.h"

/* Construct an owned Ethernet/IPv4/TCP packet on the neighbor table's owner
 * worker. Source IPv4/MAC come from its one configured address/device;
 * destination MAC must exist as a NUD_PERMANENT entry. The entry reference is
 * released before allocation. Options/payload are borrowed for this call and
 * copied; ports, sequence, acknowledgment, and window are wire order. TCP
 * options are opaque (0..40 bytes, four-byte aligned). No resolution, FIB,
 * routing, source fallback, TCP state, socket, or NIC transmission is done. */
int ker_tcp_ipv4_create_neighbor(struct ker_neighbor_table *table, __be32 destination_ip,
    __be16 source_port, __be16 destination_port, __be32 sequence, __be32 acknowledgment,
    __be16 window, uint8_t flags, uint8_t ttl, const void *options,
    unsigned int options_length, const void *payload, unsigned int payload_length,
    struct sk_buff **result);
#endif
