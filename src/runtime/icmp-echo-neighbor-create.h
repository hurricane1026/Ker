#ifndef KER_RUNTIME_ICMP_ECHO_NEIGHBOR_CREATE_H
#define KER_RUNTIME_ICMP_ECHO_NEIGHBOR_CREATE_H
#include "runtime/icmp-echo-create.h"
#include "runtime/neighbor.h"

/* Construct an echo request/reply using the one configured local IPv4/device
 * and an existing permanent destination mapping. Lookup references are
 * released before packet allocation. No FIB, ARP resolution, routing or reply
 * policy is performed. */
int ker_icmp_echo_ipv4_create_neighbor_ip_options(struct ker_neighbor_table *,
    __be32 destination_ip, __be16 identifier, __be16 sequence, uint8_t type,
    uint8_t ttl, const void *ip_options, unsigned int ip_options_length,
    const void *payload, unsigned int payload_length, struct sk_buff **result);
#endif
