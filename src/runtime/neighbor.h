#ifndef KER_RUNTIME_NEIGHBOR_H
#define KER_RUNTIME_NEIGHBOR_H
#include "ker/linux_neighbor.h"
#include "runtime/ipv4-address.h"
struct kmem_cache;
/* One worker/device permanent IPv4 neighbor table. Stable zero-initialized
 * storage, a configured IPv4 address, fixed descriptor pool, no dynamic NUD,
 * probe timers, GC, unresolved packet queues, proxy or output service. */
struct ker_neighbor_table {
    struct neigh_table *native;
    struct ker_ipv4_address *address;
    struct kmem_cache *records;
    unsigned int limit;
    unsigned int lcore;
};
/* limit is logical; pool object count comes from ker_memory_init cache_objects.
 * hash_bits 1..16, fixed hash multiplier, no untrusted packet learning. */
int ker_neighbor_table_init(struct ker_neighbor_table *table, struct ker_ipv4_address *address,
    const char *name, unsigned int limit, unsigned int hash_bits);
/* Requires zero entries and no extra parameter references. */
int ker_neighbor_table_cleanup(struct ker_neighbor_table *table);
/* Immutable NUD_PERMANENT entry. Duplicate keys fail, no replacement/learning.
 * limit exhaustion is ENOSPC; fixed DPDK pool/budget failure is ENOMEM. */
int ker_neighbor_add(struct ker_neighbor_table *table, __be32 ip, const unsigned char mac[6]);
int ker_neighbor_remove(struct ker_neighbor_table *table, __be32 ip);
/* Original lookup/clone grants one reference. Failure leaves output unchanged.
 * Every acquired reference must be released; removal refuses live references. */
int ker_neighbor_lookup(struct ker_neighbor_table *table, __be32 ip, struct neighbour **result);
int ker_neighbor_release(struct ker_neighbor_table *table, struct neighbour *entry);
int ker_neighbor_mac(struct ker_neighbor_table *table, struct neighbour *entry, unsigned char mac[6]);
#endif
