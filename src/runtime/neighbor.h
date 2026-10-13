#ifndef KER_RUNTIME_NEIGHBOR_H
#define KER_RUNTIME_NEIGHBOR_H
#include "ker/linux_neighbor.h"
#include "runtime/ipv4-address.h"
struct kmem_cache;
/* One worker/device permanent IPv4 neighbor table. Stable zero-initialized
 * storage, a configured IPv4 address and fixed descriptor pool. Optional
 * neighbor-timer monitors pin selected entries. Native unresolved queues and
 * output require an explicit bounded per-monitor resolver binding; no unknown
 * neighbor creation, FIB, GC, or proxy service is exposed. */
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
/* Explicit worker tick counts (HZ=1000 for the timer_list profile). No implicit
 * defaults or application/proxy probes. Configuration requires an offline,
 * empty table and no extra parameter references; invalid input is atomic. */
struct ker_neighbor_config {
    unsigned int retrans_ticks, reachable_ticks, delay_ticks;
    unsigned int ucast_probes, mcast_probes, mcast_reprobes;
    unsigned int queue_bytes; /* zero disables the native unresolved queue */
};
int ker_neighbor_configure(struct ker_neighbor_table *, const struct ker_neighbor_config *);
/* Requires zero entries and no extra parameter references. */
int ker_neighbor_table_cleanup(struct ker_neighbor_table *table);
/* Immutable NUD_PERMANENT entry. Duplicate keys fail, no replacement/learning.
 * limit exhaustion is ENOSPC; fixed DPDK pool/budget failure is ENOMEM. */
int ker_neighbor_add(struct ker_neighbor_table *table, __be32 ip, const unsigned char mac[6]);
int ker_neighbor_remove(struct ker_neighbor_table *table, __be32 ip);
/* Original lookup/clone grants one reference. Failure leaves output unchanged.
 * Every acquired reference must be released; removal refuses live references. */
int ker_neighbor_lookup(struct ker_neighbor_table *table, __be32 ip, struct neighbour **result);
/* Release lookup references in any monitored state as well as PERMANENT. */
int ker_neighbor_release(struct ker_neighbor_table *table, struct neighbour *entry);
/* Internal teardown restoration for monitor-owned updates. */
void ker_neighbor_update_restore_mac(struct neighbour *, const unsigned char[ETH_ALEN]);
/* Permanent mappings only; monitored entries require a stateful snapshot. */
int ker_neighbor_mac(struct ker_neighbor_table *table, struct neighbour *entry, unsigned char mac[6]);
#endif
