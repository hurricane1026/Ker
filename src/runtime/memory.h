#ifndef KER_RUNTIME_MEMORY_H
#define KER_RUNTIME_MEMORY_H
#include <stddef.h>
/* Call after successful EAL initialization, on the owning EAL worker. The
 * selected NUMA socket is thread local. No implicit libc fallback exists. */
int ker_memory_init(int socket_id, unsigned int cache_objects);
/* Configure increasing cache-line-aligned size classes on the owning worker,
 * before polling starts. Each class has an independent fixed object budget.
 * Pool objects may be returned by another registered, initialized worker.
 * All users must quiesce before shutdown or the owner thread exits. */
struct ker_memory_pool_config {
    unsigned int size;
    unsigned int objects;
    unsigned int cache_size;
};
struct ker_memory_pool_stats {
    unsigned int size;
    unsigned int objects;
    size_t in_use;
    size_t requests;
    size_t failures;
};
int ker_memory_atomic_pools_init(const char *name,
    const struct ker_memory_pool_config *classes, size_t count);
int ker_memory_atomic_pool_stats(size_t index, struct ker_memory_pool_stats *stats);
int ker_memory_shutdown(void);
void ker_memory_fail_after(long count);
size_t ker_memory_live_allocations(void);
#endif
