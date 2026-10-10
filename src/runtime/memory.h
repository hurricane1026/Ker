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
enum ker_memory_domain {
    KER_MEMORY_CONTROL,
    KER_MEMORY_CACHE,
    KER_MEMORY_ATOMIC,
    KER_MEMORY_DOMAIN_COUNT
};
/* Per allocation-worker limits on usable capacity, including in-flight
 * reservations. Zero limit means unlimited; zero high disables pressure.
 * Configure only while all allocation/return users are quiescent. */
struct ker_memory_budget_config {
    size_t limit;
    size_t high;
    size_t low;
};
struct ker_memory_budget_stats {
    size_t used;
    size_t peak;
    size_t denied;
    int pressure;
};
int ker_memory_budget_configure(enum ker_memory_domain domain,
    const struct ker_memory_budget_config *config);
int ker_memory_budget_stats(enum ker_memory_domain domain,
    struct ker_memory_budget_stats *stats);
int ker_memory_shutdown(void);
void ker_memory_fail_after(long count);
size_t ker_memory_live_allocations(void);
#endif
