#include "runtime/neighbor.h"
#include "runtime/memory.h"
#include <rte_lcore.h>
#include <sys/random.h>
#include <limits.h>
#include <errno.h>
void ker_neigh_parms_set_bit(unsigned int bit, unsigned long *words)
{
    BUG_ON(!words || bit >= NEIGH_VAR_DATA_MAX);
    const unsigned int width = sizeof(*words) * CHAR_BIT;
    __atomic_fetch_or(&words[bit / width], 1UL << (bit % width), __ATOMIC_RELAXED);
}
u32 get_random_u32_below(u32 ceiling)
{
    BUG_ON(!ceiling);
    /* Rejection sampling preserves uniformity rather than modulo bias.
     * Configure offline; host entropy failure cannot masquerade as randomness. */
    u32 value, threshold = -ceiling % ceiling;
    do {
        size_t offset = 0;
        while (offset < sizeof(value)) {
            ssize_t n = getrandom((unsigned char *)&value + offset, sizeof(value) - offset, 0);
            if (n < 0 && errno == EINTR) continue;
            BUG_ON(n <= 0);
            offset += (size_t)n;
        }
    } while (value < threshold);
    return value % ceiling;
}
int ker_neighbor_configure(struct ker_neighbor_table *table, const struct ker_neighbor_config *config)
{
    if (!table || !table->native || !config) return -EINVAL;
    if (rte_lcore_id() != table->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    if (!table->address || !table->address->native ||
        table->address->native->arp_parms != &table->native->parms) return -ESHUTDOWN;
    if (atomic_read(&table->native->entries) || refcount_read(&table->native->parms.refcnt) != 1 ||
        table->address->device->context->live || table->address->device->napi_live ||
        table->address->device->protocol_live) return -EBUSY;
    /* Linux stores parameters and randomized reachable_time in signed ints.
     * Bound the complete 1/2..3/2 reachable range before mutating any fields. */
    if (!config->retrans_ticks || config->retrans_ticks > INT_MAX ||
        !config->reachable_ticks || config->reachable_ticks > (unsigned int)(INT_MAX / 3) * 2 ||
        !config->delay_ticks || config->delay_ticks > INT_MAX ||
        config->ucast_probes > INT_MAX || config->mcast_probes > INT_MAX ||
        config->mcast_reprobes > INT_MAX ||
        config->queue_bytes > INT_MAX ||
        config->ucast_probes > (unsigned int)INT_MAX - config->mcast_probes ||
        config->ucast_probes > (unsigned int)INT_MAX - config->mcast_reprobes) return -EINVAL;
    struct neigh_parms *p = &table->native->parms;
    NEIGH_VAR_SET(p, RETRANS_TIME, (int)config->retrans_ticks);
    NEIGH_VAR_SET(p, BASE_REACHABLE_TIME, (int)config->reachable_ticks);
    NEIGH_VAR_SET(p, DELAY_PROBE_TIME, (int)config->delay_ticks);
    NEIGH_VAR_SET(p, UCAST_PROBES, (int)config->ucast_probes);
    NEIGH_VAR_SET(p, MCAST_PROBES, (int)config->mcast_probes);
    NEIGH_VAR_SET(p, MCAST_REPROBES, (int)config->mcast_reprobes);
    NEIGH_VAR_SET(p, APP_PROBES, 0); /* No userspace ARPD service in this profile. */
    NEIGH_VAR_SET(p, QUEUE_LEN_BYTES, (int)config->queue_bytes);
    neigh_set_reach_time(p);
    return 0;
}
