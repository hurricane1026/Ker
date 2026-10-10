#ifndef KER_COMPAT_NAPI_SUPPORT_H
#define KER_COMPAT_NAPI_SUPPORT_H
/* GRO and deferred IRQ timers are not ported. Empty GRO is a genuine no-work
 * case; unexpected queued aggregation or timer activation must fail closed. */
static inline void gro_flush_normal(struct gro_node *gro, bool flush)
{
    (void)flush;
    BUG_ON(gro->bitmask || gro->rx_count || !list_empty(&gro->rx_list));
    for (unsigned int i = 0; i < GRO_HASH_BUCKETS; ++i)
        BUG_ON(gro->hash[i].count || !list_empty(&gro->hash[i].list));
}
#define HRTIMER_MODE_REL_PINNED 0
static inline ktime_t ns_to_ktime(u64 ns) { return (ktime_t)ns; }
static inline void hrtimer_start(struct hrtimer *timer, ktime_t time, int mode)
{
    (void)timer; (void)time; (void)mode;
    BUG();
}
#endif
