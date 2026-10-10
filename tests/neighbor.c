#include "check.h"
#include "eal.h"
#include "runtime/neighbor.h"
#include "runtime/arp.h"
#include "runtime/napi.h"
#include "runtime/receive.h"
#include "runtime/memory.h"
#include <pthread.h>
#include <errno.h>
#include <limits.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device, other;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static const struct ker_neighbor_config timing = {
    .retrans_ticks = 1000, .reachable_ticks = 30000, .delay_ticks = 5000,
    .ucast_probes = 3, .mcast_probes = 3, .mcast_reprobes = 2
};
static int unused_poll(struct ker_napi *napi, unsigned int budget, void *arg)
{
    (void)napi; (void)budget; (void)arg; CHECK(false); return 0;
}
static int unused_receive(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    (void)skb; (void)handler; (void)original; (void)arg; CHECK(false); return 0;
}
static void parameters(void)
{
    struct neigh_parms *p = &table.native->parms;
    int old_data[NEIGH_VAR_DATA_MAX]; unsigned long old_state[sizeof(p->data_state) / sizeof(p->data_state[0])];
    memcpy(old_data, p->data, sizeof(old_data)); memcpy(old_state, p->data_state, sizeof(old_state));
    int old_reachable = p->reachable_time;
    CHECK(ker_neighbor_configure(NULL, &timing) == -EINVAL);
    CHECK(ker_neighbor_configure(&table, NULL) == -EINVAL);
    address.native->arp_parms = NULL;
    CHECK(ker_neighbor_configure(&table, &timing) == -ESHUTDOWN);
    address.native->arp_parms = p;
    struct ker_neighbor_config bad = timing;
    bad.reachable_ticks = INT_MAX;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.retrans_ticks = 0;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.delay_ticks = UINT_MAX;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.ucast_probes = INT_MAX; bad.mcast_probes = 1;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.ucast_probes = INT_MAX; bad.mcast_probes = 0; bad.mcast_reprobes = 1;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.reachable_ticks = 0;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.delay_ticks = 0;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.mcast_probes = UINT_MAX;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    bad = timing; bad.mcast_reprobes = UINT_MAX;
    CHECK(ker_neighbor_configure(&table, &bad) == -EINVAL);
    CHECK(memcmp(old_data, p->data, sizeof(old_data)) == 0);
    CHECK(memcmp(old_state, p->data_state, sizeof(old_state)) == 0 && p->reachable_time == old_reachable);
    struct neigh_parms *held = neigh_parms_clone(p);
    CHECK(ker_neighbor_configure(&table, &timing) == -EBUSY);
    __neigh_parms_put(held);
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&context, 64, 0, &skb) == 0);
    CHECK(ker_neighbor_configure(&table, &timing) == -EBUSY);
    CHECK(ker_skb_free(skb) == 0);
    struct ker_napi_runtime nr = {0}; struct ker_napi napi = {0};
    CHECK(ker_napi_runtime_init(&nr) == 0);
    CHECK(ker_napi_init(&napi, &nr, &device, 1, unused_poll, NULL) == 0);
    CHECK(ker_neighbor_configure(&table, &timing) == -EBUSY);
    CHECK(ker_napi_cleanup(&napi) == 0 && ker_napi_runtime_cleanup(&nr) == 0);
    struct ker_receive_runtime rx = {0}; struct ker_protocol_handler handler = {0};
    CHECK(ker_receive_runtime_init(&rx, &context) == 0);
    CHECK(ker_protocol_register(&rx, &handler, &device, rte_cpu_to_be_16(ETH_P_ARP), unused_receive, NULL) == 0);
    CHECK(ker_neighbor_configure(&table, &timing) == -EBUSY);
    CHECK(ker_protocol_unregister(&handler) == 0 && ker_receive_runtime_cleanup(&rx) == 0);
    ker_memory_fail_after(0);
    CHECK(ker_neighbor_configure(&table, &timing) == 0);
    ker_memory_fail_after(-1);
    CHECK(NEIGH_VAR(p, RETRANS_TIME) == 1000 && NEIGH_VAR(p, BASE_REACHABLE_TIME) == 30000);
    CHECK(NEIGH_VAR(p, DELAY_PROBE_TIME) == 5000 && NEIGH_VAR(p, UCAST_PROBES) == 3);
    CHECK(NEIGH_VAR(p, MCAST_PROBES) == 3 && NEIGH_VAR(p, MCAST_REPROBES) == 2 && NEIGH_VAR(p, APP_PROBES) == 0);
    unsigned long mask = (1UL << NEIGH_VAR_RETRANS_TIME) | (1UL << NEIGH_VAR_BASE_REACHABLE_TIME) |
        (1UL << NEIGH_VAR_DELAY_PROBE_TIME) | (1UL << NEIGH_VAR_UCAST_PROBES) |
        (1UL << NEIGH_VAR_MCAST_PROBES) | (1UL << NEIGH_VAR_MCAST_REPROBES) | (1UL << NEIGH_VAR_APP_PROBES);
    CHECK(p->data_state[0] == mask);
    CHECK(neigh_rand_reach_time(0) == 0 && neigh_rand_reach_time(1) == 0);
    struct ker_neighbor_config disabled = timing;
    disabled.ucast_probes = disabled.mcast_probes = disabled.mcast_reprobes = 0;
    CHECK(ker_neighbor_configure(&table, &disabled) == 0);
    CHECK(NEIGH_VAR(p, UCAST_PROBES) == 0 && NEIGH_VAR(p, MCAST_PROBES) == 0 && NEIGH_VAR(p, MCAST_REPROBES) == 0);
    const unsigned int bases[] = {2, 3, 1000, 30000, (unsigned int)(INT_MAX / 3) * 2};
    for (unsigned int b = 0; b < sizeof(bases) / sizeof(bases[0]); ++b) {
        struct ker_neighbor_config cfg = timing; cfg.reachable_ticks = bases[b];
        for (unsigned int i = 0; i < 32; ++i) {
            CHECK(ker_neighbor_configure(&table, &cfg) == 0);
            CHECK(p->reachable_time >= (int)(bases[b] >> 1));
            CHECK((unsigned int)p->reachable_time < bases[b] + (bases[b] >> 1));
        }
    }
    CHECK(ker_neighbor_configure(&table, &timing) == 0);
}
static const unsigned char mac[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 6, 7, 8, 9, 10};
static __be32 ip(unsigned int n) { return rte_cpu_to_be_32(0xc0000200U + n); }
static u32 force_device_hash(const void *key, const struct net_device *dev, u32 *rnd)
{
    (void)dev;
    return arp_hashfn(key, device.native, rnd);
}
static void *foreign(void *arg)
{
    (void)arg;
    struct neighbour *result = (void *)(uintptr_t)1;
    CHECK(ker_neighbor_configure(&table, &timing) == -EXDEV);
    CHECK(ker_neighbor_add(&table, ip(2), peer) == -EXDEV);
    CHECK(ker_neighbor_lookup(&table, ip(2), &result) == -EXDEV && result == (void *)(uintptr_t)1);
    CHECK(ker_neighbor_table_cleanup(&table) == -EXDEV);
    return NULL;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "neigh_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "neigh_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    CHECK(ker_eth_device_init(&other, &context, "eth1", 2, peer) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, ip(1), 24) == 0);
    size_t baseline = ker_memory_live_allocations();
    CHECK(ker_neighbor_table_init(&table, &address, "neigh_records", 3, 0) == -EINVAL);
    for (long fail = 0; fail < 3; ++fail) {
        ker_memory_fail_after(fail);
        CHECK(ker_neighbor_table_init(&table, &address, "neigh_records", 3, 1) == -ENOMEM);
        ker_memory_fail_after(-1);
        CHECK(!table.native && !address.native->arp_parms);
        CHECK(refcount_read(&address.native->refcnt) == 1 && ker_memory_live_allocations() == baseline);
    }
    struct kmem_cache *conflict = kmem_cache_create("neigh_records", 64, 0, 0, NULL);
    CHECK(conflict != NULL);
    size_t with_conflict = ker_memory_live_allocations();
    CHECK(ker_neighbor_table_init(&table, &address, "neigh_records", 3, 1) == -ENOMEM);
    CHECK(!table.native && !address.native->arp_parms && ker_memory_live_allocations() == with_conflict);
    kmem_cache_destroy(conflict);
    CHECK(ker_neighbor_table_init(&table, &address, "neigh_records", 3, 1) == 0);
    CHECK(address.native->arp_parms == &table.native->parms && refcount_read(&address.native->refcnt) == 2);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY && ker_eth_device_cleanup(&device) == -EBUSY);
    parameters();
    CHECK(ker_neighbor_add(&table, 0, peer) == -EINVAL);
    unsigned char bad[6] = {1, 0, 0, 0, 0, 0};
    CHECK(ker_neighbor_add(&table, ip(2), bad) == -EINVAL);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign, NULL) == 0 && pthread_join(thread, NULL) == 0);
    ker_memory_fail_after(0);
    CHECK(ker_neighbor_add(&table, ip(2), peer) == -ENOMEM && atomic_read(&table.native->entries) == 0);
    ker_memory_fail_after(-1);
    for (unsigned int i = 2; i < 5; ++i) CHECK(ker_neighbor_add(&table, ip(i), peer) == 0);
    CHECK(ker_neighbor_add(&table, ip(2), peer) == -EEXIST);
    CHECK(ker_neighbor_add(&table, ip(5), peer) == -ENOSPC);
    CHECK(ker_neighbor_configure(&table, &timing) == -EBUSY);
    CHECK(atomic_read(&table.native->entries) == 3 && refcount_read(&table.native->parms.refcnt) == 4);
    struct neighbour *held = NULL;
    CHECK(ker_neighbor_lookup(&table, ip(2), &held) == 0 && held->nud_state == NUD_PERMANENT);
    CHECK(refcount_read(&held->refcnt) == 2 && held->parms == &table.native->parms);
    CHECK(held->arp_queue.qlen == 0 && held->arp_queue.next == (struct sk_buff *)&held->arp_queue);
    __be32 key = ip(2);
    CHECK(___neigh_lookup_noref(table.native, neigh_key_eq32, force_device_hash, &key, other.native) == NULL);
    struct neighbour *missing = (void *)(uintptr_t)1;
    CHECK(ker_neighbor_lookup(&table, ip(99), &missing) == -ENOENT && missing == (void *)(uintptr_t)1);
    unsigned char snapshot[6];
    CHECK(ker_neighbor_mac(&table, held, snapshot) == 0 && memcmp(snapshot, peer, 6) == 0);
    device.native->addr_len = 7;
    CHECK(ker_neighbor_mac(&table, held, snapshot) == -ENOTSUP);
    device.native->addr_len = 6;
    CHECK(ker_neighbor_remove(&table, ip(2)) == -EBUSY && ker_neighbor_table_cleanup(&table) == -EBUSY);
    CHECK(ker_arp_device_setup(&device) == 0);
    struct sk_buff *reply = NULL;
    CHECK(ker_arp_create(&device, ARPOP_REPLY, ip(1), ip(2), snapshot, NULL, snapshot, &reply) == 0);
    CHECK(memcmp(reply->data, peer, 6) == 0 && memcmp(reply->data + 32, peer, 6) == 0);
    CHECK(ker_skb_free(reply) == 0);
    CHECK(ker_neighbor_release(&table, held) == 0);
    for (unsigned int i = 2; i < 5; ++i) CHECK(ker_neighbor_remove(&table, ip(i)) == 0);
    CHECK(ker_neighbor_remove(&table, ip(2)) == -ENOENT);
    CHECK(ker_neighbor_table_cleanup(&table) == 0 && !address.native->arp_parms);
    CHECK(refcount_read(&address.native->refcnt) == 1 && ker_memory_live_allocations() == baseline);
    /* Table limit and the independently configured fixed pool differ. */
    CHECK(ker_neighbor_table_init(&table, &address, "neigh_records", 8, 1) == 0);
    for (unsigned int i = 2; i < 9; ++i) CHECK(ker_neighbor_add(&table, ip(i), peer) == 0);
    CHECK(ker_neighbor_add(&table, ip(9), peer) == -ENOMEM && atomic_read(&table.native->entries) == 7);
    for (unsigned int i = 2; i < 9; ++i) {
        struct neighbour *entry = NULL;
        CHECK(ker_neighbor_lookup(&table, ip(i), &entry) == 0);
        CHECK(ker_neighbor_mac(&table, entry, snapshot) == 0 && memcmp(snapshot, peer, 6) == 0);
        CHECK(ker_neighbor_release(&table, entry) == 0);
        CHECK(ker_neighbor_remove(&table, ip(i)) == 0);
    }
    CHECK(ker_neighbor_add(&table, ip(9), peer) == 0 && ker_neighbor_remove(&table, ip(9)) == 0);
    CHECK(ker_neighbor_table_cleanup(&table) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_eth_device_cleanup(&other) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("neighbor: original layouts/hash/lookup/snapshot, references, collision/device checks, bounded pool and rollback passed");
    return 0;
}
