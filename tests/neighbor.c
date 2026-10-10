#include "check.h"
#include "eal.h"
#include "runtime/neighbor.h"
#include "runtime/arp.h"
#include "runtime/memory.h"
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device, other;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
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
