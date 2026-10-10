#include "check.h"
#include "runtime/memory.h"
#include "runtime/buffer.h"
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include "eal.h"

static void test_heap(void)
{
    CHECK(kmalloc(1, GFP_ATOMIC) == NULL);
    CHECK(kmalloc(1, GFP_NOWAIT) == NULL);
    CHECK(kmalloc(1, GFP_KERNEL | __GFP_DMA) == NULL);
    CHECK(kmalloc(SIZE_MAX, GFP_KERNEL) == NULL);
    CHECK(kcalloc(SIZE_MAX, 2, GFP_KERNEL) == NULL);
    CHECK(kmalloc(0, GFP_KERNEL) == ZERO_SIZE_PTR);
    kfree(ZERO_SIZE_PTR);
    kfree(NULL);
    unsigned char *data = kzalloc(17, GFP_KERNEL);
    CHECK(data != NULL && (uintptr_t)data % RTE_CACHE_LINE_SIZE == 0);
    size_t capacity = ksize(data);
    CHECK(capacity >= 17);
    for (size_t i = 0; i < capacity; ++i)
        CHECK(data[i] == 0);
    memset(data, 0x5a, capacity);
    ker_memory_fail_after(0);
    CHECK(krealloc(data, capacity + 1, GFP_KERNEL) == NULL);
    CHECK(ksize(data) == capacity && data[0] == 0x5a);
    ker_memory_fail_after(-1);
    unsigned char *grown = krealloc(data, capacity + 1, GFP_KERNEL);
    CHECK(grown != NULL);
    for (size_t i = 0; i < capacity; ++i)
        CHECK(grown[i] == 0x5a);
    CHECK(ker_memory_shutdown() == -EBUSY);
    kfree(grown);
    data = kzalloc(17, GFP_KERNEL);
    CHECK(data != NULL);
    memset(data, 0x7b, 17);
    data = krealloc(data, 33, GFP_KERNEL | __GFP_ZERO);
    CHECK(data != NULL);
    for (size_t i = 0; i < 33; ++i)
        CHECK(data[i] == (i < 17 ? 0x7b : 0));
    CHECK(krealloc(data, 0, GFP_KERNEL) == ZERO_SIZE_PTR);
    unsigned long flags;
    local_irq_save(flags);
    CHECK(kmalloc(1, GFP_KERNEL) == NULL);
    local_irq_restore(flags);
    CHECK(ker_memory_live_allocations() == 0);
}
static void test_object_pool(void)
{
    ker_memory_fail_after(0);
    CHECK(kmem_cache_create("ker_objects", 80, 0, SLAB_HWCACHE_ALIGN, NULL) == NULL);
    ker_memory_fail_after(-1);
    struct kmem_cache *cache = kmem_cache_create("ker_objects", 80, 0, SLAB_HWCACHE_ALIGN, NULL);
    CHECK(cache != NULL && kmem_cache_size(cache) == 80);
    CHECK(kmem_cache_create("ker_objects", 80, 0, 0, NULL) == NULL);
    CHECK(ker_memory_live_allocations() == 1);
    void *objects[7];
    unsigned long flags;
    local_irq_save(flags);
    for (size_t i = 0; i < 7; ++i) {
        objects[i] = kmem_cache_zalloc(cache, GFP_ATOMIC);
        CHECK(objects[i] != NULL && (uintptr_t)objects[i] % RTE_CACHE_LINE_SIZE == 0);
        CHECK(ksize(objects[i]) >= 80);
        for (size_t j = 0; j < 80; ++j)
            CHECK(((uint8_t *)objects[i])[j] == 0);
    }
    CHECK(kmem_cache_alloc(cache, GFP_ATOMIC) == NULL);
    kmem_cache_free(cache, objects[3]);
    objects[3] = kmem_cache_alloc(cache, GFP_NOWAIT);
    CHECK(objects[3] != NULL);
    for (size_t i = 0; i < 7; ++i)
        kmem_cache_free(cache, objects[i]);
    local_irq_restore(flags);
    kmem_cache_destroy(cache);
    CHECK(ker_memory_live_allocations() == 0);
}
static void test_packet_pool(void)
{
    struct ker_packet_pool pool = {0};
    CHECK(ker_packet_pool_init(&pool, "ker_packets", 7, 0, 1024, SOCKET_ID_ANY) == 0);
    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    memset(packet->buf_addr, 0x32, packet->data_off);
    char *data = rte_pktmbuf_append(packet, 5);
    CHECK(data != NULL);
    memcpy(data, "hello", 5);
    packet->vlan_tci = 123;
    struct rte_mbuf *clone = ker_packet_clone(&pool, packet);
    CHECK(clone != NULL && !RTE_MBUF_DIRECT(clone));
    CHECK(rte_mbuf_refcnt_read(packet) == 2);
    CHECK(rte_pktmbuf_mtod(clone, void *) == rte_pktmbuf_mtod(packet, void *));
    CHECK(ker_packet_pool_cleanup(&pool) == -EBUSY);
    struct rte_mbuf *spares[5];
    for (int i = 0; i < 5; ++i) {
        spares[i] = ker_packet_alloc(&pool);
        CHECK(spares[i] != NULL);
    }
    CHECK(ker_packet_alloc(&pool) == NULL);
    struct rte_mbuf *old_clone = clone;
    CHECK(ker_packet_make_writable(&pool, &clone) == -ENOMEM);
    CHECK(clone == old_clone && rte_mbuf_refcnt_read(packet) == 2);
    ker_packet_free(spares[0]);
    CHECK(ker_packet_make_writable(&pool, &clone) == 0);
    CHECK(RTE_MBUF_DIRECT(clone) && clone->vlan_tci == 123);
    CHECK(clone->data_off == packet->data_off);
    CHECK(rte_mbuf_refcnt_read(packet) == 1);
    CHECK(memcmp(rte_pktmbuf_mtod(clone, void *), "hello", 5) == 0);
    CHECK(((uint8_t *)clone->buf_addr)[0] == 0x32);
    rte_pktmbuf_mtod(clone, char *)[0] = 'H';
    CHECK(rte_pktmbuf_mtod(packet, char *)[0] == 'h');
    ker_packet_free(packet);
    CHECK(memcmp(rte_pktmbuf_mtod(clone, void *), "Hello", 5) == 0);
    ker_packet_free(clone);
    for (int i = 1; i < 5; ++i)
        ker_packet_free(spares[i]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 7);
    /* Holding two references to one direct descriptor also requires COW. */
    packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    CHECK(rte_pktmbuf_append(packet, 3) != NULL);
    memcpy(rte_pktmbuf_mtod(packet, void *), "one", 3);
    struct rte_mbuf *other_owner = packet;
    rte_mbuf_refcnt_update(packet, 1);
    CHECK(ker_packet_make_writable(&pool, &packet) == 0);
    CHECK(packet != other_owner && rte_mbuf_refcnt_read(other_owner) == 1);
    rte_pktmbuf_mtod(packet, char *)[0] = 'O';
    CHECK(rte_pktmbuf_mtod(other_owner, char *)[0] == 'o');
    ker_packet_free(other_owner);
    ker_packet_free(packet);
    /* Multisegment packets are explicitly unsupported in this first bridge. */
    packet = ker_packet_alloc(&pool);
    other_owner = ker_packet_alloc(&pool);
    CHECK(packet != NULL && other_owner != NULL);
    CHECK(rte_pktmbuf_chain(packet, other_owner) == 0);
    struct rte_mbuf *unchanged = packet;
    CHECK(ker_packet_clone(&pool, packet) == NULL);
    CHECK(ker_packet_make_writable(&pool, &packet) == -ENOTSUP);
    CHECK(packet == unchanged);
    ker_packet_free(packet);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 7);
    /* An indirect mbuf from another pool retains its original backing pool.
     * Failed COW to a smaller data room must return all temporary segments. */
    struct ker_packet_pool small = {0};
    CHECK(ker_packet_pool_init(&small, "ker_small_packets", 7, 0, 256, SOCKET_ID_ANY) == 0);
    packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    CHECK(rte_pktmbuf_append(packet, 200) != NULL);
    memset(rte_pktmbuf_mtod(packet, void *), 0x6c, 200);
    clone = ker_packet_clone(&small, packet);
    CHECK(clone != NULL);
    old_clone = clone;
    CHECK(ker_packet_make_writable(&small, &clone) == -ENOSPC);
    CHECK(clone == old_clone && rte_mbuf_refcnt_read(packet) == 2);
    CHECK(rte_mempool_avail_count(small.mbufs) == 6);
    ker_packet_free(packet);
    CHECK(rte_pktmbuf_mtod(clone, uint8_t *)[199] == 0x6c);
    CHECK(ker_packet_pool_cleanup(&pool) == -EBUSY);
    CHECK(ker_packet_pool_cleanup(&small) == -EBUSY);
    ker_packet_free(clone);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 7);
    CHECK(rte_mempool_avail_count(small.mbufs) == 7);
    CHECK(ker_packet_pool_cleanup(&small) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
}
int main(void)
{
    CHECK(kmalloc(1, GFP_KERNEL) == NULL);
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == -EALREADY);
    test_heap();
    test_object_pool();
    test_packet_pool();
    CHECK(ker_memory_live_allocations() == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(kmalloc(1, GFP_KERNEL) == NULL);
    CHECK(rte_eal_cleanup() == 0);
    puts("DPDK: native heap, NUMA API, object/mbuf pools, exhaustion, COW and final reclamation passed");
    return 0;
}
