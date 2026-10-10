#include "check.h"
#include "eal.h"
#include "runtime/skb.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>

static struct ker_packet_pool pool;
static struct ker_skb_context ctx;
static void check_pool(unsigned int available)
{
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
}
static void test_geometry_and_operations(void)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 32, &skb) == 0);
    CHECK(refcount_read(&skb->users) == 1);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 1);
    CHECK((uintptr_t)skb_shinfo(skb) % SMP_CACHE_BYTES == 0);
    CHECK(skb_headroom(skb) == 32);
    CHECK(skb_tailroom(skb) == (int)skb->end - 32);
    uint8_t *data = NULL;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    CHECK(ker_skb_push(skb, 4, &data) == 0);
    memcpy(data, "HEAD", 4);
    CHECK(skb->len == 9 && memcmp(skb->data, "HEADhello", 9) == 0);
    CHECK(ker_skb_pull(skb, 4) == 0);
    CHECK(skb->len == 5 && memcmp(skb->data, "hello", 5) == 0);
    CHECK(memcmp(skb->data - 4, "HEAD", 4) == 0);
    CHECK(ker_skb_pull(skb, 6) == -EINVAL && skb->len == 5);
    CHECK(ker_skb_trim(skb, 6) == -EINVAL && skb->len == 5);
    uint8_t *unchanged = data;
    CHECK(ker_skb_put(skb, UINT_MAX, &data) == -ENOSPC && data == unchanged);
    CHECK(ker_skb_push(skb, UINT_MAX, &data) == -ENOSPC && data == unchanged);
    CHECK(ker_skb_trim(skb, 3) == 0 && skb->len == 3);
    CHECK(skb_tail_pointer(skb) == skb->data + 3);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(ctx.live == 0);
    check_pool(31);
}
static int destructor_count;
static void destructor(struct sk_buff *skb)
{
    CHECK(skb->cb[0] == 'x');
    ++destructor_count;
}
static void test_clone_and_descriptor_refs(void)
{
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 4, 64, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 4, &data) == 0);
    memcpy(data, "data", 4);
    skb->cb[0] = 'x';
    skb->priority = 77;
    skb->mark = 42;
    skb->tstamp = 101;
    skb->destructor = destructor;
    CHECK(ker_skb_get(skb) == 0 && refcount_read(&skb->users) == 2);
    CHECK(ker_skb_put(skb, 1, &data) == -EBUSY);
    CHECK(ker_skb_pull(skb, 1) == -EBUSY);
    CHECK(ker_skb_make_writable(skb, 0, 0) == -EBUSY);
    CHECK(ker_skb_free(skb) == 0 && refcount_read(&skb->users) == 1);
    CHECK(destructor_count == 0);
    CHECK(ker_skb_clone(skb, &clone) == 0);
    CHECK(clone != skb && clone->data == skb->data);
    CHECK(clone->cb[0] == 'x' && clone->priority == 77 && clone->mark == 42 && clone->tstamp == 101);
    CHECK(clone->destructor == NULL && clone->sk == NULL);
    CHECK(refcount_read(&clone->users) == 1 && atomic_read(&skb_shinfo(skb)->dataref) == 2);
    CHECK(skb_cloned(skb) && skb_cloned(clone));
    CHECK(ker_skb_put(clone, 1, &data) == -EBUSY);
    CHECK(ker_skb_push(clone, 1, &data) == -EBUSY);
    CHECK(ker_skb_pull(clone, 1) == 0 && clone->len == 3 && skb->len == 4);
    CHECK(ker_skb_context_cleanup(&ctx) == -EBUSY);
    CHECK(ker_skb_free(skb) == 0 && destructor_count == 1);
    CHECK(memcmp(clone->data, "ata", 3) == 0);
    CHECK(!skb_cloned(clone));
    check_pool(30);
    CHECK(ker_skb_free(clone) == 0 && destructor_count == 1);
    check_pool(31);
}
static void test_headerless_references(void)
{
    struct sk_buff *skb = NULL, *a = NULL, *b = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 64, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    __skb_header_release(skb);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 0x10001);
    CHECK(ker_skb_clone(skb, &a) == 0);
    CHECK(a->nohdr == 0 && a->hdr_len == 64);
    CHECK(!skb_header_cloned(a) && skb_cloned(a));
    CHECK(ker_skb_clone(skb, &b) == 0);
    CHECK(skb_header_cloned(a) && skb_header_cloned(b));
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 0x10003);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 2);
    CHECK(ker_skb_make_writable(a, 0, 0) == 0);
    CHECK(a->head != b->head && atomic_read(&skb_shinfo(a)->dataref) == 1);
    CHECK(atomic_read(&skb_shinfo(b)->dataref) == 1);
    a->data[0] = 'H';
    CHECK(b->data[0] == 'h');
    CHECK(ker_skb_free(a) == 0);
    CHECK(ker_skb_free(b) == 0);
    /* COW of the payload-only owner must drop its high-word bias as well. */
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skb) == 0);
    __skb_header_release(skb);
    CHECK(ker_skb_clone(skb, &a) == 0);
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 0x10002);
    CHECK(ker_skb_make_writable(skb, 0, 0) == 0);
    CHECK(skb->nohdr == 0 && atomic_read(&skb_shinfo(skb)->dataref) == 1);
    CHECK(a->head != skb->head && atomic_read(&skb_shinfo(a)->dataref) == 1);
    CHECK(ker_skb_free(skb) == 0 && ker_skb_free(a) == 0);
    check_pool(31);
}
static void test_cow_and_export(void)
{
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 32, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    memcpy(skb->data - 4, "HEAD", 4);
    skb->network_header = 32;
    skb->transport_header = 34;
    skb->mac_header = 28;
    skb->mark = 19;
    CHECK(ker_skb_clone(skb, &clone) == 0);
    unsigned char *head = clone->head;
    CHECK(ker_skb_make_writable(clone, UINT_MAX, 0) == -ENOSPC && clone->head == head);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    CHECK(ker_skb_make_writable(clone, 64, 12) == 0);
    CHECK(clone->head != skb->head && skb_headroom(clone) == 64 && skb_tailroom(clone) >= 12);
    CHECK(clone->network_header == 64 && clone->transport_header == 66 && clone->mac_header == 60);
    CHECK(clone->mark == 19 && memcmp(clone->data - 4, "HEAD", 4) == 0);
    clone->data[0] = 'H';
    CHECK(skb->data[0] == 'h');
    struct rte_mbuf *packet = NULL;
    CHECK(ker_skb_to_mbuf(clone, &packet) == 0);
    CHECK(packet->data_len == 5 && packet->pkt_len == 5 && packet->ol_flags == 0);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, void *), "Hello", 5) == 0);
    CHECK(rte_pktmbuf_mtod(packet, void *) != clone->data);
    ker_packet_free(packet);
    clone->ip_summed = CHECKSUM_PARTIAL;
    packet = NULL;
    CHECK(ker_skb_to_mbuf(clone, &packet) == -ENOTSUP && packet == NULL);
    clone->ip_summed = CHECKSUM_NONE;
    skb_shinfo(clone)->gso_size = 1448;
    CHECK(ker_skb_to_mbuf(clone, &packet) == -ENOTSUP && packet == NULL);
    skb_shinfo(clone)->gso_size = 0;
    CHECK(ker_skb_free(clone) == 0 && ker_skb_free(skb) == 0);
    check_pool(31);
}
static void test_exhaustion_and_rollback(void)
{
    struct sk_buff *skbs[7];
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skbs[0]) == 0);
    for (int i = 1; i < 7; ++i)
        CHECK(ker_skb_clone(skbs[0], &skbs[i]) == 0);
    struct sk_buff *unchanged = skbs[0];
    CHECK(ker_skb_clone(skbs[0], &unchanged) == -ENOMEM && unchanged == skbs[0]);
    CHECK(atomic_read(&skb_shinfo(skbs[0])->dataref) == 7);
    for (int i = 0; i < 7; ++i)
        CHECK(ker_skb_free(skbs[i]) == 0);
    check_pool(31);
    ker_memory_fail_after(0);
    unchanged = NULL;
    CHECK(ker_skb_alloc(&ctx, 1, 64, &unchanged) == -ENOMEM && unchanged == NULL);
    check_pool(31);
    struct rte_mbuf *raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    memset(raw->buf_addr, 0xa5, raw->buf_len);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &unchanged) == -ENOMEM);
    CHECK(((uint8_t *)raw->buf_addr)[raw->buf_len - 1] == 0xa5);
    ker_packet_free(raw);
    ker_memory_fail_after(-1);
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skb) == 0 && ker_skb_clone(skb, &clone) == 0);
    struct rte_mbuf *held[30];
    for (int i = 0; i < 30; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i] != NULL); }
    unsigned char *old_head = clone->head;
    CHECK(ker_skb_make_writable(clone, 0, 0) == -ENOMEM && clone->head == old_head);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    raw = NULL;
    CHECK(ker_skb_to_mbuf(skb, &raw) == -ENOMEM && raw == NULL);
    for (int i = 0; i < 30; ++i)
        ker_packet_free(held[i]);
    CHECK(ker_skb_free(clone) == 0 && ker_skb_free(skb) == 0);
    check_pool(31);
}
static void *wrong_worker(void *skb)
{
    CHECK(ker_skb_get(skb) == -EXDEV);
    CHECK(ker_skb_free(skb) == -EXDEV);
    return NULL;
}
static void test_rx_and_rejection(void)
{
    struct rte_mbuf *raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, 3) != NULL);
    memcpy(rte_pktmbuf_mtod(raw, void *), "udp", 3);
    struct sk_buff *skb = NULL;
    rte_mbuf_refcnt_update(raw, 1);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == -EBUSY && skb == NULL);
    ker_packet_free(raw);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == 0);
    CHECK(skb->len == 3 && memcmp(skb->data, "udp", 3) == 0);
    struct sk_buff *observer = NULL;
    CHECK(ker_skb_clone(skb, &observer) == 0);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    /* Read-only inspection while skb owns the backing: no extra mbuf ref. */
    CHECK(rte_mbuf_refcnt_read(raw) == 1);
    CHECK(ker_skb_free(observer) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wrong_worker, skb) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(refcount_read(&skb->users) == 1);
    skb->_skb_refdst = 1;
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(skb, &clone) == -ENOTSUP && clone == NULL);
    skb->_skb_refdst = 0;
    CHECK(ker_skb_free(skb) == 0);
    raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, raw->buf_len - raw->data_off) != NULL);
    skb = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == -ENOSPC && skb == NULL);
    ker_packet_free(raw);
    raw = ker_packet_alloc(&pool);
    struct rte_mbuf *indirect = ker_packet_clone(&pool, raw);
    CHECK(indirect != NULL);
    CHECK(ker_skb_from_mbuf(&ctx, indirect, &skb) == -ENOTSUP && skb == NULL);
    ker_packet_free(indirect);
    ker_packet_free(raw);
    check_pool(31);
}
static void test_foreign_backing(void)
{
    struct ker_packet_pool foreign = {0};
    CHECK(ker_packet_pool_init(&foreign, "ker_skb_foreign", 7, 0, 2048, SOCKET_ID_ANY) == 0);
    struct rte_mbuf *raw = ker_packet_alloc(&foreign);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, 4) != NULL);
    memcpy(rte_pktmbuf_mtod(raw, void *), "data", 4);
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == 0);
    CHECK(ker_packet_pool_cleanup(&foreign) == -EBUSY);
    /* Closing an unused export pool must not prevent releasing foreign data. */
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(rte_mempool_avail_count(foreign.mbufs) == 7);
    CHECK(ker_packet_pool_cleanup(&foreign) == 0);
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_skb_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&ctx, &pool, "ker_skb_descriptors") == 0);
    test_geometry_and_operations();
    test_clone_and_descriptor_refs();
    test_headerless_references();
    test_cow_and_export();
    test_exhaustion_and_rollback();
    test_rx_and_rejection();
    test_foreign_backing();
    CHECK(ctx.live == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_skb_context_cleanup(&ctx) == 0);
    CHECK(ker_memory_live_allocations() == 0 && ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("skb: native Linux layout, dataref/headerless refs, DPDK backing, COW and rollback passed");
    return 0;
}
