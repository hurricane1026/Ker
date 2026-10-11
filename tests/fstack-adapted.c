/* Scenario adaptations from F-Stack tests at the revision recorded in
 * fstack-provenance.json. Ker-specific implementation and assertions; no ff_*
 * glue, FreeBSD implementation, mocks or upstream harness code are compiled. */
#include "check.h"
#include "eal.h"
#include "runtime/skb-queue.h"
#include "runtime/memory.h"
#include "runtime/timer.h"
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_skb_queue first, second;
static struct sk_buff *packet(unsigned int length)
{
    struct sk_buff *skb = NULL; unsigned char *bytes;
    CHECK(ker_skb_alloc(&context, length, 16, &skb) == 0);
    CHECK(ker_skb_put(skb, length, &bytes) == 0);
    for (unsigned int i = 0; i < length; ++i) bytes[i] = (unsigned char)(i * 17 + 3);
    return skb;
}
static void mbuf_release(void)
{
    unsigned int available = rte_mempool_avail_count(pool.mbufs);
    struct rte_mbuf *mbuf = ker_packet_alloc(&pool); CHECK(mbuf);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available - 1);
    ker_packet_free(mbuf);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
}
static void clock_monotonic(void)
{
    int64_t previous, now;
    CHECK(ker_monotonic_ns(&previous) == 0 && previous >= 0);
    for (unsigned int i = 0; i < 1000; ++i) {
        CHECK(ker_monotonic_ns(&now) == 0 && now >= previous);
        previous = now;
    }
}
static void empty_export(void)
{
    struct sk_buff *skb = packet(0); struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy && copy->pkt_len == 0 && copy->data_len == 0);
    CHECK(!copy->ol_flags && refcount_read(&skb->users) == 1 && context.live == 1);
    ker_packet_free(copy); CHECK(ker_skb_free(skb) == 0);
}
static void null_context(void)
{
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_skb_alloc(NULL, 0, 0, &skb) == -EXDEV && skb == (void *)(uintptr_t)1);
    CHECK(!context.live && rte_mempool_avail_count(pool.mbufs) == 31);
}
static void packet_export(void)
{
    struct sk_buff *skb = packet(64); struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy->pkt_len == 64);
    CHECK(!memcmp(rte_pktmbuf_mtod(copy, const void *), skb->data, 64));
    CHECK(!copy->ol_flags && refcount_read(&skb->users) == 1);
    CHECK(ker_skb_free(skb) == 0);
    /* Copy remains readable after the original backing is returned. */
    const unsigned char *bytes = rte_pktmbuf_mtod(copy, const unsigned char *);
    for (unsigned int i = 0; i < 64; ++i) CHECK(bytes[i] == (unsigned char)(i * 17 + 3));
    ker_packet_free(copy);
}
static void headroom_export(void)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&context, 96, 192, &skb) == 0);
    CHECK(skb_headroom(skb) == 192);
    uint8_t *bytes;
    CHECK(ker_skb_put(skb, 96, &bytes) == 0);
    for (unsigned int i = 0; i < 96; ++i) bytes[i] = (uint8_t)(255 - i);
    struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy);
    CHECK(copy->data_off == 192 && copy->data_len == 96 && copy->pkt_len == 96);
    CHECK(!memcmp(rte_pktmbuf_mtod(copy, const void *), skb->data, 96));
    CHECK(refcount_read(&skb->users) == 1 && context.live == 1);
    CHECK(ker_skb_free(skb) == 0);
    const uint8_t *exported = rte_pktmbuf_mtod(copy, const uint8_t *);
    for (unsigned int i = 0; i < 96; ++i) CHECK(exported[i] == (uint8_t)(255 - i));
    ker_packet_free(copy);
}
static void export_exhaustion_retry(void)
{
    struct sk_buff *skb = packet(64);
    struct rte_mbuf *held[30];
    for (unsigned int i = 0; i < 30; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    struct rte_mbuf *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOMEM && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    for (unsigned int i = 0; i < 64; ++i) CHECK(skb->data[i] == (unsigned char)(i * 17 + 3));
    ker_packet_free(held[0]);
    CHECK(ker_skb_to_mbuf(skb, &output) == 0 && output && output->pkt_len == 64);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), skb->data, 64));
    for (unsigned int i = 1; i < 30; ++i) ker_packet_free(held[i]);
    CHECK(ker_skb_free(skb) == 0);
    /* The remaining allocated copy is released by the caller. */
    CHECK(rte_mempool_avail_count(pool.mbufs) == 30);
    ker_packet_free(output);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
}
static void offload_metadata_rejection(void)
{
    struct sk_buff *skb = packet(64);
    struct rte_mbuf *output = (void *)(uintptr_t)1;
    skb->ip_summed = CHECKSUM_PARTIAL;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    skb->ip_summed = CHECKSUM_NONE;
    skb_shinfo(skb)->gso_size = 1448;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    skb_shinfo(skb)->gso_size = 0;
    CHECK(ker_skb_to_mbuf(skb, &output) == 0 && output && output->pkt_len == 64);
    ker_packet_free(output);
    CHECK(ker_skb_free(skb) == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
}
static void multiseg_boundary(void)
{
    struct rte_mbuf *a = ker_packet_alloc(&pool), *b = ker_packet_alloc(&pool); CHECK(a && b);
    CHECK(rte_pktmbuf_append(a, 16) && rte_pktmbuf_append(b, 16));
    CHECK(rte_pktmbuf_chain(a, b) == 0);
    struct sk_buff *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_from_mbuf(&context, a, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(a->next == b && a->nb_segs == 2 && a->pkt_len == 32);
    CHECK(rte_mbuf_refcnt_read(a) == 1 && rte_mbuf_refcnt_read(b) == 1);
    ker_packet_free(a); /* Ker refuses adoption; caller still owns the chain. */
}
static void multiseg_copy(void)
{
    struct rte_mbuf *a = ker_packet_alloc(&pool), *b = ker_packet_alloc(&pool), *c = ker_packet_alloc(&pool);
    CHECK(a && b && c);
    CHECK(rte_pktmbuf_append(a, 5) && rte_pktmbuf_append(b, 0) && rte_pktmbuf_append(c, 7));
    memcpy(rte_pktmbuf_mtod(a, void *), "first", 5);
    memcpy(rte_pktmbuf_mtod(c, void *), "payload", 7);
    CHECK(rte_pktmbuf_chain(b, c) == 0 && rte_pktmbuf_chain(a, b) == 0);
    CHECK(a->nb_segs == 3 && a->pkt_len == 12 && a->next == b && b->nb_segs == 2 && b->next == c && !c->next);
    struct rte_mbuf *identity_b = a->next, *identity_c = b->next;
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&context, a, 192, &skb) == 0 && skb != (void *)(uintptr_t)1);
    CHECK(skb->len == 12 && skb_headroom(skb) == 192 && !memcmp(skb->data, "firstpayload", 12));
    CHECK(a->nb_segs == 3 && a->pkt_len == 12 && a->next == identity_b && b->nb_segs == 2 && b->next == identity_c);
    CHECK(rte_mbuf_refcnt_read(a) == 1 && rte_mbuf_refcnt_read(b) == 1 && rte_mbuf_refcnt_read(c) == 1);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(a->next == identity_b && b->next == identity_c && a->pkt_len == 12);
    CHECK(!memcmp(rte_pktmbuf_mtod(a, const void *), "first", 5));
    CHECK(!memcmp(rte_pktmbuf_mtod(c, const void *), "payload", 7));
    skb = NULL;
    CHECK(ker_skb_copy_from_mbuf_chain(&context, a, 192, &skb) == 0 && skb);
    ker_packet_free(a);
    CHECK(!memcmp(skb->data, "firstpayload", 12));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
}
static void queue_isolation(void)
{
    struct sk_buff *skb = packet(16), *identity = skb, *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_queue_push(&first, &skb) == 0 && !skb);
    CHECK(first.native.qlen == 1 && !second.native.qlen);
    CHECK(ker_skb_queue_pop(&second, &output) == 0 && output == (void *)(uintptr_t)1);
    CHECK(first.native.qlen == 1 && context.live == 1);
    CHECK(ker_skb_queue_pop(&first, &output) == 1 && output == identity);
    CHECK(refcount_read(&output->users) == 1 && ker_skb_free(output) == 0);
}
static void queue_full_ownership(void)
{
    struct sk_buff *a = packet(16), *b = packet(16), *identity = b;
    CHECK(ker_skb_queue_push(&first, &a) == 0 && !a);
    unsigned int available = rte_mempool_avail_count(pool.mbufs);
    CHECK(ker_skb_queue_push(&first, &b) == -ENOSPC && b == identity);
    CHECK(first.native.qlen == 1 && refcount_read(&b->users) == 1);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
    CHECK(ker_skb_free(b) == 0 && rte_mempool_avail_count(pool.mbufs) == available + 1);
    CHECK(ker_skb_queue_purge(&first, 1) == 1 && rte_mempool_avail_count(pool.mbufs) == 31);
}
int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        {"mbuf-release", mbuf_release}, {"clock-monotonic", clock_monotonic},
        {"empty-export", empty_export}, {"null-context", null_context},
        {"packet-export", packet_export}, {"multiseg-boundary", multiseg_boundary},
        {"queue-isolation", queue_isolation}, {"queue-full-ownership", queue_full_ownership},
        {"multiseg-copy", multiseg_copy},
        {"headroom-export", headroom_export},
        {"export-exhaustion-retry", export_exhaustion_retry},
        {"offload-metadata-rejection", offload_metadata_rejection}
    };
    CHECK(argc == 2); void (*run)(void) = NULL;
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (!strcmp(argv[1], cases[i].name)) run = cases[i].run;
    CHECK(run);
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "fstack_adapted_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "fstack_adapted_skb") == 0);
    CHECK(ker_skb_queue_init(&first, &context, 1, SIZE_MAX) == 0);
    CHECK(ker_skb_queue_init(&second, &context, 1, SIZE_MAX) == 0);
    run();
    CHECK(!context.live && !first.bytes && !second.bytes && rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_skb_queue_cleanup(&first) == 0 && ker_skb_queue_cleanup(&second) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    printf("F-Stack scenario adapted to Ker: %s passed\n", argv[1]);
    return 0;
}
