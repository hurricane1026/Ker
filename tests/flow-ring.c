#include "check.h"
#include "eal.h"
#include "runtime/flow-ring.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <rte_ether.h>
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>

static unsigned int received;
static struct ker_flow_ring *active_rx;
static uint8_t ids[8];
struct foreign_ops { struct ker_flow_ring *rx; int poll, cancel, cleanup; };
static void *foreign_lifecycle(void *arg)
{
    struct foreign_ops *ops = arg;
    struct rte_mbuf *out = NULL;
    ops->poll = ker_flow_ring_poll(ops->rx, 1);
    ops->cancel = ker_flow_ring_cancel(ops->rx, &out);
    ops->cleanup = ker_flow_ring_cleanup(ops->rx);
    return NULL;
}

static struct rte_mbuf *packet(struct ker_packet_pool *, uint8_t, bool);
struct producer_fixture {
    struct ker_packet_pool *pool;
    struct ker_tx_ring ring;
    struct ker_flow_ring *adapter;
    pthread_barrier_t phase;
    unsigned int lcore;
    int wrong_poll, wrong_cancel, wrong_cleanup;
};
static void barrier(struct producer_fixture *p)
{
    int rc = pthread_barrier_wait(&p->phase);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *registered_producer(void *arg)
{
    struct producer_fixture *p = arg;
    CHECK(rte_thread_register() == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    p->lcore = rte_lcore_id();
    CHECK(p->lcore != LCORE_ID_ANY);
    CHECK(ker_tx_ring_init(&p->ring, "flow_ring_remote_source", 4, SOCKET_ID_ANY) == 0);
    barrier(p); /* Ring initialization published to the consumer. */
    barrier(p); /* Main attached the consumer and authorized traffic. */
    struct rte_mbuf *out = NULL;
    p->wrong_poll = ker_flow_ring_poll(p->adapter, 1);
    p->wrong_cancel = ker_flow_ring_cancel(p->adapter, &out);
    p->wrong_cleanup = ker_flow_ring_cleanup(p->adapter);
    CHECK(ker_tx_ring_sink(packet(p->pool, 7, true), &p->ring) == 0);
    CHECK(ker_tx_ring_sink(packet(p->pool, 8, true), &p->ring) == 0);
    barrier(p); /* Both enqueues are visible to main. */
    barrier(p); /* Adapter detached; source is safe to clean up. */
    CHECK(ker_tx_ring_cleanup(&p->ring) == 0);
    CHECK(ker_memory_shutdown() == 0);
    rte_thread_unregister();
    return NULL;
}
static void receive(void *arg, const struct ker_flow_key *key, struct rte_mbuf *packet)
{
    (void)arg; CHECK((key->domain == 7 || key->domain == 8) && key->protocol == IPPROTO_UDP);
    if (active_rx && active_rx->polling) {
        struct rte_mbuf *out = NULL;
        CHECK(ker_flow_ring_poll(active_rx, 1) == -EBUSY);
        CHECK(ker_flow_ring_cancel(active_rx, &out) == -EBUSY && !out);
        CHECK(ker_flow_ring_cleanup(active_rx) == -EBUSY);
    }
    CHECK(received < sizeof(ids));
    ids[received++] = *rte_pktmbuf_mtod_offset(packet, uint8_t *, 42);
    ker_packet_free(packet);
}
static struct rte_mbuf *packet(struct ker_packet_pool *pool, uint8_t id, bool valid)
{
    struct rte_mbuf *m = ker_packet_alloc(pool); CHECK(m);
    uint8_t *b = (uint8_t *)rte_pktmbuf_append(m, 43); CHECK(b);
    memset(b, 0, 43); b[12] = valid ? 8 : 0x88; b[13] = valid ? 0 : 0xb5;
    b[14] = 0x45; b[16] = 0; b[17] = 29; b[22] = 64; b[23] = IPPROTO_UDP;
    b[26] = 192; b[29] = 1; b[30] = 10; b[33] = 1;
    b[34] = 0x04; b[35] = 0xd2; b[36] = 1; b[37] = 0xbb;
    b[38] = 0; b[39] = 9; b[42] = id;
    return m;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_packet_pool pool = {0};
    CHECK(ker_packet_pool_init(&pool, "flow_ring_pool", 31, 0, 256, SOCKET_ID_ANY) == 0);
    uint16_t owners[KER_FLOW_BUCKETS];
    for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i) owners[i] = 1;
    struct ker_flow_fabric fabric = {0};
    struct rte_mbuf *key_packet = packet(&pool, 0, true);
    struct ker_flow_special local = {0};
    CHECK(ker_flow_parse(key_packet, 8, KER_FLOW_INGRESS, &local.key) == 0);
    rte_pktmbuf_free(key_packet);
    local.owner = 0;
    struct ker_flow_config fc = {.worker_count=2, .bucket_owner=owners, .special=&local,
        .special_count=1, .inbox_capacity=1, .name="flow_ring_fabric", .socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&fabric, &fc) == 0);
    struct ker_worker worker = {0}, owner_worker = {0};
    struct ker_flow_context context = {0}, owner_context = {0};
    struct ker_worker_config wc = {.timer_budget=1, .handoff_budget=1};
    CHECK(ker_worker_init(&worker, &pool, &wc, &(struct ker_worker_ops){0}) == 0);
    CHECK(ker_flow_attach(&context, &fabric, &worker, 0, receive, NULL) == 0);
    CHECK(ker_worker_init(&owner_worker, &pool, &wc, &(struct ker_worker_ops){0}) == 0);
    CHECK(ker_flow_attach(&owner_context, &fabric, &owner_worker, 1, receive, NULL) == 0);
    struct ker_tx_ring source = {0}; struct ker_flow_ring rx = {0};
    CHECK(ker_tx_ring_init(&source, "flow_ring_source", 8, SOCKET_ID_ANY) == 0);
    struct ker_flow_ring competitor = {0};
    CHECK(ker_flow_ring_init(&competitor, &source, &context, 7, (enum ker_flow_direction)9) == -EINVAL);
    CHECK(!source.consumers && !context.flow_ring_live);
    CHECK(ker_flow_ring_init(&rx, &source, &context, 7, KER_FLOW_INGRESS) == 0);
    CHECK(ker_flow_ring_init(&competitor, &source, &context, 7, KER_FLOW_INGRESS) == -EBUSY);
    active_rx = &rx;
    CHECK(source.consumers == 1 && context.flow_ring_live == 1);
    worker.polling = true;
    struct ker_flow_ring during_poll = {0};
    CHECK(ker_flow_ring_init(&during_poll, &source, &context, 7, KER_FLOW_INGRESS) == -EBUSY);
    CHECK(ker_flow_ring_cleanup(&rx) == -EBUSY);
    worker.polling = false;
    CHECK(ker_tx_ring_take(&source, &(struct rte_mbuf *){0}) == -EBUSY);
    CHECK(ker_flow_detach(&context) == -EBUSY);
    CHECK(ker_worker_cleanup(&worker) == -EBUSY);
    CHECK(ker_tx_ring_cleanup(&source) == -EBUSY);
    struct foreign_ops foreign = {.rx = &rx};
    pthread_t foreign_thread;
    CHECK(pthread_create(&foreign_thread, NULL, foreign_lifecycle, &foreign) == 0);
    CHECK(pthread_join(foreign_thread, NULL) == 0);
    CHECK(foreign.poll == -EXDEV && foreign.cancel == -EXDEV && foreign.cleanup == -EXDEV);
    CHECK(ker_flow_ring_poll(&rx, 0) == 0);
    struct rte_mbuf *occupier = packet(&pool, 9, true);
    CHECK(ker_flow_submit(&context, 7, KER_FLOW_INGRESS, &occupier) == 0 && !occupier);
    CHECK(ker_tx_ring_sink(packet(&pool, 1, true), &source) == 0);
    CHECK(ker_tx_ring_sink(packet(&pool, 2, true), &source) == 0);
    CHECK(ker_flow_ring_poll(&rx, 1) == -ENOBUFS && rx.pending && rx.last_completed == 0);
    CHECK(ker_flow_poll(&owner_context, 1) == 1 && received == 1 && ids[0] == 9);
    CHECK(ker_flow_ring_poll(&rx, UINT_MAX) == -EOVERFLOW);
    CHECK(ker_flow_ring_poll(&rx, 1) == 1 && !rx.pending);
    CHECK(ker_flow_ring_poll(&rx, 1) == -ENOBUFS && rx.pending);
    CHECK(ker_flow_poll(&owner_context, 1) == 1 && received == 2 && ids[1] == 1);
    CHECK(ker_flow_ring_poll(&rx, 1) == 1);
    CHECK(ker_flow_poll(&owner_context, 1) == 1 && received == 3 && ids[2] == 2);
    CHECK(rx.last_completed == 1 && rx.last_dropped == 0 && rx.last_error == 0);
    CHECK(ker_tx_ring_sink(packet(&pool, 3, false), &source) == 0);
    CHECK(ker_flow_ring_poll(&rx, 1) == 1 && rx.last_dropped == 1 && rx.last_error == -ENOTSUP);
    CHECK(ker_flow_ring_poll(&rx, 0) == 0 && rx.last_completed == 1 &&
        rx.last_dropped == 1 && rx.last_error == -ENOTSUP);
    CHECK(ker_flow_detach(&owner_context) == 0);
    struct rte_mbuf *cancel_head = packet(&pool, 4, true);
    struct rte_mbuf *cancel_tail = ker_packet_alloc(&pool); CHECK(cancel_tail);
    void *tail_bytes = rte_pktmbuf_append(cancel_tail, 20); CHECK(tail_bytes);
    memcpy(tail_bytes, rte_pktmbuf_mtod_offset(cancel_head, const uint8_t *, 23), 20);
    CHECK(rte_pktmbuf_trim(cancel_head, 20) == 0);
    CHECK(rte_pktmbuf_chain(cancel_head, cancel_tail) == 0);
    CHECK(ker_tx_ring_sink(cancel_head, &source) == 0);
    CHECK(ker_flow_ring_poll(&rx, 1) == -ESHUTDOWN && rx.pending);
    struct rte_mbuf *cancelled = NULL;
    CHECK(ker_flow_ring_cleanup(&rx) == -EBUSY);
    CHECK(ker_flow_ring_cancel(&rx, &cancelled) == 1 && cancelled == cancel_head);
    CHECK(cancelled->next == cancel_tail && cancelled->nb_segs == 2 && cancelled->pkt_len == 43);
    CHECK(rte_mbuf_refcnt_read(cancelled) == 1 && rte_mbuf_refcnt_read(cancel_tail) == 1);
    ker_packet_free(cancelled);
    cancelled = NULL;
    CHECK(ker_flow_attach(&owner_context, &fabric, &owner_worker, 1, receive, NULL) == 0);
    CHECK(ker_flow_ring_cancel(&rx, &cancelled) == 0 && !cancelled);
    CHECK(ker_flow_detach(&owner_context) == 0);
    CHECK(ker_tx_ring_sink(packet(&pool, 5, true), &source) == 0);
    CHECK(ker_flow_ring_poll(&rx, 1) == -ESHUTDOWN && rx.pending);
    CHECK(ker_flow_attach(&owner_context, &fabric, &owner_worker, 1, receive, NULL) == 0);
    CHECK(ker_flow_ring_poll(&rx, 1) == 1 && !rx.pending);
    CHECK(ker_flow_poll(&owner_context, 1) == 1 && received == 4 && ids[3] == 5);
    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_flow_ring_cancel(&rx, &sentinel) == 0 && sentinel == (void *)(uintptr_t)1);
    CHECK(ker_flow_ring_cleanup(&rx) == 0 && !source.consumers && !context.flow_ring_live);
    struct ker_flow_ring local_rx = {0};
    CHECK(ker_flow_ring_init(&local_rx, &source, &context, 8, KER_FLOW_INGRESS) == 0);
    active_rx = &local_rx;
    CHECK(ker_tx_ring_sink(packet(&pool, 6, true), &source) == 0);
    CHECK(ker_flow_ring_poll(&local_rx, 1) == 1 && received == 5 && ids[4] == 6);
    CHECK(ker_flow_ring_cleanup(&local_rx) == 0);
    active_rx = NULL;
    struct producer_fixture producer = {.pool = &pool};
    CHECK(pthread_barrier_init(&producer.phase, NULL, 2) == 0);
    pthread_t producer_thread;
    CHECK(pthread_create(&producer_thread, NULL, registered_producer, &producer) == 0);
    barrier(&producer);
    CHECK(producer.lcore != rte_lcore_id());
    struct ker_flow_ring producer_rx = {0};
    CHECK(ker_flow_ring_init(&producer_rx, &producer.ring, &context, 7, KER_FLOW_INGRESS) == 0);
    producer.adapter = &producer_rx;
    barrier(&producer);
    barrier(&producer);
    CHECK(producer.wrong_poll == -EXDEV && producer.wrong_cancel == -EXDEV &&
        producer.wrong_cleanup == -EXDEV);
    active_rx = &producer_rx;
    CHECK(ker_flow_ring_poll(&producer_rx, 2) == 1 && producer_rx.pending);
    CHECK(producer_rx.last_completed == 1 && producer_rx.last_error == -ENOBUFS &&
        producer_rx.last_dropped == 0);
    CHECK(ker_flow_poll(&owner_context, 1) == 1);
    CHECK(ker_flow_ring_poll(&producer_rx, 1) == 1 && !producer_rx.pending);
    CHECK(ker_flow_poll(&owner_context, 1) == 1);
    CHECK(received == 7 && ids[5] == 7 && ids[6] == 8);
    CHECK(ker_flow_ring_cleanup(&producer_rx) == 0);
    active_rx = NULL;
    barrier(&producer);
    CHECK(pthread_join(producer_thread, NULL) == 0);
    CHECK(pthread_barrier_destroy(&producer.phase) == 0);
    CHECK(ker_flow_detach(&context) == 0);
    CHECK(ker_flow_detach(&owner_context) == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_worker_cleanup(&owner_worker) == 0);
    CHECK(ker_tx_ring_cleanup(&source) == 0);
    CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Flow ring adapter: bounded polling, ownership pins and terminal packet drop passed");
    return 0;
}
