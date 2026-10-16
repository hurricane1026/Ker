#include "check.h"
#include "eal.h"
#include "runtime/ethdev-tx.h"
#include "runtime/memory.h"
#include "runtime/skb.h"
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>

#define POOL_COUNT 63
#define HELD_CAPACITY (POOL_COUNT + 8)
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_ethdev_tx output;
static uint8_t expected[5][4096];
static size_t lengths[5];

struct reclaim_test {
    struct ker_ethdev_tx *tx;
    struct rte_mbuf **release;
    unsigned int calls;
    unsigned int expected_index;
    int result;
    int poll_reentry;
    int cleanup_reentry;
};

static int reclaim_one(uint16_t port, uint16_t queue, uint32_t free_count, void *arg)
{
    struct reclaim_test *test = arg;
    CHECK(port == test->tx->port_id && queue == test->tx->queue_id && free_count == 0);
    ++test->calls;
    test->poll_reentry = ker_ethdev_tx_poll(test->tx, 1);
    test->cleanup_reentry = ker_ethdev_tx_cleanup(test->tx);
    if (test->result) return test->result;
    if (!*test->release) return -EIO;
    CHECK((*test->release)->pkt_len == lengths[test->expected_index]);
    uint8_t bytes[4096];
    const void *read = rte_pktmbuf_read(*test->release, 0,
        (uint16_t)(*test->release)->pkt_len, bytes);
    CHECK(read);
    if (read != bytes) memcpy(bytes, read, (*test->release)->pkt_len);
    CHECK(memcmp(bytes, expected[test->expected_index], lengths[test->expected_index]) == 0);
    rte_pktmbuf_free(*test->release);
    *test->release = NULL;
    return 1;
}

static void *foreign_poll(void *arg)
{
    int *result = arg;
    *result = ker_ethdev_tx_poll(&output, 1);
    return NULL;
}

static struct sk_buff *packet(unsigned int index, size_t len)
{
    struct sk_buff *skb = NULL;
    uint8_t *data = NULL;
    CHECK(ker_skb_alloc(&context, len, 64, &skb) == 0);
    CHECK(ker_skb_put(skb, len, &data) == 0);
    lengths[index] = len;
    for (size_t i = 0; i < len; ++i)
        data[i] = expected[index][i] = (uint8_t)(index * 53U + i * 17U + 9U);
    return skb;
}

static void inspect_one(struct rte_ring *ring, unsigned int index, bool chained)
{
    void *object = NULL;
    CHECK(rte_ring_dequeue(ring, &object) == 0);
    struct rte_mbuf *m = object;
    CHECK(m->pkt_len == lengths[index]);
    CHECK((m->nb_segs > 1) == chained);
    uint8_t bytes[4096];
    const void *read = rte_pktmbuf_read(m, 0, m->pkt_len, bytes);
    CHECK(read);
    if (read != bytes) memcpy(bytes, read, m->pkt_len);
    CHECK(memcmp(bytes, expected[index], lengths[index]) == 0);
    rte_pktmbuf_free(m);
}

static void test_real_ethdev_tx(void)
{
    struct rte_ring *tx_ring = rte_ring_create("ker_ethdev_tx_ring", 4,
        rte_socket_id(), RING_F_EXACT_SZ);
    struct rte_ring *rx_ring = rte_ring_create("ker_ethdev_rx_ring", 4,
        rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(tx_ring && rx_ring);
    struct rte_ring *txq[] = {tx_ring}, *rxq[] = {rx_ring};
    int port = rte_eth_from_rings("ker_ethdev_ring", rxq, 1, txq, 1, rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf conf = {0};
    conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &conf) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);

    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ethdev_tx_skb", POOL_COUNT, 0, 8192, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ethdev_tx_ctx") == 0);
    struct ker_ethdev_tx invalid = {0};
    CHECK(ker_ethdev_tx_init(&invalid, &context, UINT16_MAX, 0, 1, 4096, 1024) == -ENODEV);
    CHECK(ker_ethdev_tx_init(&invalid, &context, (uint16_t)port, 1, 1, 4096, 1024) == -EINVAL);
    struct ker_skb_context wrong_owner = context;
    wrong_owner.lcore = context.lcore == 0 ? 1 : 0;
    CHECK(ker_ethdev_tx_init(&invalid, &wrong_owner, (uint16_t)port, 0, 1, 4096, 1024) == -EXDEV);
    struct rte_ring *no_multi_tx = rte_ring_create("ker_no_multi_tx", 4,
        rte_socket_id(), RING_F_EXACT_SZ);
    struct rte_ring *no_multi_rx = rte_ring_create("ker_no_multi_rx", 4,
        rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(no_multi_tx && no_multi_rx);
    struct rte_ring *no_multi_txq[] = {no_multi_tx}, *no_multi_rxq[] = {no_multi_rx};
    int no_multi_port = rte_eth_from_rings("ker_no_multi_ring", no_multi_rxq, 1,
        no_multi_txq, 1, rte_socket_id());
    CHECK(no_multi_port >= 0);
    struct rte_eth_conf no_multi_conf = {0};
    CHECK(rte_eth_dev_configure((uint16_t)no_multi_port, 1, 1, &no_multi_conf) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)no_multi_port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(ker_ethdev_tx_init(&invalid, &context, (uint16_t)no_multi_port, 0, 1,
        4096, 1024) == -ENOTSUP);
    CHECK(rte_eth_dev_close((uint16_t)no_multi_port) == 0);
    rte_ring_free(no_multi_rx);
    rte_ring_free(no_multi_tx);
    CHECK(ker_ethdev_tx_init(&output, &context, (uint16_t)port, 0, 10,
        65536, 1024) == 0);
    CHECK(output.exporter.ethdev_refs == 1);
    CHECK(output.max_segments >= 4);
    CHECK(ker_tx_export_cleanup(&output.exporter) == -EBUSY);

    /* Hold a completed TX copy to model a PMD that defers mbuf reclamation. */
    struct sk_buff *s = packet(0, 64);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    CHECK(ker_ethdev_tx_poll(&output, 1) == 1);
    CHECK(output.last_cleanup_error == -ENOTSUP);
    void *deferred_object = NULL;
    CHECK(rte_ring_dequeue(tx_ring, &deferred_object) == 0);
    struct rte_mbuf *deferred = deferred_object;

    /* Pool exhaustion does not hand anything to the ethdev or lose the skb. */
    s = packet(0, 64);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    pthread_t foreign;
    int foreign_result = 0;
    CHECK(pthread_create(&foreign, NULL, foreign_poll, &foreign_result) == 0);
    CHECK(pthread_join(foreign, NULL) == 0 && foreign_result == -EXDEV);
    CHECK(output.exporter.packets == 1 && output.exporter.queue.context == &context);
    CHECK(ker_ethdev_tx_cleanup(&output) == -EBUSY && output.initialized &&
        output.exporter.ethdev_refs == 1);
    struct sk_buff *offload = packet(4, 64);
    offload->ip_summed = CHECKSUM_PARTIAL;
    CHECK(ker_tx_export_enqueue(&output.exporter, &offload) == -ENOTSUP && offload);
    CHECK(ker_skb_free(offload) == 0);
    struct rte_mbuf *held[HELD_CAPACITY];
    unsigned int held_count = 0;
    while (held_count < HELD_CAPACITY && (held[held_count] = rte_pktmbuf_alloc(pool.mbufs)))
        ++held_count;
    CHECK(held_count > 0);
    struct reclaim_test reclaim = { .tx = &output, .release = &deferred,
        .expected_index = 0, .result = -EIO };
    CHECK(ker_ethdev_tx_poll_with_reclaim(&output, 0, reclaim_one, &reclaim) == 0);
    CHECK(ker_ethdev_tx_poll_with_reclaim(&output, UINT_MAX, reclaim_one, &reclaim) == -EOVERFLOW);
    CHECK(reclaim.calls == 0);
    CHECK(ker_ethdev_tx_poll(&output, 1) == -ENOMEM);
    CHECK(ker_ethdev_tx_poll_with_reclaim(&output, 1, reclaim_one, &reclaim) == -EIO);
    CHECK(reclaim.calls == 1 && reclaim.poll_reentry == -EBUSY &&
        reclaim.cleanup_reentry == -EBUSY && deferred != NULL &&
        output.last_cleanup_error == -EIO && output.exporter.pending &&
        output.exporter.packets == 1);
    reclaim.result = 0;
    CHECK(ker_ethdev_tx_poll_with_reclaim(&output, 1, reclaim_one, &reclaim) == 1);
    CHECK(reclaim.calls == 2 && reclaim.poll_reentry == -EBUSY &&
        reclaim.cleanup_reentry == -EBUSY && deferred == NULL);
    for (unsigned int i = 0; i < held_count; ++i) rte_pktmbuf_free(held[i]);
    CHECK(output.last_cleanup_error == 0);
    inspect_one(tx_ring, 0, false);

    /* A successful prefix followed by ENOMEM makes progress after next-poll reclaim. */
    s = packet(1, 4096);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    s = packet(2, 4096);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    held_count = 0;
    while (held_count < HELD_CAPACITY && (held[held_count] = rte_pktmbuf_alloc(pool.mbufs)))
        ++held_count;
    CHECK(held_count > 4);
    for (unsigned int i = 0; i < 4; ++i) rte_pktmbuf_free(held[i]);
    held[0] = held[1] = held[2] = held[3] = NULL;
    CHECK(ker_ethdev_tx_poll(&output, 2) == 1);
    CHECK(output.exporter.last_error == -ENOMEM && output.exporter.pending &&
        output.exporter.packets == 1);
    deferred_object = NULL;
    CHECK(rte_ring_dequeue(tx_ring, &deferred_object) == 0);
    deferred = deferred_object;
    reclaim.expected_index = 1;
    reclaim.result = 0;
    CHECK(ker_ethdev_tx_poll_with_reclaim(&output, 1, reclaim_one, &reclaim) == 1);
    CHECK(!output.exporter.pending && output.exporter.packets == 0 && deferred == NULL);
    inspect_one(tx_ring, 2, true);
    for (unsigned int i = 4; i < held_count; ++i) rte_pktmbuf_free(held[i]);

    /* The upstream 64-byte and 4096-byte cases traverse the real PMD. */
    s = packet(1, 64);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    s = packet(2, 4096);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    CHECK(ker_ethdev_tx_poll(&output, 2) == 2);
    CHECK(output.last_cleanup_error == -ENOTSUP);
    inspect_one(tx_ring, 1, false);
    inspect_one(tx_ring, 2, true);

    /* Exercise a reported segment ceiling; net_ring itself reports none. */
    uint16_t reported_max_segments = output.max_segments;
    output.max_segments = 3;
    s = packet(4, 4096);
    CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    CHECK(ker_ethdev_tx_poll(&output, 1) == -ENOTSUP && output.exporter.pending);
    output.max_segments = reported_max_segments;
    CHECK(ker_ethdev_tx_poll(&output, 1) == 1 && !output.exporter.pending);
    inspect_one(tx_ring, 4, true);

    /* Fill the exact-sized ring, retain the next copy, then retry in FIFO order. */
    for (unsigned int i = 0; i < 5; ++i) {
        s = packet(i, 64 + i);
        CHECK(ker_tx_export_enqueue(&output.exporter, &s) == 0 && !s);
    }
    CHECK(ker_ethdev_tx_poll(&output, 5) == 4);
    CHECK(output.exporter.pending && output.exporter.last_error == -EAGAIN);
    inspect_one(tx_ring, 0, false);
    CHECK(ker_ethdev_tx_poll(&output, 1) == 1 && !output.exporter.pending);
    inspect_one(tx_ring, 1, false);
    inspect_one(tx_ring, 2, false);
    inspect_one(tx_ring, 3, false);
    inspect_one(tx_ring, 4, false);
    struct rte_eth_stats stats;
    memset(&stats, 0, sizeof(stats));
    CHECK(rte_eth_stats_get((uint16_t)port, &stats) == 0);
    CHECK(stats.opackets == 12);

    CHECK(ker_ethdev_tx_cleanup(&output) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(rte_eth_dev_stop((uint16_t)port) == 0);
    CHECK(rte_eth_dev_close((uint16_t)port) == 0);
    rte_ring_free(rx_ring);
    rte_ring_free(tx_ring);
    CHECK(ker_memory_shutdown() == 0);
}

int main(void)
{
    ker_test_eal_init();
    test_real_ethdev_tx();
    rte_eal_cleanup();
    return 0;
}
