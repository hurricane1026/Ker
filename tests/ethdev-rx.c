#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/rx-ring.h"
#include "runtime/skb.h"
#include "runtime/tx-ring.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 127
#define HELD_CAPACITY (POOL_COUNT + 16)
#define FRAME_LEN 60
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_protocol_handler handler;
static struct ker_ethdev_rx input;
static uint8_t expected[8][FRAME_LEN - ETH_HLEN];
static unsigned int expected_order[8], expected_count, received;
static bool test_reentry;
static int poll_reentry_result, cleanup_reentry_result;

static void expect_delivery(unsigned int id)
{
    CHECK(expected_count < 8);
    expected_order[expected_count++] = id;
}

static int receive_ip(struct sk_buff *skb, struct ker_protocol_handler *ph,
    struct net_device *original, void *arg)
{
    (void)arg;
    CHECK(ph == &handler && ph->runtime == &runtime && ph->device == &device);
    CHECK(original == device.native && skb->dev == device.native);
    CHECK(skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(received < expected_count && skb->len == sizeof(expected[0]));
    CHECK(memcmp(skb->data, expected[expected_order[received]], skb->len) == 0);
    received++;
    if (test_reentry) {
        test_reentry = false;
        poll_reentry_result = ker_ethdev_rx_poll(&input, 1);
        cleanup_reentry_result = ker_ethdev_rx_cleanup(&input);
    }
    CHECK(ker_skb_free(skb) == 0);
    return NET_RX_SUCCESS;
}

static struct rte_mbuf *make_frame(unsigned int id, bool malformed, bool split)
{
    uint16_t length = malformed ? 10 : FRAME_LEN;
    uint8_t frame[FRAME_LEN];
    uint8_t *bytes = frame;
    memset(bytes, (int)(0x20 + id), length);
    if (!malformed) {
        struct rte_ether_hdr *ether = (struct rte_ether_hdr *)bytes;
        ether->dst_addr.addr_bytes[0] = 2;
        ether->src_addr.addr_bytes[0] = 4;
        ether->ether_type = rte_cpu_to_be_16(ETH_P_IP);
        uint8_t *ip = bytes + ETH_HLEN;
        ip[0] = 0x45;
        ip[2] = 0;
        ip[3] = FRAME_LEN - ETH_HLEN;
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        memcpy(expected[id], bytes + ETH_HLEN, FRAME_LEN - ETH_HLEN);
    }
    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool.mbufs);
    CHECK(packet);
    if (split && !malformed) {
        const uint16_t first_length = 10;
        uint8_t *first = rte_pktmbuf_append(packet, first_length);
        struct rte_mbuf *tail = rte_pktmbuf_alloc(pool.mbufs);
        CHECK(first && tail);
        uint8_t *second = rte_pktmbuf_append(tail, length - first_length);
        CHECK(second);
        memcpy(first, frame, first_length);
        memcpy(second, frame + first_length, length - first_length);
        CHECK(rte_pktmbuf_chain(packet, tail) == 0);
        return packet;
    }
    uint8_t *linear = rte_pktmbuf_append(packet, length);
    CHECK(linear);
    memcpy(linear, frame, length);
    return packet;
}

static void inject(struct rte_ring *rx_ring, unsigned int id, bool malformed,
    bool split, bool expect)
{
    struct rte_mbuf *packet = make_frame(id, malformed, split);
    CHECK(rte_ring_enqueue(rx_ring, packet) == 0);
    if (expect) expect_delivery(id);
}

static int worker_rx(void *arg, unsigned int budget)
{
    return ker_ethdev_rx_poll(arg, budget);
}

struct poll_result { int result; };
static void *foreign_poll(void *arg)
{
    struct poll_result *result = arg;
    result->result = ker_ethdev_rx_poll(&input, 1);
    return NULL;
}

static void exhaust_pool(struct rte_mbuf **held, unsigned int *count)
{
    *count = 0;
    while (*count < HELD_CAPACITY && (held[*count] = rte_pktmbuf_alloc(pool.mbufs)))
        ++*count;
}

static void release_pool(struct rte_mbuf **held, unsigned int count,
    unsigned int first)
{
    for (unsigned int i = first; i < count; ++i)
        rte_pktmbuf_free(held[i]);
}

static void test_ethdev_receive(void)
{
    struct rte_ring *rx_ring = rte_ring_create("ker_ethdev_rx_in", 8,
        rte_socket_id(), RING_F_EXACT_SZ);
    struct rte_ring *tx_ring = rte_ring_create("ker_ethdev_rx_out", 8,
        rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(rx_ring && tx_ring);
    struct rte_ring *rxq[] = {rx_ring}, *txq[] = {tx_ring};
    int port = rte_eth_from_rings("ker_ethdev_rx_ring", rxq, 1, txq, 1,
        rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf conf = {0};
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &conf) == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ethdev_rx_pool", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
        pool.mbufs) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ethdev_rx_context") == 0);
    static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "erx0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_protocol_register(&runtime, &handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), receive_ip, NULL) == 0);

    struct ker_ethdev_rx invalid = {0};
    CHECK(ker_ethdev_rx_init(&invalid, &device, &runtime, UINT16_MAX, 0, 0) == -ENODEV);
    CHECK(ker_ethdev_rx_init(&invalid, &device, &runtime, (uint16_t)port, 1, 0) == -EINVAL);
    struct ker_skb_context wrong_context = context;
    wrong_context.lcore = context.lcore == 0 ? 1 : 0;
    struct ker_eth_device wrong_device = device;
    wrong_device.context = &wrong_context;
    CHECK(ker_ethdev_rx_init(&invalid, &wrong_device, &runtime, (uint16_t)port, 0, 0) == -EINVAL);

    struct ker_tx_ring software_queue = {0};
    struct ker_rx_ring software_rx = {0};
    CHECK(ker_tx_ring_init(&software_queue, "ethdev_rx_conflict", 2,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_rx_ring_init(&software_rx, &software_queue, &device, &runtime, 0) == 0);

    CHECK(ker_ethdev_rx_init(&invalid, &device, &runtime, (uint16_t)port, 0, 0) == -EBUSY);
    CHECK(ker_rx_ring_cleanup(&software_rx) == 0);
    CHECK(ker_tx_ring_cleanup(&software_queue) == 0);
    CHECK(ker_ethdev_rx_init(&input, &device, &runtime, (uint16_t)port, 0, 0) == 0);
    CHECK(device.rx_ring_live == 1 && runtime.rx_ring_live == 1);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(ker_receive_runtime_cleanup(&runtime) == -EBUSY);
    struct ker_tx_ring conflicting_queue = {0};
    struct ker_rx_ring conflicting_rx = {0};
    CHECK(ker_tx_ring_init(&conflicting_queue, "ethdev_rx_conflict2", 2,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_rx_ring_init(&conflicting_rx, &conflicting_queue, &device, &runtime,
        0) == -EBUSY);
    CHECK(ker_tx_ring_cleanup(&conflicting_queue) == 0);
    struct ker_eth_device second_device = {0};
    CHECK(ker_eth_device_init(&second_device, &context, "erx1", 2, mac) == 0);
    struct ker_ethdev_rx conflict = {0};
    CHECK(ker_ethdev_rx_init(&conflict, &second_device, &runtime,
        (uint16_t)port, 0, 0) == -EBUSY);
    CHECK(ker_eth_device_cleanup(&second_device) == 0);

    struct ker_worker worker = {0};
    struct ker_worker_config worker_config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops worker_ops = {.rx = worker_rx, .arg = &input};
    CHECK(ker_worker_init(&worker, &pool, &worker_config, &worker_ops) == 0);
    inject(rx_ring, 0, false, false, true);
    inject(rx_ring, 1, false, false, true);
    inject(rx_ring, 2, false, true, true);
    struct ker_worker_result progress = {0};
    test_reentry = true;
    CHECK(ker_worker_poll(&worker, 0, &progress) == 0 && progress.rx == 1 && received == 1);
    CHECK(poll_reentry_result == -EBUSY && cleanup_reentry_result == -EBUSY);
    CHECK(rte_ring_count(rx_ring) == 2);
    CHECK(ker_worker_poll(&worker, 1, &progress) == 0 && progress.rx == 1 && received == 2);
    CHECK(ker_worker_poll(&worker, 2, &progress) == 0 && progress.rx == 1 && received == 3);

    inject(rx_ring, 3, true, false, false);
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && input.last_dropped == 1 &&
        input.last_error == -EMSGSIZE && received == 3);

    /* Pending ownership survives pool pressure and is retried before later RX. */
    inject(rx_ring, 4, false, false, true);
    inject(rx_ring, 5, false, false, true);
    struct rte_mbuf *held[HELD_CAPACITY];
    unsigned int held_count;
    exhaust_pool(held, &held_count);
    CHECK(held_count > 0);
    CHECK(ker_ethdev_rx_poll(&input, 2) == -ENOMEM && input.pending &&
        input.last_error == -ENOMEM && received == 3 && rte_ring_count(rx_ring) == 1);
    CHECK(ker_ethdev_rx_cleanup(&input) == -EBUSY);
    pthread_t thread;
    struct poll_result foreign = {0};
    CHECK(pthread_create(&thread, NULL, foreign_poll, &foreign) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && foreign.result == -EXDEV);
    rte_pktmbuf_free(held[0]);
    held[0] = NULL;
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && !input.pending && received == 4 &&
        rte_ring_count(rx_ring) == 1);
    CHECK(ker_ethdev_rx_poll(&input, 1) == 1 && received == 5 &&
        rte_ring_count(rx_ring) == 0);
    release_pool(held, held_count, 1);

    /* Cancel transfers a pending PMD-owned chain back to the caller. */
    inject(rx_ring, 6, false, false, false);
    exhaust_pool(held, &held_count);
    CHECK(held_count > 0);
    CHECK(ker_ethdev_rx_poll(&input, 1) == -ENOMEM && input.pending);
    struct rte_mbuf *cancelled = NULL;
    CHECK(ker_ethdev_rx_cancel(&input, &cancelled) == 1 && cancelled && !input.pending);
    rte_pktmbuf_free(cancelled);
    release_pool(held, held_count, 0);
    CHECK(ker_ethdev_rx_cancel(&input, &cancelled) == 0);

    struct rte_eth_stats stats = {0};
    CHECK(rte_eth_stats_get((uint16_t)port, &stats) == 0 && stats.ipackets == 7);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_ethdev_rx_cleanup(&input) == 0);
    CHECK(device.rx_ring_live == 0 && runtime.rx_ring_live == 0);
    CHECK(ker_protocol_unregister(&handler) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(rte_eth_dev_stop((uint16_t)port) == 0);
    CHECK(rte_eth_dev_close((uint16_t)port) == 0);
    rte_ring_free(tx_ring);
    rte_ring_free(rx_ring);
    CHECK(ker_memory_shutdown() == 0);
}

int main(void)
{
    ker_test_eal_init();
    test_ethdev_receive();
    rte_eal_cleanup();
    return 0;
}
