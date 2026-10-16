#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 127
#define HELD_CAPACITY (POOL_COUNT + 8)
#define FRAME_LEN 60
#define IP_PAYLOAD_LEN (FRAME_LEN - ETH_HLEN)
#define EXPECTED_COUNT 2

struct callback_epoch {
    struct ker_eth_device *device;
    struct ker_receive_runtime *runtime;
    struct ker_protocol_handler *handler;
    uint8_t generation;
    unsigned int received;
    uint8_t expected[EXPECTED_COUNT][IP_PAYLOAD_LEN];
};

static uint16_t checksum(const uint8_t *bytes, size_t length)
{
    uint32_t sum = 0;
    while (length >= 2) {
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length) sum += (uint32_t)bytes[0] << 8;
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static struct rte_mbuf *make_packet(struct ker_packet_pool *pool,
    uint8_t generation, uint8_t marker, uint8_t expected[IP_PAYLOAD_LEN])
{
    uint8_t frame[FRAME_LEN];
    memset(frame, marker, sizeof(frame));
    struct rte_ether_hdr *ether = (struct rte_ether_hdr *)frame;
    ether->dst_addr.addr_bytes[0] = 2;
    ether->src_addr.addr_bytes[0] = 4;
    ether->ether_type = rte_cpu_to_be_16(ETH_P_IP);
    uint8_t *ip = frame + ETH_HLEN;
    ip[0] = 0x45;
    ip[2] = 0;
    ip[3] = IP_PAYLOAD_LEN;
    ip[8] = 64;
    ip[9] = IPPROTO_UDP;
    ip[12] = 10;
    ip[13] = generation;
    ip[14] = 0;
    ip[15] = marker;
    ip[16] = 10;
    ip[17] = generation;
    ip[18] = 1;
    ip[19] = marker;
    ip[20] = generation;
    ip[21] = marker;
    ip[10] = 0;
    ip[11] = 0;
    uint16_t ip_sum = checksum(ip, 20);
    ip[10] = (uint8_t)(ip_sum >> 8);
    ip[11] = (uint8_t)ip_sum;
    memcpy(expected, ip, IP_PAYLOAD_LEN);

    struct rte_mbuf *packet = rte_pktmbuf_alloc(pool->mbufs);
    CHECK(packet);
    uint8_t *data = rte_pktmbuf_append(packet, sizeof(frame));
    CHECK(data);
    memcpy(data, frame, sizeof(frame));
    return packet;
}

static int receive_epoch(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    struct callback_epoch *epoch = arg;
    CHECK(epoch && epoch->handler == handler && epoch->runtime == handler->runtime &&
        epoch->device == handler->device && original == epoch->device->native &&
        skb->dev == epoch->device->native &&
        skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(epoch->received < EXPECTED_COUNT && skb->len == IP_PAYLOAD_LEN);
    CHECK(memcmp(skb->data, epoch->expected[epoch->received], IP_PAYLOAD_LEN) == 0);
    CHECK(skb->data[0] == 0x45 && skb->data[9] == IPPROTO_UDP &&
        skb->data[20] == epoch->generation && checksum(skb->data, 20) == 0);
    epoch->received++;
    CHECK(ker_skb_free(skb) == 0);
    return NET_RX_SUCCESS;
}

static int worker_rx(void *arg, unsigned int budget)
{
    return ker_ethdev_rx_poll(arg, budget);
}

static void exhaust_pool(struct ker_packet_pool *pool, struct rte_mbuf **held,
    unsigned int *count)
{
    *count = 0;
    while (*count < HELD_CAPACITY && (held[*count] = rte_pktmbuf_alloc(pool->mbufs)))
        ++*count;
}

static void release_pool(struct rte_mbuf **held, unsigned int count)
{
    for (unsigned int i = 0; i < count; ++i)
        rte_pktmbuf_free(held[i]);
}

static void test_teardown_rebind(void)
{
    struct rte_ring *rx0 = rte_ring_create("ker_rebind_rx0", 8,
        rte_socket_id(), RING_F_EXACT_SZ);
    struct rte_ring *tx = rte_ring_create("ker_rebind_tx", 8,
        rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(rx0 && tx);
    struct rte_ring *rx_queues[] = {rx0};
    struct rte_ring *tx_queues[] = {tx};
    int port = rte_eth_from_rings("ker_ethdev_rebind", rx_queues, 1,
        tx_queues, 1, rte_socket_id());
    CHECK(port >= 0);
    struct rte_eth_conf config = {0};
    CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1, &config) == 0);

    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_packet_pool pool_a = {0}, pool_b = {0};
    CHECK(ker_packet_pool_init(&pool_a, "rebind_pool_a", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
        pool_a.mbufs) == 0);
    CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) == 0);
    CHECK(rte_eth_dev_start((uint16_t)port) == 0);

    struct ker_skb_context context = {0};
    struct ker_eth_device device = {0};
    struct ker_receive_runtime runtime = {0};
    struct ker_protocol_handler handler = {0};
    struct ker_ethdev_rx rx = {0};
    struct callback_epoch first = {.device = &device, .runtime = &runtime,
        .handler = &handler, .generation = 0xa1};
    static const uint8_t mac[ETH_ALEN] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_skb_context_init(&context, &pool_a, "rebind_context_a") == 0);
    CHECK(ker_eth_device_init(&device, &context, "rebind0", 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_protocol_register(&runtime, &handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), receive_epoch, &first) == 0);
    CHECK(ker_ethdev_rx_init(&rx, &device, &runtime, (uint16_t)port, 0, 0) == 0);
    CHECK(device.rx_ring_live == 1 && runtime.rx_ring_live == 1);

    /* Prove the first callback generation is live before teardown. */
    struct ker_worker worker_a = {0};
    struct ker_worker_config worker_config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops worker_ops = {.rx = worker_rx, .arg = &rx};
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_init(&worker_a, &pool_a, &worker_config, &worker_ops) == 0);
    struct rte_mbuf *first_packet = make_packet(&pool_a, first.generation, 0x10,
        first.expected[0]);
    CHECK(rte_ring_enqueue(rx0, first_packet) == 0);
    CHECK(ker_worker_poll(&worker_a, 0, &progress) == 0 && progress.rx == 1 &&
        first.received == 1);
    CHECK(ker_worker_cleanup(&worker_a) == 0);

    /* Place a successor behind the pending packet on the same bound queue. */
    uint8_t next_expected[EXPECTED_COUNT][IP_PAYLOAD_LEN];
    struct rte_mbuf *pending = make_packet(&pool_a, first.generation, 0x11,
        first.expected[1]);
    CHECK(rte_ring_enqueue(rx0, pending) == 0);
    struct rte_mbuf *queued_old = make_packet(&pool_a, 0xb2, 0x21, next_expected[0]);
    CHECK(rte_ring_enqueue(rx0, queued_old) == 0 && rte_ring_count(rx0) == 2);
    struct rte_mbuf *held[HELD_CAPACITY];
    unsigned int held_count;
    exhaust_pool(&pool_a, held, &held_count);
    CHECK(held_count > 0);
    CHECK(ker_ethdev_rx_poll(&rx, 1) == -ENOMEM && rx.pending == pending);
    CHECK(ker_ethdev_rx_cleanup(&rx) == -EBUSY && device.rx_ring_live == 1 &&
        runtime.rx_ring_live == 1);
    struct rte_mbuf *cancelled = NULL;
    CHECK(ker_ethdev_rx_cancel(&rx, &cancelled) == 1 && cancelled == pending &&
        !rx.pending && cancelled->pkt_len == FRAME_LEN);
    rte_pktmbuf_free(cancelled);
    release_pool(held, held_count);

    /* The same bound queue retains its successor across adapter cleanup. */
    CHECK(rte_ring_count(rx0) == 1 && rte_mempool_avail_count(pool_a.mbufs) == POOL_COUNT - 1);
    CHECK(ker_ethdev_rx_cleanup(&rx) == 0 && !device.rx_ring_live &&
        !runtime.rx_ring_live && rte_ring_count(rx0) == 1);
    CHECK(ker_protocol_unregister(&handler) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_ring_count(rx0) == 1 && rte_mempool_avail_count(pool_a.mbufs) == POOL_COUNT - 1);

    /* Reuse the same adapter, device, runtime, handler, and context storage
     * on the same RX queue with a new generation and destination pool. Failed
     * initialization must
     * leave the zeroed adapter and all pins unchanged. */
    CHECK(ker_packet_pool_init(&pool_b, "rebind_pool_b", POOL_COUNT, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool_b, "rebind_context_b") == 0);
    CHECK(ker_eth_device_init(&device, &context, "rebind1", 2, mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    struct callback_epoch second = {.device = &device, .runtime = &runtime,
        .handler = &handler, .generation = 0xb2};
    memcpy(second.expected[0], next_expected[0], IP_PAYLOAD_LEN);
    CHECK(ker_ethdev_rx_init_profile(&rx, &device, &runtime,
        (uint16_t)port, 1, 0, KER_ETHDEV_RX_COPY_UNIQUE) == -EINVAL);
    CHECK(!rx.initialized && !rx.device && !rx.runtime && !rx.pending &&
        !device.rx_ring_live && !runtime.rx_ring_live);
    CHECK(ker_ethdev_rx_init_profile(&rx, &device, &runtime,
        (uint16_t)port, 0, 0, (enum ker_ethdev_rx_copy_profile)99) == -EINVAL);
    CHECK(!rx.initialized && !rx.device && !rx.runtime && !rx.pending &&
        !device.rx_ring_live && !runtime.rx_ring_live);
    CHECK(ker_protocol_register(&runtime, &handler, &device,
        rte_cpu_to_be_16(ETH_P_IP), receive_epoch, &second) == 0);
    CHECK(ker_ethdev_rx_init_profile(&rx, &device, &runtime, (uint16_t)port,
        0, 0, KER_ETHDEV_RX_COPY_UNIQUE) == 0);

    struct rte_mbuf *queued_new = make_packet(&pool_a, 0xb2, 0x23, next_expected[1]);
    memcpy(second.expected[1], next_expected[1], IP_PAYLOAD_LEN);
    CHECK(rte_ring_enqueue(rx0, queued_new) == 0 && rte_ring_count(rx0) == 2);
    struct ker_worker worker_b = {0};
    CHECK(ker_worker_init(&worker_b, &pool_b, &worker_config, &worker_ops) == 0);
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK(ker_worker_poll(&worker_b, i, &progress) == 0 && progress.rx == 1 &&
            second.received == i + 1);
    }
    CHECK(first.received == 1 && second.received == 2 && rte_ring_count(rx0) == 0);
    CHECK(rte_mempool_avail_count(pool_a.mbufs) == POOL_COUNT);
    CHECK(ker_worker_cleanup(&worker_b) == 0);
    CHECK(ker_ethdev_rx_cleanup(&rx) == 0 && !device.rx_ring_live && !runtime.rx_ring_live);
    CHECK(ker_protocol_unregister(&handler) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_eth_dev_stop((uint16_t)port) == 0);
    CHECK(rte_eth_dev_close((uint16_t)port) == 0);
    CHECK(ker_packet_pool_cleanup(&pool_b) == 0);
    CHECK(ker_packet_pool_cleanup(&pool_a) == 0);
    CHECK(ker_memory_live_allocations() == 0 && ker_memory_shutdown() == 0);
    rte_ring_free(tx);
    rte_ring_free(rx0);
}

int main(void)
{
    ker_test_eal_init();
    test_teardown_rebind();
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
