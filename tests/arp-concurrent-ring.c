#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-receive.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/rx-ring.h"
#include "runtime/skb.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/worker.h"
#include <errno.h>
#include <pthread.h>
#include <rte_lcore.h>
#include <sched.h>
#include <stdatomic.h>
#include <time.h>

#define COUNT 192U
#define POOL_SIZE 127U
struct fixture {
    struct ker_tx_ring ring;
    struct ker_tx_export tx;
    struct ker_rx_ring rx;
    struct ker_packet_pool producer_pool, consumer_pool;
    struct ker_skb_context producer_context, consumer_context;
    struct ker_eth_device producer_device, consumer_device;
    struct ker_ipv4_address producer_address, consumer_address;
    struct ker_receive_runtime runtime;
    struct ker_arp_receiver receiver;
    struct ker_worker producer_worker, worker;
    atomic_bool consumer_ready, consumer_start, producer_done;
    atomic_bool consumer_cleaned, producer_cleaned;
    atomic_uint received;
    unsigned int consumer_lcore;
    int consumer_result;
    int callback_failure;
};
static struct fixture f;
static const unsigned char source_mac[ETH_ALEN] = {2, 0x40, 0x41, 0x42, 0x43, 0x44};
static const unsigned char target_mac[ETH_ALEN] = {2, 0x50, 0x51, 0x52, 0x53, 0x54};
static const unsigned char broadcast_mac[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
static const unsigned char zero_mac[ETH_ALEN];
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 consumer_ip = (__be32)0x020200c0;
static unsigned int sink_accepted;
static unsigned char expected_frames[COUNT][42];

static uint64_t deadline_after_seconds(unsigned int seconds)
{
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec +
        (uint64_t)seconds * UINT64_C(1000000000);
}
static void check_deadline(uint64_t deadline)
{
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    CHECK((uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec < deadline);
}
static __be32 target_for(unsigned int index)
{
    if (index == 37U) return consumer_ip;
    return rte_cpu_to_be_32(UINT32_C(0xc6336400) + index);
}
static void encode(unsigned char bytes[42], unsigned int index)
{
    unsigned int operation = (index & 1U) ? ARPOP_REPLY : ARPOP_REQUEST;
    memset(bytes, 0, 42);
    memcpy(bytes, operation == ARPOP_REPLY ? target_mac : broadcast_mac, ETH_ALEN);
    memcpy(bytes + ETH_ALEN, source_mac, ETH_ALEN);
    bytes[12] = 0x08; bytes[13] = 0x06;
    bytes[15] = ARPHRD_ETHER; bytes[16] = 0x08;
    bytes[18] = ETH_ALEN; bytes[19] = 4; bytes[21] = (unsigned char)operation;
    memcpy(bytes + 22, source_mac, ETH_ALEN);
    memcpy(bytes + 28, &source_ip, sizeof(source_ip));
    memcpy(bytes + 32, operation == ARPOP_REPLY ? target_mac : zero_mac, ETH_ALEN);
    __be32 target = target_for(index);
    memcpy(bytes + 38, &target, sizeof(target));
}
static int sink(struct rte_mbuf *chain, void *arg)
{
    struct ker_tx_ring *ring = arg;
    CHECK(chain && chain->pkt_len == 42 && chain->nb_segs == 4);
    unsigned char actual[42];
    size_t offset = 0; unsigned int segments = 0;
    for (struct rte_mbuf *part = chain; part; part = part->next) {
        CHECK(part->data_len && part->ol_flags == 0 &&
            rte_mbuf_refcnt_read(part) == 1 && offset + part->data_len <= sizeof(actual));
        memcpy(actual + offset, rte_pktmbuf_mtod(part, const void *), part->data_len);
        offset += part->data_len; ++segments;
    }
    CHECK(offset == sizeof(actual) && segments == chain->nb_segs);
    /* Each queued request has a distinct target IP, so the independent oracle
     * also makes FIFO order observable across ring wraparound. */
    CHECK(sink_accepted < COUNT);
    CHECK(!memcmp(actual, expected_frames[sink_accepted], sizeof(actual)));
    int rc = ker_tx_ring_sink(chain, ring);
    if (!rc) ++sink_accepted;
    return rc;
}
static int receive_arp(const struct ker_arp_message *message, void *arg)
{
    CHECK(arg == &f && rte_lcore_id() == f.consumer_lcore);
    unsigned int index = atomic_load_explicit(&f.received, memory_order_relaxed);
    if (index >= COUNT) { f.callback_failure = -EOVERFLOW; return NET_RX_DROP; }
    const unsigned char *expected_frame = expected_frames[index];
    unsigned int operation = expected_frame[21];
    __be32 expected_target;
    memcpy(&expected_target, expected_frame + 38, sizeof(expected_target));
    if (message->operation != operation || message->sender_ip != source_ip ||
        message->target_ip != expected_target ||
        message->target_local != (expected_target == consumer_ip) ||
        memcmp(message->sender_mac, expected_frame + 22, ETH_ALEN) ||
        memcmp(message->target_mac, expected_frame + 32, ETH_ALEN)) {
        f.callback_failure = -EBADMSG;
        return NET_RX_DROP;
    }
    atomic_store_explicit(&f.received, index + 1, memory_order_release);
    return NET_RX_SUCCESS;
}
static int worker_rx(void *arg, unsigned int budget)
{
    return ker_rx_ring_poll(arg, budget);
}
static int worker_tx(void *arg, unsigned int budget)
{
    return ker_tx_export_poll(arg, budget);
}
static void *consumer_main(void *arg)
{
    struct fixture *fixture = arg;
    CHECK(rte_thread_register() == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&fixture->consumer_pool, "arp_ring_consumer_pool",
        POOL_SIZE, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&fixture->consumer_context, &fixture->consumer_pool,
        "arp_ring_consumer_skb") == 0);
    CHECK(ker_eth_device_init(&fixture->consumer_device, &fixture->consumer_context,
        "arp-rx-cons", 29, target_mac) == 0);
    CHECK(ker_arp_device_setup(&fixture->consumer_device) == 0);
    CHECK(ker_ipv4_address_init(&fixture->consumer_address, &fixture->consumer_device,
        consumer_ip, 24) == 0);
    CHECK(ker_receive_runtime_init(&fixture->runtime, &fixture->consumer_context) == 0);
    CHECK(ker_arp_receiver_register(&fixture->receiver, &fixture->runtime,
        &fixture->consumer_address, receive_arp, fixture) == 0);
    CHECK(ker_rx_ring_init(&fixture->rx, &fixture->ring, &fixture->consumer_device,
        &fixture->runtime, 128) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 8};
    struct ker_worker_ops ops = {.rx = worker_rx, .arg = &fixture->rx};
    CHECK(ker_worker_init(&fixture->worker, &fixture->consumer_pool, &config, &ops) == 0);
    fixture->consumer_lcore = rte_lcore_id();
    CHECK(fixture->consumer_lcore != fixture->ring.owner_lcore);
    atomic_store_explicit(&fixture->consumer_ready, true, memory_order_release);
    uint64_t deadline = deadline_after_seconds(18);
    while (!atomic_load_explicit(&fixture->consumer_start, memory_order_acquire)) {
        check_deadline(deadline); sched_yield();
    }
    int64_t now = 1;
    while (!atomic_load_explicit(&fixture->producer_done, memory_order_acquire) ||
        atomic_load_explicit(&fixture->received, memory_order_acquire) < COUNT) {
        check_deadline(deadline);
        struct ker_worker_result progress = {0};
        CHECK(ker_worker_poll(&fixture->worker, now++, &progress) == 0);
        sched_yield();
    }
    CHECK(!fixture->callback_failure && rte_ring_empty(fixture->ring.ring) &&
        !fixture->rx.pending && fixture->rx.last_dropped == 0 && fixture->rx.last_error == 0);
    fixture->consumer_result = (int)atomic_load_explicit(&fixture->received,
        memory_order_acquire);
    CHECK(ker_rx_ring_cleanup(&fixture->rx) == 0);
    CHECK(ker_worker_cleanup(&fixture->worker) == 0);
    CHECK(ker_arp_receiver_unregister(&fixture->receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&fixture->runtime) == 0);
    CHECK(ker_ipv4_address_cleanup(&fixture->consumer_address) == 0);
    CHECK(ker_eth_device_cleanup(&fixture->consumer_device) == 0);
    CHECK(ker_skb_context_cleanup(&fixture->consumer_context) == 0);
    CHECK(ker_packet_pool_cleanup(&fixture->consumer_pool) == 0);
    atomic_store_explicit(&fixture->consumer_cleaned, true, memory_order_release);
    while (!atomic_load_explicit(&fixture->producer_cleaned, memory_order_acquire)) {
        check_deadline(deadline); sched_yield();
    }
    CHECK(ker_memory_shutdown() == 0);
    rte_thread_unregister();
    return NULL;
}

int main(void)
{
    for (unsigned int i = 0; i < COUNT; ++i) encode(expected_frames[i], i);
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&f.producer_pool, "arp_ring_producer_pool",
        POOL_SIZE, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&f.producer_context, &f.producer_pool,
        "arp_ring_producer_skb") == 0);
    CHECK(ker_eth_device_init(&f.producer_device, &f.producer_context,
        "arp-tx-prod", 28, source_mac) == 0);
    CHECK(ker_arp_device_setup(&f.producer_device) == 0);
    CHECK(ker_ipv4_address_init(&f.producer_address, &f.producer_device, source_ip, 24) == 0);
    CHECK(ker_tx_ring_init(&f.ring, "arp_worker_ring1", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init_chain(&f.tx, &f.producer_context, 4, 32768, 13,
        sink, &f.ring) == 0);
    struct ker_worker_config producer_config = {.timer_budget = 1, .tx_budget = 1};
    struct ker_worker_ops producer_ops = {.tx = worker_tx, .arg = &f.tx};
    CHECK(ker_worker_init(&f.producer_worker, &f.producer_pool,
        &producer_config, &producer_ops) == 0);
    pthread_t consumer;
    CHECK(pthread_create(&consumer, NULL, consumer_main, &f) == 0);
    uint64_t deadline = deadline_after_seconds(18);
    while (!atomic_load_explicit(&f.consumer_ready, memory_order_acquire)) {
        check_deadline(deadline); sched_yield();
    }
    /* Hold RX before the first transfer to force deterministic cap-one ring
     * backpressure and prove the exporter retains its second original. */
    struct sk_buff *first = NULL;
    CHECK(ker_arp_create_configured(&f.producer_address, ARPOP_REQUEST,
        target_for(0), broadcast_mac, zero_mac, &first) == 0);
    CHECK(ker_tx_export_enqueue(&f.tx, &first) == 0 && !first);
    struct ker_worker_result producer_progress = {0};
    CHECK(ker_worker_poll(&f.producer_worker, f.producer_worker.timers.now_ns,
        &producer_progress) == 0 && producer_progress.tx == 1 &&
        rte_ring_count(f.ring.ring) == 1);
    struct sk_buff *second = NULL;
    CHECK(ker_arp_create_configured(&f.producer_address, ARPOP_REPLY,
        target_for(1), target_mac, target_mac, &second) == 0);
    struct sk_buff *retained = second;
    CHECK(second->len == sizeof(expected_frames[1]) &&
        !memcmp(second->data, expected_frames[1], sizeof(expected_frames[1])));
    CHECK(ker_tx_export_enqueue(&f.tx, &second) == 0 && !second);
    CHECK(ker_worker_poll(&f.producer_worker, f.producer_worker.timers.now_ns,
        &producer_progress) == -EAGAIN && f.tx.pending == retained &&
        f.tx.last_error == -EAGAIN && f.tx.packets == 1 && retained->len == 42 &&
        !memcmp(retained->data, expected_frames[1], sizeof(expected_frames[1])));
    atomic_store_explicit(&f.consumer_start, true, memory_order_release);

    for (unsigned int i = 2; i < COUNT; ++i) {
        struct sk_buff *skb = NULL;
        unsigned int operation = (i & 1U) ? ARPOP_REPLY : ARPOP_REQUEST;
        CHECK(ker_arp_create_configured(&f.producer_address, operation,
            target_for(i), operation == ARPOP_REPLY ? target_mac : broadcast_mac,
            operation == ARPOP_REPLY ? target_mac : zero_mac, &skb) == 0);
        CHECK(ker_tx_export_enqueue(&f.tx, &skb) == 0 && !skb);
        int rc;
        do {
            producer_progress = (struct ker_worker_result){0};
            int poll_error = ker_worker_poll(&f.producer_worker,
                f.producer_worker.timers.now_ns, &producer_progress);
            rc = poll_error ? poll_error : (int)producer_progress.tx;
            CHECK(rc == 1 || rc == -EAGAIN);
            if (rc == -EAGAIN) sched_yield();
            check_deadline(deadline);
        } while (rc != 1);
    }
    while (f.tx.packets) {
        producer_progress = (struct ker_worker_result){0};
        int poll_error = ker_worker_poll(&f.producer_worker,
            f.producer_worker.timers.now_ns, &producer_progress);
        int rc = poll_error ? poll_error : (int)producer_progress.tx;
        CHECK(rc == 1 || rc == -EAGAIN);
        if (rc == -EAGAIN) sched_yield();
        check_deadline(deadline);
    }
    CHECK(sink_accepted == COUNT);
    atomic_store_explicit(&f.producer_done, true, memory_order_release);
    while (!atomic_load_explicit(&f.consumer_cleaned, memory_order_acquire)) {
        check_deadline(deadline); sched_yield();
    }
    CHECK(f.consumer_result == (int)COUNT && !f.callback_failure &&
        atomic_load_explicit(&f.received, memory_order_acquire) == COUNT &&
        rte_ring_empty(f.ring.ring) && !f.tx.pending);
    CHECK(ker_tx_export_cleanup(&f.tx) == 0);
    CHECK(ker_worker_cleanup(&f.producer_worker) == 0);
    CHECK(ker_ipv4_address_cleanup(&f.producer_address) == 0);
    CHECK(ker_eth_device_cleanup(&f.producer_device) == 0);
    CHECK(ker_skb_context_cleanup(&f.producer_context) == 0);
    CHECK(ker_packet_pool_cleanup(&f.producer_pool) == 0);
    atomic_store_explicit(&f.producer_cleaned, true, memory_order_release);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(ker_tx_ring_cleanup(&f.ring) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("ARP concurrent ring: 192 configured requests crossed producer/consumer workers in FIFO order");
    return 0;
}
