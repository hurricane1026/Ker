#include "check.h"
#include "eal.h"
#include "runtime/buffer.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/rx-ring.h"
#include "runtime/skb.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <net/checksum.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_SIZE 127U
#define MAX_MESSAGES 10U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_skb_context wrong_context;
static struct ker_tx_ring ring;
static struct ker_rx_ring rx;
static struct ker_tx_export tx;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static const uint8_t src_mac[6] = {2, 1, 2, 3, 4, 5};
static const uint8_t dst_mac[6] = {2, 6, 7, 8, 9, 10};
static const __be32 src_ip = (__be32)0x010200c0;
static const __be32 dst_ip = (__be32)0x026433c6;
static const __be16 src_port = (__be16)0x3412;
static const __be16 dst_port = (__be16)0x7856;
struct expected_message { bool tcp; const uint8_t *payload; size_t length; int status; };
static struct expected_message expected[MAX_MESSAGES];
static unsigned int expected_count, received;
static bool test_reentry;
static int callback_reentry_result;
static int callback_cleanup_result;

static void expect(bool tcp, const uint8_t *payload, size_t length, int status)
{
    CHECK(expected_count < MAX_MESSAGES);
    expected[expected_count++] = (struct expected_message){tcp, payload, length, status};
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.initialized && !worker.timers.polling);
    CHECK(received < expected_count);
    struct expected_message *item = &expected[received];
    CHECK(message->protocol == (item->tcp ? KER_TRANSPORT_TCP : KER_TRANSPORT_UDP));
    if (item->tcp) {
        CHECK(message->packet.tcp.source_port == src_port &&
            message->packet.tcp.destination_port == dst_port);
        CHECK(message->packet.tcp.payload_length == item->length &&
            !memcmp(message->packet.tcp.payload, item->payload, item->length));
    } else {
        CHECK(message->packet.udp.source_port == src_port &&
            message->packet.udp.destination_port == dst_port);
        CHECK(message->packet.udp.payload_length == item->length &&
            !memcmp(message->packet.udp.payload, item->payload, item->length));
    }
    if (test_reentry) {
        test_reentry = false;
        callback_reentry_result = ker_rx_ring_poll(&rx, 1);
        callback_cleanup_result = ker_rx_ring_cleanup(&rx);
    }
    received++;
    return item->status;
}

static struct sk_buff *make_packet(bool tcp, bool partial,
    const uint8_t *payload, size_t length)
{
    struct sk_buff *skb = NULL;
    if (tcp) {
        CHECK(ker_tcp_ipv4_create(&context, src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, (__be32)0x10203040, (__be32)0x50607080,
            (__be16)4096, 0x18, 61, payload, length, &skb) == 0);
    } else {
        CHECK(ker_udp_ipv4_create(&context, src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, 63, payload, length, &skb) == 0);
    }
    if (partial) {
        unsigned int start = ETH_HLEN + 20;
        unsigned int offset = tcp ? 16 : 6;
        unsigned int l4_length = skb->len - start;
        __wsum pseudo = csum_tcpudp_nofold(src_ip, dst_ip, l4_length,
            tcp ? IPPROTO_TCP : IPPROTO_UDP, 0);
        __sum16 seed = (__sum16)~csum_fold(pseudo);
        memcpy(skb->data + start + offset, &seed, sizeof(seed));
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
        skb->csum_offset = (uint16_t)offset;
    }
    return skb;
}

static void stage(bool tcp, bool partial, const uint8_t *payload, size_t length,
    int status)
{
    struct sk_buff *skb = make_packet(tcp, partial, payload, length);
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    CHECK(ker_tx_export_poll(&tx, 1) == 1);
    expect(tcp, payload, length, status);
}

static int worker_rx(void *arg, unsigned int budget)
{
    (void)arg;
    return ker_rx_ring_poll(&rx, budget);
}

struct poll_call { struct ker_rx_ring *rx; int result; };
struct cancel_call { struct ker_rx_ring *rx; struct rte_mbuf *out; int rc; };
struct cleanup_call { struct ker_rx_ring *rx; int result; };
static void *foreign_poll(void *arg)
{
    struct poll_call *call = arg;
    call->result = ker_rx_ring_poll(call->rx, 1);
    return NULL;
}

static void *foreign_cancel(void *arg)
{
    struct cancel_call *call = arg;
    call->rc = ker_rx_ring_cancel(call->rx, &call->out);
    return NULL;
}

static void *foreign_cleanup(void *arg)
{
    struct cleanup_call *call = arg;
    call->result = ker_rx_ring_cleanup(call->rx);
    return NULL;
}

static void exhaust_mbuf_pool(struct rte_mbuf **held, unsigned int *count)
{
    *count = 0;
    while (*count < POOL_SIZE) {
        struct rte_mbuf *packet = ker_packet_alloc(&pool);
        if (!packet) break;
        held[(*count)++] = packet;
    }
    CHECK(*count > 0 && *count < POOL_SIZE);
}

static void release_mbuf_pool(struct rte_mbuf **held, unsigned int *count)
{
    while (*count) ker_packet_free(held[--*count]);
}

static void receive_flow_and_guards(void)
{
    static const uint8_t udp_bytes[] = {0x10, 0x11, 0x12, 0x13, 0x14};
    static const uint8_t tcp_bytes[] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
    expect(false, udp_bytes, sizeof(udp_bytes), NET_RX_SUCCESS);
    expect(true, tcp_bytes, sizeof(tcp_bytes), NET_RX_SUCCESS);
    struct sk_buff *udp = make_packet(false, false, udp_bytes, sizeof(udp_bytes));
    struct sk_buff *tcp = make_packet(true, true, tcp_bytes, sizeof(tcp_bytes));
    CHECK(ker_tx_export_enqueue(&tx, &udp) == 0 && !udp);
    CHECK(ker_tx_export_enqueue(&tx, &tcp) == 0 && !tcp);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 2,
        .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = worker_rx, .arg = &tx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, 1, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && received == 1);
    CHECK(tx.last_error == -EAGAIN && tx.pending && ring.ring);
    CHECK(ker_worker_poll(&worker, 2, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && received == 2);
    CHECK(!tx.pending && rte_ring_count(ring.ring) == 0);

    static const uint8_t dropped[] = {0x31, 0x32};
    stage(false, false, dropped, sizeof(dropped), NET_RX_DROP);
    test_reentry = true;
    CHECK(ker_rx_ring_poll(&rx, 1) == 1);
    CHECK(callback_reentry_result == -EBUSY && rx.last_completed == 1 &&
        callback_cleanup_result == -EBUSY && !rx.last_error &&
        rx.last_dropped == 1 && received == 3);

    static const uint8_t invalid_status[] = {0x41, 0x42, 0x43};
    stage(false, false, invalid_status, sizeof(invalid_status), 77);
    CHECK(ker_rx_ring_poll(&rx, 1) == 1);
    CHECK(rx.last_completed == 1 && rx.last_error == -EPROTO &&
        rx.last_dropped == 1 && received == 4);

    static const uint8_t foreign[] = {0x51, 0x52, 0x53, 0x54};
    stage(false, false, foreign, sizeof(foreign), NET_RX_SUCCESS);
    pthread_t thread;
    struct poll_call call = {.rx = &rx, .result = 0};
    CHECK(pthread_create(&thread, NULL, foreign_poll, &call) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && call.result == -EXDEV);
    CHECK(ker_rx_ring_poll(&rx, 1) == 1 && received == 5);
}

static void allocation_retry_and_cancel(void)
{
    static const uint8_t descriptor_bytes[] = {0x55, 0x56, 0x57};
    stage(false, false, descriptor_bytes, sizeof(descriptor_bytes), NET_RX_SUCCESS);
    ker_memory_fail_after(0);
    CHECK(ker_rx_ring_poll(&rx, 1) == -ENOMEM && rx.pending &&
        rx.last_completed == 0 && rx.last_error == -ENOMEM);
    CHECK(ker_rx_ring_cleanup(&rx) == -EBUSY);
    pthread_t cancel_thread;
    struct cancel_call cancel_call = {.rx = &rx, .out = (void *)(uintptr_t)1};
    CHECK(pthread_create(&cancel_thread, NULL, foreign_cancel, &cancel_call) == 0);
    CHECK(pthread_join(cancel_thread, NULL) == 0 && cancel_call.rc == -EXDEV &&
        cancel_call.out == (void *)(uintptr_t)1);
    ker_memory_fail_after(-1);
    CHECK(ker_rx_ring_poll(&rx, 1) == 1 && !rx.pending && received == 6);

    static const uint8_t retry_bytes[] = {0x61, 0x62, 0x63, 0x64, 0x65};
    static const uint8_t later_bytes[] = {0x66, 0x67, 0x68};
    struct sk_buff *later_skb = make_packet(false, false, later_bytes,
        sizeof(later_bytes));
    struct rte_mbuf *later_chain = NULL;
    CHECK(ker_skb_to_mbuf_chain_copy(later_skb, 16, &later_chain) == 0);
    CHECK(ker_skb_free(later_skb) == 0);
    stage(false, false, retry_bytes, sizeof(retry_bytes), NET_RX_SUCCESS);
    expect(false, later_bytes, sizeof(later_bytes), NET_RX_SUCCESS);
    struct rte_mbuf *held[POOL_SIZE];
    unsigned int count;
    exhaust_mbuf_pool(held, &count);
    CHECK(ker_rx_ring_poll(&rx, 1) == -ENOMEM && rx.pending &&
        rx.last_completed == 0 && rx.last_error == -ENOMEM);
    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_tx_ring_take(&ring, &sentinel) == -EBUSY &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_tx_ring_sink(later_chain, &ring) == 0);
    CHECK(count >= 2);
    ker_packet_free(held[--count]);
    ker_packet_free(held[--count]);
    CHECK(ker_rx_ring_poll(&rx, 2) == 2 && !rx.pending && received == 8);
    CHECK(rx.last_completed == 2 && !rx.last_error);
    release_mbuf_pool(held, &count);

    static const uint8_t cancel_bytes[] = {0x71, 0x72};
    stage(false, false, cancel_bytes, sizeof(cancel_bytes), NET_RX_SUCCESS);
    exhaust_mbuf_pool(held, &count);
    CHECK(ker_rx_ring_poll(&rx, 1) == -ENOMEM && rx.pending);
    CHECK(ker_rx_ring_cleanup(&rx) == -EBUSY);
    struct rte_mbuf *cancelled = NULL;
    CHECK(ker_rx_ring_cancel(&rx, &cancelled) == 1 && cancelled && !rx.pending);
    sentinel = (void *)(uintptr_t)1;
    CHECK(ker_rx_ring_cancel(&rx, &sentinel) == 0 && sentinel == (void *)(uintptr_t)1);
    CHECK(cancelled->pkt_len >= ETH_HLEN);
    uint8_t payload_copy[sizeof(cancel_bytes)];
    const void *payload = rte_pktmbuf_read(cancelled,
        ETH_HLEN + 20 + 8, sizeof(payload_copy), payload_copy);
    CHECK(payload && !memcmp(payload, cancel_bytes, sizeof(payload_copy)));
    ker_packet_free(cancelled);
    release_mbuf_pool(held, &count);
}

static void permanent_drop(void)
{
    struct rte_mbuf *short_frame = ker_packet_alloc(&pool);
    CHECK(short_frame);
    CHECK(rte_pktmbuf_append(short_frame, 1));
    CHECK(ker_tx_ring_sink(short_frame, &ring) == 0);
    CHECK(ker_rx_ring_poll(&rx, 1) == 1 && !rx.pending &&
        rx.last_completed == 1 && rx.last_error == -EMSGSIZE && rx.last_dropped == 1);
    unsigned int completed = rx.last_completed, dropped = rx.last_dropped;
    int last_error = rx.last_error;
    CHECK(ker_rx_ring_poll(&rx, 0) == 0 && rx.last_completed == completed &&
        rx.last_dropped == dropped && rx.last_error == last_error);
}

static void cleanup_preserves_ring_queue(void)
{
    struct rte_mbuf *queued = ker_packet_alloc(&pool);
    CHECK(queued && rte_pktmbuf_append(queued, 1));
    CHECK(ker_tx_ring_sink(queued, &ring) == 0);
    CHECK(ker_rx_ring_cleanup(&rx) == 0);
    CHECK(rte_ring_count(ring.ring) == 1);
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    CHECK(ker_tx_ring_take(&ring, &out) == 1 && out == queued);
    ker_packet_free(out);
    CHECK(ker_rx_ring_init(&rx, &ring, &device, &runtime, 128) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "rx_ring_pool", POOL_SIZE, 0, 4096,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "rx_ring_skb") == 0);
    CHECK(ker_skb_context_init(&wrong_context, &pool, "rx_ring_wrong_skb") == 0);
    CHECK(ker_tx_ring_init(&ring, "ker_rx_ring", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_eth_device_init(&device, &context, "rx0", 17, src_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device,
        receive_message, &receiver) == 0);

    uint32_t backing = RTE_ALIGN_FLOOR(
        rte_pktmbuf_data_room_size(pool.mbufs), SMP_CACHE_BYTES);
    CHECK(backing > ker_skb_shared_info_size() + ETH_HLEN);
    unsigned int max_headroom = backing - (unsigned int)ker_skb_shared_info_size() - ETH_HLEN;
    struct ker_rx_ring boundary = {0};
    CHECK(ker_rx_ring_init(&boundary, &ring, &device, &runtime,
        max_headroom + 2) == -ENOSPC);
    CHECK(!boundary.ring && !ring.consumers && !device.rx_ring_live &&
        !runtime.rx_ring_live);
    CHECK(ker_rx_ring_init(&boundary, &ring, &device, &runtime,
        max_headroom) == 0);
    CHECK(ring.consumers == 1 && device.rx_ring_live == 1 && runtime.rx_ring_live == 1);
    pthread_t cleanup_thread;
    struct cleanup_call cleanup_call = {.rx = &boundary};
    CHECK(pthread_create(&cleanup_thread, NULL, foreign_cleanup, &cleanup_call) == 0);
    CHECK(pthread_join(cleanup_thread, NULL) == 0 && cleanup_call.result == -EXDEV);
    CHECK(boundary.ring == &ring && ring.consumers == 1 && device.rx_ring_live == 1 &&
        runtime.rx_ring_live == 1);
    CHECK(ker_rx_ring_cleanup(&boundary) == 0);
    struct ker_rx_ring duplicate = {.owner_lcore = 77};
    struct ker_eth_device wrong_device = device;
    wrong_device.context = &wrong_context;
    CHECK(ker_rx_ring_init(&duplicate, &ring, &wrong_device, &runtime, 128) == -EXDEV);
    CHECK(!duplicate.ring && duplicate.owner_lcore == 77 && !ring.consumers);
    struct ker_receive_runtime wrong_runtime = runtime;
    wrong_runtime.context = &wrong_context;
    CHECK(ker_rx_ring_init(&duplicate, &ring, &device, &wrong_runtime, 128) == -EXDEV);
    CHECK(!duplicate.ring && duplicate.owner_lcore == 77 && !ring.consumers);
    struct ker_tx_ring wrong_ring = ring;
    wrong_ring.owner_lcore = UINT_MAX;
    CHECK(ker_rx_ring_init(&duplicate, &wrong_ring, &device, &runtime, 128) == -EXDEV);
    CHECK(!duplicate.ring && duplicate.owner_lcore == 77 && !ring.consumers);
    CHECK(ker_rx_ring_init(&rx, &ring, &device, &runtime, UINT_MAX - 1) == -ENOSPC);
    CHECK(!rx.ring && !rx.device && !rx.runtime && !ring.consumers &&
        !device.rx_ring_live && !runtime.rx_ring_live);
    CHECK(ker_rx_ring_init(&rx, &ring, &device, &runtime, 128) == 0);
    CHECK(ker_rx_ring_init(&duplicate, &ring, &device, &runtime, 128) == -EBUSY);
    CHECK(!duplicate.ring && duplicate.owner_lcore == 77);
    CHECK(ring.consumers == 1 && device.rx_ring_live == 1 && runtime.rx_ring_live == 1);
    CHECK(ker_tx_ring_cleanup(&ring) == -EBUSY);
    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_tx_ring_take(&ring, &sentinel) == -EBUSY &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_rx_ring_poll(&rx, 0) == 0);
    CHECK(ker_rx_ring_poll(&rx, UINT_MAX) == -EOVERFLOW);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(ker_receive_runtime_cleanup(&runtime) == -EBUSY);

    CHECK(ker_tx_export_init_chain_software_checksum(&tx, &context, 8,
        SIZE_MAX, 16, ker_tx_ring_sink, &ring) == 0);
    receive_flow_and_guards();
    allocation_retry_and_cancel();
    permanent_drop();
    CHECK(received == 8);
    cleanup_preserves_ring_queue();
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == -EBUSY);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(ker_tx_ring_cleanup(&ring) == -EBUSY);
    CHECK(ker_rx_ring_cleanup(&rx) == 0);
    CHECK(!ring.consumers && !device.rx_ring_live && !runtime.rx_ring_live);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_tx_ring_cleanup(&ring) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_skb_context_cleanup(&wrong_context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
