#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-receive.h"
#include "runtime/arp-responder.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/neighbor.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include "ker/linux_neighbor_update.h"
#include <errno.h>
#include <limits.h>

#define PACKETS 63U
static struct ker_packet_pool pool;
static struct ker_packet_pool bpool;
static struct ker_skb_context actx, bctx;
static struct ker_eth_device adev, bdev;
static struct ker_ipv4_address aaddr, baddr;
static struct ker_receive_runtime art, brt;
static struct ker_arp_responder responder;
static struct ker_transport_receiver udp_rx;
static struct ker_arp_receiver a_arp_rx;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor monitor;
static struct ker_worker aworker, bworker;
static struct ker_tx_ring ab, ba;
static struct ker_rx_ring arx, brx;
static struct ker_tx_export atx, btx;
static const unsigned char amac[6] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const unsigned char bmac[6] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static const unsigned char broadcast[6] = {255, 255, 255, 255, 255, 255};
static const unsigned char zero[6];
static const unsigned char payload[] = {0x4b, 0x65, 0x72, 0x21};
static __be32 aip, bip;
static unsigned int udp_received;
static int feedback_status;
static void arp_oracle(const unsigned char actual[42], unsigned int operation,
    __be32 source_ip, const unsigned char source_mac[6], __be32 target_ip,
    const unsigned char destination_mac[6], const unsigned char target_mac[6]);

static int receive_udp(const struct ker_transport_message *message, void *arg)
{
    (void)arg;
    CHECK(message->protocol == KER_TRANSPORT_UDP);
    CHECK(!memcmp(message->ipv4.header + 12, &aip, sizeof(aip)) &&
        !memcmp(message->ipv4.header + 16, &bip, sizeof(bip)));
    CHECK(message->packet.udp.source_port == rte_cpu_to_be_16(41001));
    CHECK(message->packet.udp.destination_port == rte_cpu_to_be_16(41002));
    CHECK(message->packet.udp.payload_length == sizeof(payload));
    CHECK(message->packet.udp.checksum != 0);
    CHECK(!memcmp(message->packet.udp.payload, payload, sizeof(payload)));
    ++udp_received;
    return NET_RX_SUCCESS;
}

static int learn_reply(const struct ker_arp_message *message, void *arg)
{
    (void)arg;
    CHECK(message->operation == ARPOP_REPLY && message->sender_ip == bip &&
        message->target_ip == aip && message->target_local);
    feedback_status = ker_arp_neighbor_feedback(&a_arp_rx, &monitor, message,
        NEIGH_UPDATE_F_OVERRIDE);
    return feedback_status == 0 ? NET_RX_SUCCESS : NET_RX_DROP;
}

static int a_rx(void *arg, unsigned int budget) { (void)arg; return ker_rx_ring_poll(&arx, budget); }
static int b_rx(void *arg, unsigned int budget) { (void)arg; return ker_rx_ring_poll(&brx, budget); }
static int b_tx(void *arg, unsigned int budget) { (void)arg; return ker_tx_export_poll(&btx, budget); }

static void poll_worker(struct ker_worker *worker)
{
    struct ker_worker_result result = {0};
    CHECK(ker_worker_poll(worker, worker->timers.now_ns, &result) == 0);
}

static void send_probe(const struct ker_neighbor_event *event, void *arg)
{
    (void)arg;
    struct sk_buff *probe = NULL;
    CHECK(ker_arp_probe_create(&monitor, event, &probe) == 0 && probe);
    CHECK(ker_tx_export_enqueue(&atx, &probe) == 0 && !probe);
}

static int ring_sink(struct rte_mbuf *packet, void *arg)
{
    return ker_tx_ring_sink(packet, arg);
}

static int reply_sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(packet && packet->pkt_len == 42);
    unsigned char bytes[42];
    const void *read = rte_pktmbuf_read(packet, 0, sizeof(bytes), bytes);
    CHECK(read);
    arp_oracle(read, ARPOP_REPLY, bip, bmac, aip, amac, amac);
    return ker_tx_ring_sink(packet, arg);
}

static void arp_oracle(const unsigned char actual[42], unsigned int operation,
    __be32 source_ip, const unsigned char source_mac[6], __be32 target_ip,
    const unsigned char destination_mac[6], const unsigned char target_mac[6])
{
    unsigned char expected[42] = {0};
    memcpy(expected, destination_mac, 6); memcpy(expected + 6, source_mac, 6);
    expected[12] = 0x08; expected[13] = 0x06;
    expected[15] = 1; expected[16] = 0x08; expected[18] = 6; expected[19] = 4;
    expected[21] = (unsigned char)operation;
    memcpy(expected + 22, source_mac, 6); memcpy(expected + 28, &source_ip, 4);
    memcpy(expected + 32, target_mac, 6); memcpy(expected + 38, &target_ip, 4);
    CHECK(!memcmp(actual, expected, sizeof(expected)));
}

static void send_request_to(unsigned int operation, __be32 source_ip,
    __be32 target_ip, const unsigned char destination[ETH_ALEN])
{
    struct sk_buff *packet = NULL;
    const unsigned char *target_mac = operation == ARPOP_REPLY ? amac : zero;
    CHECK(ker_arp_create(&adev, operation, source_ip, target_ip,
        destination, amac, target_mac, &packet) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
    CHECK(ker_tx_export_poll(&atx, 1) == 1);
    CHECK(ker_rx_ring_poll(&brx, 1) == 1);
}

static void send_request(unsigned int operation, __be32 source_ip, __be32 target_ip)
{
    send_request_to(operation, source_ip, target_ip, broadcast);
}

static void queue_request(unsigned int operation, __be32 source_ip, __be32 target_ip)
{
    struct sk_buff *packet = NULL;
    const unsigned char *target_mac = operation == ARPOP_REPLY ? amac : zero;
    CHECK(ker_arp_create(&adev, operation, source_ip, target_ip,
        broadcast, amac, target_mac, &packet) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
    CHECK(ker_tx_export_poll(&atx, 1) == 1);
}

static void run(void)
{
    CHECK(ker_packet_pool_init(&pool, "arp_rsp_a_packets", PACKETS, 0, 2048,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_packet_pool_init(&bpool, "arp_rsp_b_packets", 31, 0, 2048,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&actx, &pool, "arp_rsp_a") == 0);
    CHECK(ker_skb_context_init(&bctx, &bpool, "arp_rsp_b") == 0);
    aip = rte_cpu_to_be_32(0xc0000201); bip = rte_cpu_to_be_32(0xc0000202);
    CHECK(ker_eth_device_init(&adev, &actx, "arp_rsp_a", 1, amac) == 0);
    CHECK(ker_eth_device_init(&bdev, &bctx, "arp_rsp_b", 2, bmac) == 0);
    CHECK(ker_arp_device_setup(&adev) == 0 && ker_arp_device_setup(&bdev) == 0);
    CHECK(ker_ipv4_address_init(&aaddr, &adev, aip, 24) == 0);
    CHECK(ker_ipv4_address_init(&baddr, &bdev, bip, 24) == 0);
    CHECK(ker_neighbor_table_init(&neighbors, &aaddr, "arp_rsp_neighbors", 4, 2) == 0);
    struct ker_neighbor_config neighbor_config = {.retrans_ticks = 20,
        .reachable_ticks = 100, .delay_ticks = 30, .ucast_probes = 2,
        .mcast_probes = 2, .mcast_reprobes = 1, .queue_bytes = 16384};
    CHECK(ker_neighbor_configure(&neighbors, &neighbor_config) == 0);
    CHECK(ker_receive_runtime_init(&art, &actx) == 0);
    CHECK(ker_receive_runtime_init(&brt, &bctx) == 0);
    CHECK(ker_transport_receiver_register(&udp_rx, &brt, &bdev,
        receive_udp, NULL) == 0);
    CHECK(ker_tx_ring_init(&ab, "arp_rsp_ab", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_ring_init(&ba, "arp_rsp_ba", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init(&atx, &actx, 4, 8192, ring_sink, &ab) == 0);
    CHECK(ker_tx_export_init(&btx, &bctx, 1, 8192, reply_sink, &ba) == 0);
    struct ker_arp_responder rejected = {0};
    CHECK(ker_arp_responder_register(&rejected, &brt, &baddr, &atx) == -EXDEV);
    CHECK(!rejected.active && !rejected.receiver.handler.registered && !atx.responder_refs);
    unsigned int saved_refs = btx.responder_refs;
    btx.responder_refs = UINT_MAX;
    CHECK(ker_arp_responder_register(&rejected, &brt, &baddr, &btx) == -EOVERFLOW);
    btx.responder_refs = saved_refs;
    CHECK(ker_arp_responder_register(&responder, &brt, &baddr, &btx) == 0);
    CHECK(btx.responder_refs == 1);
    CHECK(ker_tx_export_cleanup(&btx) == -EBUSY &&
        ker_ipv4_address_cleanup(&baddr) == -EBUSY);
    CHECK(ker_rx_ring_init(&brx, &ab, &bdev, &brt, 128) == 0);
    CHECK(ker_arp_receiver_register(&a_arp_rx, &art, &aaddr, learn_reply, NULL) == 0);
    CHECK(ker_rx_ring_init(&arx, &ba, &adev, &art, 128) == 0);
    struct ker_worker_config worker_config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops worker_ops = {.rx = a_rx};
    CHECK(ker_worker_init(&aworker, &pool, &worker_config, &worker_ops) == 0);
    struct ker_worker_ops bworker_ops = {.tx = b_tx, .rx = b_rx};
    struct ker_worker_config bworker_config = {.timer_budget = 1, .tx_budget = 1,
        .rx_budget = 1};
    CHECK(ker_worker_init(&bworker, &pool, &bworker_config, &bworker_ops) == 0);
    CHECK(ker_neighbor_monitor_discovery_init(&monitor, &neighbors,
        &aworker.timers, &atx, bip, send_probe, NULL, NULL) == 0);

    static const unsigned char unknown_mac[ETH_ALEN] = {0};
    struct sk_buff *udp = NULL;
    CHECK(ker_udp_ipv4_create_configured(&aaddr, unknown_mac, bip,
        rte_cpu_to_be_16(41001), rte_cpu_to_be_16(41002), 64,
        NULL, 0, payload, sizeof(payload), &udp) == 0);
    CHECK(ker_neighbor_monitor_resolve_output(&monitor, &udp) == 0 && !udp);
    struct ker_neighbor_event neighbor_event;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &neighbor_event) == 0 &&
        neighbor_event.state == NUD_INCOMPLETE && atx.packets == 1);
    CHECK(ker_tx_export_poll(&atx, 1) == 1);
    poll_worker(&bworker);
    CHECK(btx.packets == 1);
    poll_worker(&bworker);
    poll_worker(&aworker);
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &neighbor_event) == 0 &&
        neighbor_event.state == NUD_REACHABLE && !memcmp(neighbor_event.mac, bmac, ETH_ALEN));
    CHECK(atx.packets == 1);
    CHECK(ker_tx_export_poll(&atx, 1) == 1);
    poll_worker(&bworker);
    CHECK(udp_received == 1);
    CHECK(responder.requests == 1 && responder.replies_enqueued == 1 && responder.dropped == 0);

    send_request_to(ARPOP_REQUEST, aip, bip, bmac);
    CHECK(btx.packets == 1);

    /* Exporter capacity is deterministic: a second request while the first
     * reply occupies the sole slot is consumed and counted as a drop. */
    send_request(ARPOP_REQUEST, aip, bip);
    CHECK(btx.packets == 1 && responder.requests == 3 &&
        responder.replies_enqueued == 2 && responder.dropped == 1 &&
        responder.last_error == -ENOSPC);
    send_request(ARPOP_REQUEST, 0, bip); /* DAD */
    send_request(ARPOP_REQUEST, aip, rte_cpu_to_be_32(0xc0000209)); /* nonlocal */
    send_request(ARPOP_REPLY, aip, bip);
    CHECK(btx.packets == 1 && responder.requests == 6 &&
        responder.replies_enqueued == 2 && responder.dropped == 4);

    /* Fill the return ring to force the existing exporter's retry head, then
     * free capacity and verify one exact reply is emitted without duplication. */
    struct rte_mbuf *filler = ker_packet_alloc(&pool);
    CHECK(filler && rte_pktmbuf_append(filler, 1));
    CHECK(ker_tx_ring_sink(filler, &ba) == 0);
    CHECK(ker_tx_export_poll(&btx, 1) == -EAGAIN && btx.pending && btx.packets == 1);
    CHECK(ker_rx_ring_poll(&arx, 1) == 1 && arx.last_dropped == 1);
    CHECK(ker_tx_export_poll(&btx, 1) == 1 && !btx.pending && btx.packets == 0);
    CHECK(ker_rx_ring_poll(&arx, 1) == 1 && arx.last_dropped == 1 &&
        feedback_status == -ENOTSUP);
    CHECK(responder.requests == 6 && responder.replies_enqueued == 2 &&
        responder.dropped == 4 && responder.last_error == -ENOTSUP);

    /* Keep one packet object available for RX linearization. The production
     * reply constructor then fails deterministically after decoding, consumes
     * the input, and recovers on the next request after pressure is released. */
    queue_request(ARPOP_REQUEST, aip, bip);
    struct rte_mbuf *held[31];
    unsigned int held_count = 0;
    while (rte_mempool_avail_count(bpool.mbufs) > 1 && held_count < 31 &&
        (held[held_count] = ker_packet_alloc(&bpool)) != NULL)
        ++held_count;
    CHECK(held_count > 0 && rte_mempool_avail_count(bpool.mbufs) == 1);
    poll_worker(&bworker);
    CHECK(brx.last_dropped == 1 && responder.requests == 7 &&
        responder.replies_enqueued == 2 && responder.dropped == 5 &&
        responder.last_error == -ENOMEM);
    for (unsigned int i = 0; i < held_count; ++i) ker_packet_free(held[i]);
    queue_request(ARPOP_REQUEST, aip, bip);
    poll_worker(&bworker);
    CHECK(brx.last_dropped == 0 && responder.requests == 8 &&
        responder.replies_enqueued == 3 && responder.dropped == 5 &&
        responder.last_error == 0 && btx.packets == 1);

    /* Unregistration releases only the service pin. The queued reply remains
     * exporter-owned, cleanup stays busy, and normal TX can still drain it. */
    CHECK(ker_arp_responder_unregister(&responder) == 0 && btx.responder_refs == 0);
    CHECK(btx.packets == 1 && ker_tx_export_cleanup(&btx) == -EBUSY);
    poll_worker(&bworker);
    poll_worker(&aworker);
    CHECK(btx.packets == 0 && arx.last_dropped == 1 && feedback_status == -ENOTSUP);
    poll_worker(&bworker);

    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0 && atx.resolver_refs == 0);
    CHECK(ker_arp_receiver_unregister(&a_arp_rx) == 0);
    CHECK(ker_transport_receiver_unregister(&udp_rx) == 0);
    CHECK(ker_rx_ring_cleanup(&arx) == 0 && ker_rx_ring_cleanup(&brx) == 0);
    CHECK(ker_worker_cleanup(&bworker) == 0 && ker_worker_cleanup(&aworker) == 0);
    CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
    CHECK(ker_tx_export_cleanup(&btx) == 0 && ker_tx_export_cleanup(&atx) == 0);
    CHECK(ker_tx_ring_cleanup(&ba) == 0 && ker_tx_ring_cleanup(&ab) == 0);
    CHECK(ker_receive_runtime_cleanup(&brt) == 0 && ker_receive_runtime_cleanup(&art) == 0);
    CHECK(ker_ipv4_address_cleanup(&baddr) == 0 && ker_ipv4_address_cleanup(&aaddr) == 0);
    CHECK(ker_eth_device_cleanup(&bdev) == 0 && ker_eth_device_cleanup(&adev) == 0);
    CHECK(ker_skb_context_cleanup(&bctx) == 0 && ker_skb_context_cleanup(&actx) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == PACKETS &&
        rte_mempool_avail_count(bpool.mbufs) == 31);
    CHECK(ker_packet_pool_cleanup(&bpool) == 0 && ker_packet_pool_cleanup(&pool) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    run();
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
