#include "check.h"
#include "eal.h"
#include "runtime/memory.h"
#include "runtime/ethernet.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/tcp-create.h"
#include "runtime/tx-export.h"
#include <errno.h>
#include <string.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_tx_export tx;
static struct ker_worker worker;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static unsigned char expected[512];
static unsigned int expected_length = sizeof(expected);
static int sink_error = -EAGAIN, calls;
static int fail_on_call;
static struct rte_mbuf *accepted;
static bool rx_enabled;
static unsigned int rx_calls;
static const unsigned char source_mac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[6] = {2, 6, 7, 8, 9, 10};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;
static enum ker_transport_protocol expected_protocol[2];
static unsigned char expected_payload[2][16];
static unsigned int expected_payload_length[2];
static unsigned char expected_frame[2][512];
static unsigned int expected_frame_length[2];
static unsigned int roundtrip_sink_index;

static int sink(struct rte_mbuf *chain, void *arg)
{
    CHECK(arg == &tx && !worker.timers.polling);
    calls++;
    if (rx_enabled) {
        unsigned int index = roundtrip_sink_index ? 1U : 0U;
        roundtrip_sink_index++;
        CHECK(chain->pkt_len == expected_frame_length[index]);
        unsigned int offset = 0;
        for (struct rte_mbuf *seg = chain; seg; seg = seg->next) {
            CHECK(seg->ol_flags == 0 && offset + seg->data_len <= expected_frame_length[index]);
            CHECK(!memcmp(rte_pktmbuf_mtod(seg, const void *), expected_frame[index] + offset, seg->data_len));
            offset += seg->data_len;
        }
        CHECK(offset == expected_frame_length[index]);
    }
    if (calls == fail_on_call) return -EAGAIN;
    if (sink_error) return sink_error;
    accepted = chain;
    return 0;
}

static int receive_packet(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling && rx_calls < 2);
    unsigned int index = rx_calls++;
    CHECK(message->protocol == expected_protocol[index]);
    if (message->protocol == KER_TRANSPORT_UDP) {
        CHECK(message->packet.udp.source_port == source_port &&
            message->packet.udp.destination_port == destination_port);
        CHECK(message->packet.udp.payload_length == expected_payload_length[index]);
        CHECK(!memcmp(message->packet.udp.payload, expected_payload[index], expected_payload_length[index]));
    } else {
        CHECK(message->packet.tcp.source_port == source_port &&
            message->packet.tcp.destination_port == destination_port);
        CHECK(message->packet.tcp.payload_length == expected_payload_length[index]);
        CHECK(!memcmp(message->packet.tcp.payload, expected_payload[index], expected_payload_length[index]));
    }
    return NET_RX_SUCCESS;
}

static int rx_poll(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!rx_enabled || !accepted) return 0;
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, accepted, 128, &skb) == 0);
    ker_packet_free(accepted);
    accepted = NULL;
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct sk_buff *make_packet(void)
{
    struct sk_buff *skb = NULL;
    uint8_t *data = NULL;
    CHECK(ker_skb_alloc(&context, sizeof(expected), 64, &skb) == 0);
    CHECK(ker_skb_put(skb, sizeof(expected), &data) == 0);
    expected_length = sizeof(expected);
    for (unsigned int i = 0; i < sizeof(expected); i++) data[i] = expected[i] = (uint8_t)(i * 29U + 7U);
    return skb;
}

static void transport_roundtrip(void)
{
    static const uint8_t udp_payload[] = {1, 3, 5, 7, 9};
    static const uint8_t tcp_payload[] = {2, 4, 6, 8, 10, 12};
    memcpy(expected_payload[0], udp_payload, sizeof(udp_payload));
    memcpy(expected_payload[1], tcp_payload, sizeof(tcp_payload));
    expected_payload_length[0] = sizeof(udp_payload);
    expected_payload_length[1] = sizeof(tcp_payload);
    expected_protocol[0] = KER_TRANSPORT_UDP;
    expected_protocol[1] = KER_TRANSPORT_TCP;
    struct sk_buff *udp = NULL, *tcp = NULL;
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, udp_payload, sizeof(udp_payload), &udp) == 0);
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, (__be32)0x01020304,
        (__be32)0x05060708, (__be16)4096, 0x18, 64, tcp_payload,
        sizeof(tcp_payload), &tcp) == 0);
    expected_frame_length[0] = udp->len;
    expected_frame_length[1] = tcp->len;
    CHECK(expected_frame_length[0] <= sizeof(expected_frame[0]) &&
        expected_frame_length[1] <= sizeof(expected_frame[1]));
    memcpy(expected_frame[0], udp->data, udp->len);
    memcpy(expected_frame[1], tcp->data, tcp->len);
    CHECK(ker_tx_export_init_chain(&tx, &context, 2, SIZE_MAX, 13, sink, &tx) == 0);
    CHECK(ker_tx_export_enqueue(&tx, &udp) == 0 && !udp);
    CHECK(ker_tx_export_enqueue(&tx, &tcp) == 0 && !tcp);
    rx_enabled = true;
    roundtrip_sink_index = 0;
    fail_on_call = calls + 2;
    sink_error = 0;
    worker.config.tx_budget = 2;
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && rx_calls == 1);
    CHECK(tx.last_completed == 1 && tx.last_error == -EAGAIN && tx.pending &&
        tx.packets == 1 && tx.bytes == tx.pending->truesize && context.live == 1);
    fail_on_call = 0;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && rx_calls == 2);
    CHECK(!tx.pending && !tx.packets && !tx.bytes && context.live == 0);
    rx_enabled = false;
    CHECK(ker_tx_export_cleanup(&tx) == 0);
}

static void check_chain(struct rte_mbuf *chain)
{
    CHECK(chain && chain->nb_segs > 1 && chain->pkt_len == expected_length);
    unsigned int offset = 0, count = 0;
    for (struct rte_mbuf *seg = chain; seg; seg = seg->next) {
        CHECK(seg->ol_flags == 0 && seg->data_len <= 80);
        CHECK(offset + seg->data_len <= expected_length);
        CHECK(!memcmp(rte_pktmbuf_mtod(seg, const uint8_t *), expected + offset, seg->data_len));
        offset += seg->data_len;
        count++;
    }
    CHECK(offset == expected_length && count == chain->nb_segs);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tx_chain", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tx_chain_skb") == 0);

    struct ker_tx_export invalid = {0};
    CHECK(ker_tx_export_init_chain(&invalid, &context, 1, 4096, 0, sink, &invalid) == -EINVAL);
    CHECK(!invalid.queue.context && !context.queue_live && invalid.mode == KER_TX_EXPORT_SINGLE);
    CHECK(ker_tx_export_init_chain(&invalid, &context, 1, 4096, UINT16_MAX + 1U, sink, &invalid) == -EOVERFLOW);
    CHECK(!invalid.queue.context && !context.queue_live && !invalid.segment_payload_limit);
    CHECK(ker_tx_export_init_chain(&invalid, &context, 1, 0, 13, sink, &invalid) == -EINVAL);
    CHECK(!invalid.queue.context && !context.queue_live && !invalid.segment_payload_limit);
    CHECK(ker_tx_export_init_chain(&invalid, &context, 1, 4096, 13, sink, &invalid) == 0);
    CHECK(context.queue_live == 1 && ker_tx_export_cleanup(&invalid) == 0 && !context.queue_live);
    CHECK(ker_tx_export_init_chain_software_checksum(&invalid, &context, 1, 4096, 13, sink, &invalid) == 0);
    CHECK(context.queue_live == 1 && ker_tx_export_cleanup(&invalid) == 0 && !context.queue_live);

    CHECK(ker_tx_export_init_chain(&tx, &context, 2, SIZE_MAX, 80, sink, &tx) == 0);
    CHECK(tx.mode == KER_TX_EXPORT_CHAIN_NONE && tx.segment_payload_limit == 80 && context.queue_live == 1);
    CHECK(ker_eth_device_init(&device, &context, "chain_tx0", 9, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_packet, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = rx_poll, .arg = &tx};
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    struct sk_buff *skb = make_packet(), *out = (void *)(uintptr_t)1;
    skb->ip_summed = CHECKSUM_PARTIAL;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == -ENOTSUP && skb && !tx.packets);
    /* Pinned Linux defines CHECKSUM_COMPLETE as the third ip_summed state. */
    skb->ip_summed = 2U;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == -ENOTSUP && skb && !tx.packets);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == -ENOTSUP && skb && !tx.packets);
    skb->ip_summed = CHECKSUM_NONE;
    skb_shinfo(skb)->gso_size = 1;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == -ENOTSUP && skb && !tx.packets);
    skb_shinfo(skb)->gso_size = 0;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb && tx.packets == 1);

    struct rte_mbuf *held[31]; unsigned int held_count = 0;
    while (held_count < 31 && (held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    CHECK(held_count > 7);
    struct sk_buff *pending_before = NULL;
    const unsigned int allocation_prefixes[] = {0, 3, 6};
    for (unsigned int trial = 0; trial < sizeof(allocation_prefixes) / sizeof(allocation_prefixes[0]); trial++) {
        unsigned int give = allocation_prefixes[trial];
        while (give--) ker_packet_free(held[--held_count]);
        CHECK(ker_tx_export_poll(&tx, 1) == -ENOMEM);
        if (!pending_before) pending_before = tx.pending;
        CHECK(tx.pending == pending_before && tx.packets == 1 && tx.bytes == pending_before->truesize);
        while ((held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    }
    while (held_count) ker_packet_free(held[--held_count]);

    CHECK(ker_worker_poll(&worker, 1, &progress) == -EAGAIN);
    CHECK(progress.tx == 0 && tx.pending && tx.last_error == -EAGAIN && calls == 1);
    CHECK(tx.pending->len == sizeof(expected));
    struct sk_buff *pending = tx.pending;
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out == pending);
    /* Cancel returned the retained original; caller owns it again. */
    CHECK(out && !tx.pending && tx.packets == 0 && tx.bytes == 0);
    CHECK(!memcmp(out->data, expected, sizeof(expected)));
    CHECK(ker_skb_free(out) == 0);
    out = (void *)(uintptr_t)1;
    CHECK(ker_tx_export_cancel(&tx, &out) == 0 && out == (void *)(uintptr_t)1);

    skb = make_packet();
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    sink_error = 1;
    CHECK(ker_worker_poll(&worker, 2, &progress) == -EPROTO && tx.last_error == -EPROTO);
    CHECK(tx.pending && tx.packets == 1 && tx.bytes == tx.pending->truesize);
    struct sk_buff *rejected_pending = tx.pending;
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out == rejected_pending);
    CHECK(out && !tx.pending && tx.packets == 0 && tx.bytes == 0);
    CHECK(ker_skb_free(out) == 0);
    skb = make_packet();
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    sink_error = 0;
    CHECK(ker_worker_poll(&worker, 3, &progress) == 0 && progress.tx == 1);
    CHECK(!tx.pending && tx.packets == 0 && context.live == 0 && accepted);
    check_chain(accepted);
    ker_packet_free(accepted);
    accepted = NULL;
    CHECK(ker_tx_export_cleanup(&tx) == 0 && context.queue_live == 0);
    transport_roundtrip();
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(calls == 6 && rx_calls == 2);
    return 0;
}
