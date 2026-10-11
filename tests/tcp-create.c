#include "check.h"
#include "eal.h"
#include "runtime/tcp-create.h"
#include "runtime/tx-export.h"
#include "runtime/ethernet.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <errno.h>

#define TCP_PROTOCOL 6U
#define TCP_FLAGS 0x12U
#define TEST_HEADROOM 128U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_tx_export tx_export;
static struct ker_worker worker;
static struct rte_mbuf *accepted;
static unsigned int sink_calls, delivered;
static int sink_backpressure = 1;
static const unsigned char source_mac[ETH_ALEN] = {2, 0x11, 0x12, 0x13, 0x14, 0x15};
static const unsigned char destination_mac[ETH_ALEN] = {2, 0x21, 0x22, 0x23, 0x24, 0x25};
static __be32 source_ip, destination_ip, sequence, acknowledgment;
static __be16 source_port, destination_port, window;
static unsigned char expected_payload[16];
static unsigned int expected_length;

static uint16_t fold_sum(const unsigned char *bytes, unsigned int length)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < length; i += 2)
        sum += ((uint16_t)bytes[i] << 8) | (i + 1 < length ? bytes[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}
static uint16_t tcp_sum(const unsigned char *ip, const unsigned char *tcp, unsigned int length)
{
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = TCP_PROTOCOL;
    pseudo[10] = (unsigned char)(length >> 8); pseudo[11] = (unsigned char)length;
    uint32_t sum = fold_sum(pseudo, sizeof(pseudo)) + fold_sum(tcp, length);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}
static int sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(arg == &tx_export && worker.polling && !worker.timers.polling);
    ++sink_calls;
    if (sink_backpressure) { sink_backpressure = 0; return -EAGAIN; }
    CHECK(!accepted && packet->ol_flags == 0);
    accepted = packet; /* Application copy consumer accepts ownership. */
    return 0;
}
static int receive_tcp(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_TCP);
    const struct ker_tcp_packet_view *tcp = &message->packet.tcp;
    CHECK(tcp->source_port == source_port && tcp->destination_port == destination_port);
    CHECK(tcp->tcp_header_length == 20 && tcp->payload_length == expected_length);
    CHECK(!memcmp(tcp->payload, expected_payload, expected_length));
    CHECK(!memcmp(tcp->header + 4, &sequence, sizeof(sequence)));
    CHECK(!memcmp(tcp->header + 8, &acknowledgment, sizeof(acknowledgment)));
    CHECK(tcp->header[12] == 0x50 && tcp->header[13] == TCP_FLAGS);
    CHECK(!memcmp(tcp->header + 14, &window, sizeof(window)));
    ++delivered;
    return NET_RX_SUCCESS;
}
static int rx(void *arg, unsigned int budget)
{
    (void)arg; CHECK(budget == 1);
    if (!accepted) return 0;
    CHECK(context.live == 0); /* TX accepted the copy and released constructor skb. */
    const unsigned char *source = rte_pktmbuf_mtod(accepted, const unsigned char *);
    unsigned int total = accepted->pkt_len;
    const unsigned int pieces[] = {1, 7, 2, 5, 3, 11};
    struct rte_mbuf *chain = NULL; unsigned int offset = 0, index = 0;
    while (offset < total) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool); CHECK(segment);
        unsigned int count = pieces[index++ % (sizeof(pieces) / sizeof(pieces[0]))];
        if (count > total - offset) count = total - offset;
        unsigned char *data = (unsigned char *)rte_pktmbuf_append(segment, (uint16_t)count); CHECK(data);
        memcpy(data, source + offset, count);
        if (!chain) chain = segment; else CHECK(rte_pktmbuf_chain(chain, segment) == 0);
        offset += count;
    }
    CHECK(chain && chain->nb_segs > 1 && chain->pkt_len == total);
    ker_packet_free(accepted); accepted = NULL; /* The accepted copy is now represented by the real chain. */
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, TEST_HEADROOM, &skb) == 0);
    ker_packet_free(chain);
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static void verify_constructed(struct sk_buff *skb, const void *payload, unsigned int length,
    __be32 seq, __be32 ack, __be16 win, uint8_t flags, uint8_t ttl)
{
    const unsigned char *frame = skb->data;
    const unsigned int tcp_length = 20 + length;
    CHECK(skb->len == ETH_HLEN + 20 + tcp_length);
    CHECK(skb_headroom(skb) == TEST_HEADROOM && skb->mac_header == TEST_HEADROOM);
    CHECK(skb->network_header == TEST_HEADROOM + ETH_HLEN);
    CHECK(skb->transport_header == TEST_HEADROOM + ETH_HLEN + 20);
    CHECK(skb->mac_len == ETH_HLEN && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(!memcmp(frame, destination_mac, 6) && !memcmp(frame + 6, source_mac, 6));
    CHECK(frame[12] == 0x08 && frame[13] == 0x00);
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(ip[0] == 0x45 && ip[1] == 0 && ip[4] == 0 && ip[5] == 0);
    CHECK(ip[6] == 0 && ip[7] == 0 && ip[8] == ttl && ip[9] == TCP_PROTOCOL);
    CHECK(ip[2] == (unsigned char)((20 + tcp_length) >> 8) && ip[3] == (unsigned char)(20 + tcp_length));
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(fold_sum(ip, 20) == 0xffff);
    const unsigned char *tcp = ip + 20;
    CHECK(!memcmp(tcp, &source_port, 2) && !memcmp(tcp + 2, &destination_port, 2));
    CHECK(!memcmp(tcp + 4, &seq, 4) && !memcmp(tcp + 8, &ack, 4));
    CHECK(tcp[12] == 0x50 && tcp[13] == flags && !memcmp(tcp + 14, &win, 2));
    CHECK(tcp[18] == 0 && tcp[19] == 0);
    CHECK(tcp_sum(ip, tcp, tcp_length) == 0xffff);
    if (length) CHECK(!memcmp(tcp + 20, payload, length));
}
static struct sk_buff *construct(const void *payload, unsigned int length)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        payload, length, &skb) == 0 && skb);
    return skb;
}
static void failure_boundaries(void)
{
    unsigned char payload[4] = {0x31,0x32,0x33,0x34};
    const unsigned char before[4] = {0x31,0x32,0x33,0x34};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
#define FAIL(args, code) do { CHECK(ker_tcp_ipv4_create args == (code)); CHECK(sentinel == (void *)(uintptr_t)0x1234); } while (0)
    FAIL((NULL, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64, payload, 4, &sentinel), -EINVAL);
    FAIL((&context, NULL, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64, payload, 4, &sentinel), -EINVAL);
    FAIL((&context, source_mac, NULL, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64, payload, 4, &sentinel), -EINVAL);
    FAIL((&context, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 0, payload, 4, &sentinel), -EINVAL);
    FAIL((&context, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, 0x20, 64, payload, 4, &sentinel), -ENOTSUP);
    FAIL((&context, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64, NULL, 1, &sentinel), -EINVAL);
    FAIL((&context, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64, payload, 65496, &sentinel), -EMSGSIZE);
#undef FAIL
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        payload, 4, NULL) == -EINVAL);
    CHECK(!memcmp(payload, before, sizeof(payload)) && context.live == 0);
    static unsigned char maximum_protocol_payload[65495];
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        maximum_protocol_payload, sizeof(maximum_protocol_payload), &sentinel) == -ENOSPC);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    unsigned char too_large[1900] = {0};
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        too_large, sizeof(too_large), &sentinel) == -ENOSPC);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);

    ker_memory_fail_after(0);
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        payload, sizeof(payload), &sentinel) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    struct sk_buff *retry = construct(payload, sizeof(payload));
    CHECK(context.live == 1 && ker_skb_free(retry) == 0 && context.live == 0);

    struct rte_mbuf *held[63]; unsigned int count = 0;
    while (count < 63 && (held[count] = ker_packet_alloc(&pool)) != NULL) count++;
    CHECK(count == 63);
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, TCP_FLAGS, 64,
        payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    ker_packet_free(held[--count]);
    retry = construct(payload, sizeof(payload)); CHECK(context.live == 1);
    CHECK(ker_skb_free(retry) == 0);
    while (count) ker_packet_free(held[--count]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
}

static void tcp_zero_checksum(void)
{
    unsigned char payload[2], ip[20] = {0}, tcp[22] = {0};
    ip[0] = 0x45; ip[2] = 0; ip[3] = 42; ip[9] = TCP_PROTOCOL;
    memcpy(ip + 12, &source_ip, 4); memcpy(ip + 16, &destination_ip, 4);
    memcpy(tcp, &source_port, 2); memcpy(tcp + 2, &destination_port, 2);
    memcpy(tcp + 4, &sequence, 4); memcpy(tcp + 8, &acknowledgment, 4);
    tcp[12] = 0x50; tcp[13] = TCP_FLAGS; memcpy(tcp + 14, &window, 2);
    bool found = false;
    for (unsigned int v = 0; v <= UINT16_MAX; ++v) {
        payload[0] = (unsigned char)(v >> 8); payload[1] = (unsigned char)v;
        memcpy(tcp + 20, payload, 2);
        if (tcp_sum(ip, tcp, sizeof(tcp)) == 0xffff) { found = true; break; }
    }
    CHECK(found);
    struct sk_buff *skb = construct(payload, sizeof(payload));
    const unsigned char *tcp_bytes = skb->data + ETH_HLEN + 20;
    CHECK(tcp_bytes[16] == 0 && tcp_bytes[17] == 0 && tcp_sum(skb->data + ETH_HLEN, tcp_bytes, sizeof(tcp)) == 0xffff);
    CHECK(ker_skb_free(skb) == 0);
}

int main(void)
{
    ker_test_eal_init();
    source_ip = rte_cpu_to_be_32(0xc0000201); destination_ip = rte_cpu_to_be_32(0xc6336402);
    source_port = rte_cpu_to_be_16(0x1234); destination_port = rte_cpu_to_be_16(0x5678);
    sequence = rte_cpu_to_be_32(0x01020304); acknowledgment = rte_cpu_to_be_32(0xa0b0c0d0);
    window = rte_cpu_to_be_16(0x2000);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tcp_create", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tcp_create_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "tcp-create0", 3, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_tcp, &receiver) == 0);
    CHECK(ker_tx_export_init(&tx_export, &context, 2, SIZE_MAX, sink, &tx_export) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = rx, .arg = &tx_export};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    const unsigned char payload[] = {0x10,0x21,0x32,0x43,0x54};
    const unsigned char even_payload[] = {0xaa,0xbb,0xcc,0xdd};
    __be16 saved_source_port = source_port, saved_destination_port = destination_port, saved_window = window;
    __be32 saved_sequence = sequence, saved_acknowledgment = acknowledgment;
    source_port = 0; destination_port = 0; window = 0; sequence = 0; acknowledgment = 0;
    struct sk_buff *zero_fields = NULL;
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        0, 0, 0, 0, 0, 0xc0, 1, NULL, 0, &zero_fields) == 0);
    verify_constructed(zero_fields, NULL, 0, 0, 0, 0, 0xc0, 1);
    CHECK(ker_skb_free(zero_fields) == 0);
    source_port = saved_source_port; destination_port = saved_destination_port; window = saved_window;
    sequence = saved_sequence; acknowledgment = saved_acknowledgment;
    struct sk_buff *vector = construct(NULL, 0);
    verify_constructed(vector, NULL, 0, sequence, acknowledgment, window, TCP_FLAGS, 64);
    CHECK(ker_skb_free(vector) == 0);
    vector = construct(even_payload, sizeof(even_payload));
    verify_constructed(vector, even_payload, sizeof(even_payload), sequence, acknowledgment, window, TCP_FLAGS, 64);
    CHECK(ker_skb_free(vector) == 0);
    memcpy(expected_payload, payload, sizeof(payload)); expected_length = sizeof(payload);
    struct sk_buff *packet = construct(payload, expected_length);
    verify_constructed(packet, payload, expected_length, sequence, acknowledgment, window, TCP_FLAGS, 64);
    CHECK(ker_tx_export_enqueue(&tx_export, &packet) == 0 && !packet && context.live == 1);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN && !progress.tx && !progress.rx);
    CHECK(tx_export.pending && context.live == 1 && !accepted);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0 && progress.tx == 1 && progress.rx == 1);
    CHECK(!tx_export.pending && !tx_export.packets && !accepted && context.live == 0 && delivered == 1);
    CHECK(sink_calls == 2);

    tcp_zero_checksum();
    failure_boundaries();
    CHECK(ker_tx_export_cleanup(&tx_export) == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
