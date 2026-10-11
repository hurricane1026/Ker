#include "check.h"
#include "eal.h"
#include "runtime/tcp-create.h"
#include "runtime/tx-export.h"
#include "runtime/ethernet.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <errno.h>

#define IPPROTO_TCP_TEST 6U
#define FIXED_FLAGS 0x12U
#define HEADROOM 128U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_tx_export tx;
static struct ker_worker worker;
static struct rte_mbuf *accepted;
static int backpressure = 1;
static unsigned int sink_calls, received;
static __be32 source_ip, destination_ip, sequence, acknowledgment;
static __be16 source_port, destination_port, window;
static unsigned char expected_payload[8];
static unsigned int expected_payload_len;
static unsigned char expected_options[40];
static const unsigned char source_mac[6] = {2,1,2,3,4,5};
static const unsigned char destination_mac[6] = {2,6,7,8,9,10};

static uint16_t sum16(const unsigned char *p, unsigned int n)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < n; i += 2) sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}
static uint16_t tcp_oracle(const unsigned char *ip, const unsigned char *tcp, unsigned int n)
{
    unsigned char pseudo[12]; memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = IPPROTO_TCP_TEST;
    pseudo[10] = (unsigned char)(n >> 8); pseudo[11] = (unsigned char)n;
    uint32_t sum = sum16(pseudo, sizeof(pseudo)) + sum16(tcp, n);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}
static int tx_sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(arg == &tx && worker.polling && !worker.timers.polling);
    ++sink_calls;
    if (backpressure) { backpressure = 0; return -EAGAIN; }
    CHECK(!accepted && packet->ol_flags == 0); accepted = packet; return 0;
}
static int tcp_message(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_TCP);
    const struct ker_tcp_packet_view *tcp = &message->packet.tcp;
    CHECK(tcp->tcp_header_length == 60 && tcp->payload_length == expected_payload_len);
    CHECK(tcp->source_port == source_port && tcp->destination_port == destination_port);
    CHECK(tcp->header[12] == 0xf0 && tcp->header[13] == FIXED_FLAGS);
    CHECK(!memcmp(tcp->header + 20, expected_options, sizeof(expected_options)));
    CHECK(!memcmp(tcp->payload, expected_payload, expected_payload_len));
    CHECK(!memcmp(tcp->header + 4, &sequence, 4) && !memcmp(tcp->header + 8, &acknowledgment, 4));
    ++received; return NET_RX_SUCCESS;
}
static int rx_poll(void *arg, unsigned int budget)
{
    (void)arg; CHECK(budget == 1);
    if (!accepted) return 0;
    CHECK(context.live == 0); /* TX transfer released the original constructor skb. */
    const unsigned char *bytes = rte_pktmbuf_mtod(accepted, const unsigned char *);
    unsigned int total = accepted->pkt_len, offset = 0, i = 0;
    const unsigned int lengths[] = {53, 3, 7, 1, 9, 4, 11};
    struct rte_mbuf *chain = NULL;
    while (offset < total) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool); CHECK(segment);
        unsigned int n = lengths[i++ % (sizeof(lengths) / sizeof(lengths[0]))];
        if (n > total - offset) n = total - offset;
        unsigned char *out = (unsigned char *)rte_pktmbuf_append(segment, (uint16_t)n); CHECK(out);
        memcpy(out, bytes + offset, n);
        if (!chain) chain = segment; else CHECK(rte_pktmbuf_chain(chain, segment) == 0);
        offset += n;
    }
    CHECK(chain && chain->nb_segs > 1 && chain->pkt_len == total);
    ker_packet_free(accepted); accepted = NULL;
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, HEADROOM, &skb) == 0);
    ker_packet_free(chain);
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}
static struct sk_buff *create(const void *options, unsigned int olen, const void *payload, unsigned int plen)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        options, olen, payload, plen, &skb) == 0 && skb);
    return skb;
}
static void verify(struct sk_buff *skb, const unsigned char *options, unsigned int olen,
    const unsigned char *payload, unsigned int plen)
{
    const unsigned char *frame = skb->data, *ip = frame + ETH_HLEN, *tcp = ip + 20;
    unsigned int thlen = 20 + olen, tcplen = thlen + plen;
    CHECK(skb->len == ETH_HLEN + 20 + tcplen && skb_headroom(skb) == HEADROOM);
    CHECK(skb->mac_header == HEADROOM && skb->network_header == HEADROOM + ETH_HLEN);
    CHECK(skb->transport_header == HEADROOM + ETH_HLEN + 20);
    CHECK(!memcmp(frame, destination_mac, 6) && !memcmp(frame + 6, source_mac, 6));
    CHECK(frame[12] == 8 && frame[13] == 0 && ip[0] == 0x45 && ip[9] == IPPROTO_TCP_TEST);
    CHECK(ip[2] == (unsigned char)((20 + tcplen) >> 8) && ip[3] == (unsigned char)(20 + tcplen));
    CHECK(sum16(ip, 20) == 0xffff && tcp[12] == (unsigned char)((thlen / 4) << 4));
    CHECK(tcp[13] == FIXED_FLAGS && tcp[18] == 0 && tcp[19] == 0);
    CHECK(!memcmp(tcp + 20, options, olen));
    CHECK(tcp_oracle(ip, tcp, tcplen) == 0xffff);
    if (plen) CHECK(!memcmp(tcp + thlen, payload, plen));
}
static void invalid_inputs(void)
{
    unsigned char options[44]; for (unsigned int i = 0; i < sizeof(options); ++i) options[i] = (unsigned char)i;
    const unsigned char copy[44] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43};
    unsigned char payload[3] = {0xaa,0xbb,0xcc}; const unsigned char payload_copy[3] = {0xaa,0xbb,0xcc};
    struct sk_buff *out = (void *)(uintptr_t)0x1234;
#define REJECT(opts, n, data, len, code) do { CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64, (opts), (n), (data), (len), &out) == (code)); CHECK(out == (void *)(uintptr_t)0x1234); } while (0)
    REJECT(NULL, 4, payload, sizeof(payload), -EINVAL);
    REJECT(options, 3, payload, sizeof(payload), -EINVAL);
    REJECT(options, 44, payload, sizeof(payload), -EINVAL);
    REJECT(options, UINT_MAX, payload, sizeof(payload), -EINVAL);
    REJECT(options, 4, NULL, 1, -EINVAL);
    REJECT(options, 4, payload, 65492, -EMSGSIZE);
#undef REJECT
    CHECK(!memcmp(options, copy, sizeof(options)) && !memcmp(payload, payload_copy, sizeof(payload)) && context.live == 0);

    unsigned char one_option[4] = {1, 2, 3, 4};
    ker_memory_fail_after(0);
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        one_option, sizeof(one_option), payload, sizeof(payload), &out) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(out == (void *)(uintptr_t)0x1234 && context.live == 0);
    struct sk_buff *retry = NULL;
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        one_option, sizeof(one_option), payload, sizeof(payload), &retry) == 0);
    CHECK(retry && context.live == 1 && ker_skb_free(retry) == 0 && context.live == 0);

    struct rte_mbuf *held[127]; unsigned int held_count = 0;
    while (held_count < 127 && (held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    CHECK(held_count == 127);
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        one_option, sizeof(one_option), payload, sizeof(payload), &out) == -ENOMEM);
    CHECK(out == (void *)(uintptr_t)0x1234 && context.live == 0);
    ker_packet_free(held[--held_count]);
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        one_option, sizeof(one_option), payload, sizeof(payload), &retry) == 0);
    CHECK(context.live == 1 && ker_skb_free(retry) == 0 && context.live == 0);
    while (held_count) ker_packet_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 127);
}
int main(void)
{
    ker_test_eal_init(); source_ip = rte_cpu_to_be_32(0xc0000201); destination_ip = rte_cpu_to_be_32(0xc6336402);
    source_port = rte_cpu_to_be_16(0x1234); destination_port = rte_cpu_to_be_16(0x5678);
    sequence = rte_cpu_to_be_32(0x01020304); acknowledgment = rte_cpu_to_be_32(0xa0b0c0d0); window = rte_cpu_to_be_16(0x2000);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tcp_options", 127, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tcp_options_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "tcp-options0", 4, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, tcp_message, &receiver) == 0);
    CHECK(ker_tx_export_init(&tx, &context, 2, SIZE_MAX, tx_sink, &tx) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = rx_poll, .arg = &tx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    unsigned char options4[4] = {1,1,1,1};
    struct sk_buff *short_options = create(options4, sizeof(options4), NULL, 0);
    verify(short_options, options4, sizeof(options4), NULL, 0); CHECK(ker_skb_free(short_options) == 0);
    const unsigned char even_payload[4] = {0x91,0x82,0x73,0x64};
    struct sk_buff *even_options = create(options4, sizeof(options4), even_payload, sizeof(even_payload));
    verify(even_options, options4, sizeof(options4), even_payload, sizeof(even_payload));
    CHECK(ker_skb_free(even_options) == 0);
    unsigned char options40[40]; for (unsigned int i = 0; i < sizeof(options40); ++i) options40[i] = (unsigned char)(i * 3U + 1U);
    unsigned char options40_original[40]; memcpy(options40_original, options40, sizeof(options40));
    unsigned char odd_payload[5] = {0x11,0x22,0x33,0x44,0x55};
    struct sk_buff *max_options = create(options40, sizeof(options40), odd_payload, sizeof(odd_payload));
    verify(max_options, options40, sizeof(options40), odd_payload, sizeof(odd_payload));
    CHECK(!memcmp(options40, options40_original, sizeof(options40)));
    CHECK(ker_skb_free(max_options) == 0);
    memcpy(expected_options, options40, sizeof(expected_options));

    /* The old API is exactly the zero-options specialization. */
    const unsigned char data[4] = {4,3,2,1};
    struct sk_buff *plain = NULL, *via_options = NULL;
    CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64, data, sizeof(data), &plain) == 0);
    via_options = create(NULL, 0, data, sizeof(data));
    CHECK(plain->len == via_options->len && !memcmp(plain->data, via_options->data, plain->len));
    CHECK(plain->mac_header == via_options->mac_header && plain->network_header == via_options->network_header &&
        plain->transport_header == via_options->transport_header && plain->mac_len == via_options->mac_len);
    CHECK(ker_skb_free(plain) == 0 && ker_skb_free(via_options) == 0);

    memcpy(expected_payload, odd_payload, sizeof(odd_payload)); expected_payload_len = sizeof(odd_payload);
    struct sk_buff *packet = create(options40, sizeof(options40), odd_payload, sizeof(odd_payload));
    CHECK(!memcmp(options40, options40_original, sizeof(options40)));
    memset(options40, 0xee, sizeof(options40)); memset(odd_payload, 0xdd, sizeof(odd_payload));
    CHECK(ker_tx_export_enqueue(&tx, &packet) == 0 && !packet && context.live == 1);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN && !progress.tx && !progress.rx);
    CHECK(tx.pending && context.live == 1 && !accepted);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0 && progress.tx == 1 && progress.rx == 1);
    CHECK(sink_calls == 2 && received == 1 && context.live == 0 && !tx.packets && !accepted);
    unsigned char max_payload[65455]; memset(max_payload, 0x5a, sizeof(max_payload));
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        options40_original, sizeof(options40_original), max_payload, sizeof(max_payload), &sentinel) == -ENOSPC);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, destination_mac, source_ip, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, FIXED_FLAGS, 64,
        options40_original, sizeof(options40_original), max_payload, sizeof(max_payload) + 1U, &sentinel) == -EMSGSIZE);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    invalid_inputs();

    CHECK(ker_tx_export_cleanup(&tx) == 0 && ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0 && ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 127 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
