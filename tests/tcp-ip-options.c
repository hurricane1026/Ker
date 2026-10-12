#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/ipv4-packet-view.h"
#include "runtime/memory.h"
#include "runtime/receive.h"
#include "runtime/skb.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/tcp-packet-view.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 127U
#define FIXED_FLAGS 0x12U
#define TCP_PROTO 6U
struct fixture {
    struct ker_packet_pool pool;
    struct ker_skb_context context;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_tx_ring ring;
    struct ker_tx_export tx;
    struct ker_worker worker;
    const unsigned char *expected_ip_options[2];
    unsigned int expected_ip_options_len[2];
    const unsigned char *expected_tcp_options[2];
    unsigned int expected_tcp_options_len[2];
    const unsigned char *expected_payload[2];
    unsigned int expected_payload_len[2];
    unsigned int sink_calls;
    unsigned int received;
    bool reject_once;
};
static struct fixture f;
static const unsigned char source_mac[6] = {2,1,2,3,4,5};
static const unsigned char destination_mac[6] = {2,6,7,8,9,10};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;
static const __be32 sequence = (__be32)0x04030201;
static const __be32 acknowledgment = (__be32)0xd0c0b0a0;
static const __be16 window = (__be16)0x0020;

static uint16_t folded_sum(const unsigned char *bytes, unsigned int length)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < length; i += 2)
        sum += ((uint16_t)bytes[i] << 8) | (i + 1 < length ? bytes[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)sum;
}

static void verify_wire(const struct sk_buff *skb,
    const unsigned char *ip_options, unsigned int ip_options_length,
    const unsigned char *tcp_options, unsigned int tcp_options_length,
    const unsigned char *payload, unsigned int payload_length)
{
    const unsigned int ihl = 20 + ip_options_length;
    const unsigned int thl = 20 + tcp_options_length;
    const unsigned int tcp_length = thl + payload_length;
    const unsigned int ip_length = ihl + tcp_length;
    CHECK(skb->len == ETH_HLEN + ip_length && skb_headroom(skb) == 128);
    CHECK(skb->mac_header == 128 && skb->network_header == 128 + ETH_HLEN);
    CHECK(skb->transport_header == 128 + ETH_HLEN + ihl && skb->mac_len == ETH_HLEN);
    const unsigned char *frame = skb->data;
    const unsigned char *ip = frame + ETH_HLEN;
    const unsigned char *tcp = ip + ihl;
    CHECK(!memcmp(frame, destination_mac, 6) && !memcmp(frame + 6, source_mac, 6));
    CHECK(frame[12] == 8 && frame[13] == 0);
    CHECK(ip[0] == (unsigned char)(0x40U | ihl / 4U) && ip[1] == 0);
    CHECK(ip[2] == (unsigned char)(ip_length >> 8) && ip[3] == (unsigned char)ip_length);
    CHECK(ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0);
    CHECK(ip[8] == 64 && ip[9] == TCP_PROTO);
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(folded_sum(ip, ihl) == 0xffffU);
    if (ip_options_length) CHECK(!memcmp(ip + 20, ip_options, ip_options_length));
    CHECK(!memcmp(tcp, &source_port, 2) && !memcmp(tcp + 2, &destination_port, 2));
    CHECK(!memcmp(tcp + 4, &sequence, 4) && !memcmp(tcp + 8, &acknowledgment, 4));
    CHECK(tcp[12] == (unsigned char)(thl / 4U << 4) && tcp[13] == FIXED_FLAGS);
    CHECK(tcp[14] == 0x20 && tcp[15] == 0 && tcp[18] == 0 && tcp[19] == 0);
    if (tcp_options_length) CHECK(!memcmp(tcp + 20, tcp_options, tcp_options_length));
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = TCP_PROTO;
    pseudo[10] = (unsigned char)(tcp_length >> 8); pseudo[11] = (unsigned char)tcp_length;
    uint32_t sum = folded_sum(pseudo, sizeof(pseudo)) + folded_sum(tcp, tcp_length);
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    CHECK(sum == 0xffffU);
    if (payload_length) CHECK(!memcmp(tcp + thl, payload, payload_length));
}

static int message_receive(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &f && f.worker.polling && !f.worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_TCP && f.received < 2);
    unsigned int i = f.received;
    const struct ker_ipv4_packet_view *ipv4 = &message->ipv4;
    const struct ker_tcp_packet_view *tcp = &message->packet.tcp;
    unsigned int ip_len = 20 + f.expected_ip_options_len[i];
    unsigned int tcp_len = 20 + f.expected_tcp_options_len[i];
    CHECK(ipv4->header_length == ip_len);
    CHECK(ipv4->packet_length == ip_len + tcp_len + f.expected_payload_len[i]);
    if (f.expected_ip_options_len[i])
        CHECK(!memcmp(ipv4->header + 20, f.expected_ip_options[i], f.expected_ip_options_len[i]));
    CHECK(tcp->tcp_header_length == tcp_len && tcp->payload_length == f.expected_payload_len[i]);
    CHECK(tcp->source_port == source_port && tcp->destination_port == destination_port);
    CHECK(!memcmp(tcp->header + 4, &sequence, 4) && !memcmp(tcp->header + 8, &acknowledgment, 4));
    if (f.expected_tcp_options_len[i])
        CHECK(!memcmp(tcp->header + 20, f.expected_tcp_options[i], f.expected_tcp_options_len[i]));
    if (f.expected_payload_len[i])
        CHECK(!memcmp(tcp->payload, f.expected_payload[i], f.expected_payload_len[i]));
    ++f.received;
    return NET_RX_SUCCESS;
}

static int sink(struct rte_mbuf *chain, void *arg)
{
    CHECK(arg == &f && f.worker.polling && !f.worker.timers.polling);
    ++f.sink_calls;
    if (f.reject_once) { f.reject_once = false; return -EAGAIN; }
    return ker_tx_ring_sink(chain, &f.ring);
}

static int tx_poll(void *arg, unsigned int budget)
{
    CHECK(arg == &f);
    return ker_tx_export_poll(&f.tx, budget);
}

static int rx_poll(void *arg, unsigned int budget)
{
    CHECK(arg == &f && budget == 1);
    struct rte_mbuf *chain = NULL;
    int taken = ker_tx_ring_take(&f.ring, &chain);
    if (!taken) return 0;
    CHECK(taken == 1 && chain && f.context.live == 1 - f.received);
    char *padding = rte_pktmbuf_append(chain, 5);
    CHECK(padding);
    memset(padding, 0xa7, 5);
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&f.device, chain, 128, &skb) == 0);
    ker_packet_free(chain);
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&f.runtime, &f.device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct sk_buff *create(const void *ip_options, unsigned int ip_options_length,
    const void *tcp_options, unsigned int tcp_options_length,
    const void *payload, unsigned int payload_length)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, sequence,
        acknowledgment, window, FIXED_FLAGS, 64, ip_options, ip_options_length,
        tcp_options, tcp_options_length, payload, payload_length, &skb) == 0 && skb);
    return skb;
}

struct foreign_call { int result; struct sk_buff *output; };
static void *foreign_owner(void *arg)
{
    struct foreign_call *call = arg;
    call->result = ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, sequence,
        acknowledgment, window, FIXED_FLAGS, 64, NULL, 0, NULL, 0, NULL, 0,
        &call->output);
    return NULL;
}

static void construct_and_validate(void)
{
    unsigned char payload_odd[] = {0x10,0x21,0x32,0x43,0x54};
    const unsigned char payload_even[] = {0xa1,0xb2,0xc3,0xd4};
    unsigned char ip4[] = {1, 0, 0x94, 4};
    unsigned char tcp4[] = {2, 4, 0x05, 0xb4};
    unsigned char ip40[40], tcp40[40];
    for (unsigned int i = 0; i < 40; ++i) {
        ip40[i] = (unsigned char)(0x81U + i * 3U);
        tcp40[i] = (unsigned char)(0x19U + i * 5U);
    }
    struct sk_buff *skb = create(NULL, 0, NULL, 0, NULL, 0);
    verify_wire(skb, NULL, 0, NULL, 0, NULL, 0);
    CHECK(ker_skb_free(skb) == 0);
    skb = create(ip4, sizeof(ip4), NULL, 0, payload_odd, sizeof(payload_odd));
    verify_wire(skb, ip4, sizeof(ip4), NULL, 0, payload_odd, sizeof(payload_odd));
    CHECK(ker_skb_free(skb) == 0);
    skb = create(NULL, 0, tcp4, sizeof(tcp4), payload_even, sizeof(payload_even));
    verify_wire(skb, NULL, 0, tcp4, sizeof(tcp4), payload_even, sizeof(payload_even));
    CHECK(ker_skb_free(skb) == 0);
    unsigned char ip40_copy[40], tcp40_copy[40], payload_copy[sizeof(payload_odd)];
    memcpy(ip40_copy, ip40, 40); memcpy(tcp40_copy, tcp40, 40);
    memcpy(payload_copy, payload_odd, sizeof(payload_odd));
    skb = create(ip40, 40, tcp40, 40, payload_odd, sizeof(payload_odd));
    CHECK(!memcmp(ip40, ip40_copy, 40) && !memcmp(tcp40, tcp40_copy, 40) &&
        !memcmp(payload_odd, payload_copy, sizeof(payload_odd)));
    memset(ip40, 0xee, 40); memset(tcp40, 0xdd, 40); memset((void *)payload_odd, 0xcc, sizeof(payload_odd));
    verify_wire(skb, ip40_copy, 40, tcp40_copy, 40, payload_copy, sizeof(payload_copy));
    CHECK(ker_skb_free(skb) == 0);
    skb = create(ip40_copy, 40, tcp40_copy, 40, NULL, 0);
    verify_wire(skb, ip40_copy, 40, tcp40_copy, 40, NULL, 0);
    CHECK(ker_skb_free(skb) == 0);
    skb = create(ip40_copy, 40, tcp40_copy, 40, payload_even, sizeof(payload_even));
    verify_wire(skb, ip40_copy, 40, tcp40_copy, 40, payload_even, sizeof(payload_even));
    CHECK(ker_skb_free(skb) == 0);

    /* Existing entry points remain exact zero-IP-options specializations. */
    struct sk_buff *legacy = NULL, *tcp_only = NULL, *new_zero = NULL, *new_tcp_only = NULL;
    CHECK(ker_tcp_ipv4_create(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment,
        window, FIXED_FLAGS, 64, payload_even, sizeof(payload_even), &legacy) == 0);
    CHECK(ker_tcp_ipv4_create_options(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment,
        window, FIXED_FLAGS, 64, tcp4, sizeof(tcp4), payload_even,
        sizeof(payload_even), &tcp_only) == 0);
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment,
        window, FIXED_FLAGS, 64, NULL, 0, NULL, 0, payload_even,
        sizeof(payload_even), &new_zero) == 0);
    CHECK(legacy->len == new_zero->len && !memcmp(legacy->data, new_zero->data, legacy->len));
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment,
        window, FIXED_FLAGS, 64, NULL, 0, tcp4, sizeof(tcp4), payload_even,
        sizeof(payload_even), &new_tcp_only) == 0);
    CHECK(tcp_only->len == new_tcp_only->len && !memcmp(tcp_only->data, new_tcp_only->data, tcp_only->len));
    CHECK(legacy->mac_header == new_zero->mac_header && legacy->network_header == new_zero->network_header &&
        legacy->transport_header == new_zero->transport_header && legacy->mac_len == new_zero->mac_len);
    verify_wire(new_zero, NULL, 0, NULL, 0, payload_even, sizeof(payload_even));
    CHECK(ker_skb_free(legacy) == 0 && ker_skb_free(tcp_only) == 0 &&
        ker_skb_free(new_zero) == 0 && ker_skb_free(new_tcp_only) == 0);
}

static void failures_and_recovery(void)
{
    unsigned char bad[44]; for (unsigned int i = 0; i < sizeof(bad); ++i) bad[i] = (unsigned char)i;
    unsigned char bad_copy[sizeof(bad)]; memcpy(bad_copy, bad, sizeof(bad));
    unsigned char payload[3] = {1, 2, 3}, payload_copy[3]; memcpy(payload_copy, payload, 3);
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
#define REJECT(ip, il, tcp, tl, data, dl, rc) do { \
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip, \
        destination_ip, source_port, destination_port, sequence, acknowledgment, window, \
        FIXED_FLAGS, 64, ip, il, tcp, tl, data, dl, &sentinel) == rc); \
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && f.context.live == 0); \
} while (0)
    REJECT(NULL, 4, NULL, 0, payload, 3, -EINVAL);
    REJECT(bad, 3, NULL, 0, payload, 3, -EINVAL);
    REJECT(bad, 44, NULL, 0, payload, 3, -EINVAL);
    REJECT(bad, UINT_MAX, NULL, 0, payload, 3, -EINVAL);
    REJECT(NULL, 0, NULL, 3, payload, 3, -EINVAL);
    REJECT(NULL, 0, bad, 44, payload, 3, -EINVAL);
    REJECT(NULL, 0, bad, UINT_MAX, payload, 3, -EINVAL);
    REJECT(NULL, 0, bad, 4, NULL, 1, -EINVAL);
    REJECT(bad, 40, bad, 40, payload, UINT_MAX, -EMSGSIZE);
    /* Protocol-legal maximum does not fit the configured linear skb backing. */
    const unsigned int maximum = UINT16_MAX - 60U - 60U;
    REJECT(bad, 40, bad, 40, payload, maximum, -ENOSPC);
    REJECT(bad, 40, bad, 40, payload, maximum + 1U, -EMSGSIZE);
    CHECK(!memcmp(payload, payload_copy, sizeof(payload)));
    CHECK(!memcmp(bad, bad_copy, sizeof(bad)));

    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment, window,
        FIXED_FLAGS, 0, NULL, 0, NULL, 0, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment, window,
        0x20, 64, NULL, 0, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && f.context.live == 0);
    struct foreign_call foreign = {.output = sentinel};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_owner, &foreign) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && foreign.result == -EXDEV &&
        foreign.output == sentinel && f.context.live == 0);

    ker_memory_fail_after(0);
    REJECT(bad, 4, bad, 4, payload, 3, -ENOMEM);
    ker_memory_fail_after(-1);
    struct sk_buff *retry = create(bad, 4, bad, 4, payload, sizeof(payload));
    CHECK(f.context.live == 1 && ker_skb_free(retry) == 0 && f.context.live == 0);

    struct rte_mbuf *held[POOL_COUNT];
    unsigned int available = rte_mempool_avail_count(f.pool.mbufs), count = 0;
    while (count < POOL_COUNT && (held[count] = ker_packet_alloc(&f.pool))) ++count;
    CHECK(count == available && count > 0);
    CHECK(ker_packet_pool_cleanup(&f.pool) == -EBUSY);
    CHECK(ker_tcp_ipv4_create_headers(&f.context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment, window,
        FIXED_FLAGS, 64, bad, 4, bad, 4, payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && f.context.live == 0);
    ker_packet_free(held[--count]);
    retry = create(bad, 4, bad, 4, payload, sizeof(payload));
    CHECK(f.context.live == 1 && ker_skb_free(retry) == 0 && f.context.live == 0);
    while (count) ker_packet_free(held[--count]);
    CHECK(rte_mempool_in_use_count(f.pool.mbufs) == 0);
#undef REJECT
}

static void worker_chain_roundtrip(void)
{
    static unsigned char ip_options[2][40], tcp_options[2][40];
    static unsigned char payloads[2][7] = {{9,8,7,6,5}, {1,3,5,7,9,11,13}};
    for (unsigned int i = 0; i < 40; ++i) {
        ip_options[0][i] = (unsigned char)(0x31U + i * 7U);
        tcp_options[0][i] = (unsigned char)(0xe1U - i * 3U);
        ip_options[1][i] = (unsigned char)(0x42U + i * 5U);
        tcp_options[1][i] = (unsigned char)(0x13U + i * 9U);
    }
    unsigned char expected_ip[2][40], expected_tcp[2][40];
    unsigned char expected_payload[2][7];
    memcpy(expected_ip, ip_options, sizeof(ip_options));
    memcpy(expected_tcp, tcp_options, sizeof(tcp_options));
    memcpy(expected_payload, payloads, sizeof(payloads));
    f.expected_ip_options[0] = expected_ip[0]; f.expected_ip_options_len[0] = 40;
    f.expected_tcp_options[0] = expected_tcp[0]; f.expected_tcp_options_len[0] = 40;
    f.expected_payload[0] = expected_payload[0]; f.expected_payload_len[0] = 5;
    f.expected_ip_options[1] = expected_ip[1]; f.expected_ip_options_len[1] = 4;
    f.expected_tcp_options[1] = expected_tcp[1]; f.expected_tcp_options_len[1] = 4;
    f.expected_payload[1] = expected_payload[1]; f.expected_payload_len[1] = 7;

    CHECK(ker_tx_ring_init(&f.ring, "tcp_ip_opts_ring", 2, SOCKET_ID_ANY) == 0);
    f.reject_once = true;
    CHECK(ker_tx_export_init_chain(&f.tx, &f.context, 2, SIZE_MAX, 13, sink, &f) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = tx_poll, .rx = rx_poll, .arg = &f};
    CHECK(ker_worker_init(&f.worker, &f.pool, &config, &ops) == 0);
    struct sk_buff *first = create(ip_options[0], 40, tcp_options[0], 40, payloads[0], 5);
    struct sk_buff *second = create(ip_options[1], 4, tcp_options[1], 4, payloads[1], 7);
    verify_wire(first, expected_ip[0], 40, expected_tcp[0], 40, expected_payload[0], 5);
    verify_wire(second, expected_ip[1], 4, expected_tcp[1], 4, expected_payload[1], 7);
    CHECK(ker_tx_export_enqueue(&f.tx, &first) == 0 && !first);
    CHECK(ker_tx_export_enqueue(&f.tx, &second) == 0 && !second && f.context.live == 2);
    memset(ip_options, 0xdd, sizeof(ip_options)); memset(tcp_options, 0xcc, sizeof(tcp_options));
    memset(payloads, 0xbb, sizeof(payloads));

    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&f.worker, 1, &progress) == -EAGAIN && !progress.tx && !progress.rx);
    CHECK(f.tx.pending && f.context.live == 2);
    struct rte_mbuf *held[POOL_COUNT];
    unsigned int count = 0;
    while (count < POOL_COUNT && (held[count] = ker_packet_alloc(&f.pool))) ++count;
    CHECK(count > 16);
    CHECK(ker_worker_poll(&f.worker, 2, &progress) == -ENOMEM);
    CHECK(f.tx.pending && f.context.live == 2 && !f.received);
    for (unsigned int i = 0; i < 16; ++i) ker_packet_free(held[--count]);
    CHECK(ker_worker_poll(&f.worker, 3, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && f.received == 1 && f.context.live == 1);
    CHECK(ker_worker_poll(&f.worker, 4, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && f.received == 2 && f.context.live == 0);
    while (count) ker_packet_free(held[--count]);
    CHECK(rte_mempool_in_use_count(f.pool.mbufs) == 0);
    CHECK(ker_worker_cleanup(&f.worker) == 0);
    CHECK(ker_tx_export_cleanup(&f.tx) == 0);
    CHECK(ker_tx_ring_cleanup(&f.ring) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&f.pool, "tcp_ip_options", POOL_COUNT, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&f.context, &f.pool, "tcp_ip_options_skb") == 0);
    CHECK(ker_eth_device_init(&f.device, &f.context, "tcp-ip-options0", 61, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&f.runtime, &f.context) == 0);
    CHECK(ker_transport_receiver_register(&f.receiver, &f.runtime, &f.device,
        message_receive, &f) == 0);

    construct_and_validate();
    failures_and_recovery();
    worker_chain_roundtrip();
    CHECK(f.received == 2 && f.context.live == 0);
    CHECK(ker_transport_receiver_unregister(&f.receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&f.runtime) == 0);
    CHECK(ker_eth_device_cleanup(&f.device) == 0);
    CHECK(ker_skb_context_cleanup(&f.context) == 0);
    CHECK(ker_packet_pool_cleanup(&f.pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
