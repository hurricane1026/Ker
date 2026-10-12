#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/ipv4-packet-view.h"
#include "runtime/memory.h"
#include "runtime/receive.h"
#include "runtime/skb.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/udp-packet-view.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_SIZE 127U
struct fixture {
    struct ker_packet_pool pool;
    struct ker_skb_context context;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_tx_ring ring;
    struct ker_tx_export tx;
    struct ker_worker worker;
    const unsigned char *expected_options;
    unsigned int expected_options_length;
    const unsigned char *expected_payload;
    unsigned int expected_payload_length;
    bool sink_reject_once;
    unsigned int delivered;
};
static struct fixture f;
static const unsigned char source_mac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[6] = {2, 6, 7, 8, 9, 10};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;

static uint16_t oracle_complement(const unsigned char *bytes, size_t length)
{
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < length) {
        sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
        i += 2;
    }
    if (i < length) sum += (uint32_t)bytes[i] << 8;
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static void verify_wire(const struct sk_buff *skb, const unsigned char *options,
    unsigned int options_length, const unsigned char *payload, unsigned int payload_length)
{
    unsigned int ihl = 20 + options_length;
    unsigned int udp_length = 8 + payload_length;
    const unsigned char *frame = skb->data;
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(skb->len == ETH_HLEN + ihl + udp_length);
    CHECK(skb_headroom(skb) == 128 && skb->mac_header == skb_headroom(skb));
    CHECK(skb->network_header == skb_headroom(skb) + ETH_HLEN);
    CHECK(skb->transport_header == skb_headroom(skb) + ETH_HLEN + ihl);
    CHECK(!memcmp(frame, destination_mac, ETH_ALEN));
    CHECK(!memcmp(frame + ETH_ALEN, source_mac, ETH_ALEN));
    CHECK(frame[12] == 0x08 && frame[13] == 0x00);
    CHECK(ip[0] == (unsigned char)(0x40U | ihl / 4U) && ip[1] == 0);
    CHECK(ip[2] == (unsigned char)((ihl + udp_length) >> 8) &&
        ip[3] == (unsigned char)(ihl + udp_length));
    CHECK(ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
        ip[8] == 64 && ip[9] == 17);
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(oracle_complement(ip, ihl) == 0);
    if (options_length)
        CHECK(!memcmp(ip + 20, options, options_length));
    const unsigned char *udp = ip + ihl;
    CHECK(!memcmp(udp, &source_port, 2) && !memcmp(udp + 2, &destination_port, 2));
    CHECK(udp[4] == (unsigned char)(udp_length >> 8) && udp[5] == (unsigned char)udp_length);
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = 17;
    pseudo[10] = (unsigned char)(udp_length >> 8); pseudo[11] = (unsigned char)udp_length;
    unsigned char checksum_input[12 + 8 + 64];
    CHECK(payload_length <= 64);
    memcpy(checksum_input, pseudo, sizeof(pseudo));
    memcpy(checksum_input + sizeof(pseudo), udp, udp_length);
    CHECK(oracle_complement(checksum_input, sizeof(pseudo) + udp_length) == 0);
    if (payload_length)
        CHECK(!memcmp(udp + 8, payload, payload_length));
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    struct fixture *fixture = arg;
    CHECK(arg == &f && fixture->worker.polling && !fixture->worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_UDP);
    CHECK(message->ipv4.header_length == 20 + fixture->expected_options_length);
    CHECK(message->ipv4.packet_length == 20 + fixture->expected_options_length + 8 +
        fixture->expected_payload_length);
    CHECK(!memcmp(message->ipv4.header + 20, fixture->expected_options,
        fixture->expected_options_length));
    CHECK(message->packet.udp.source_port == source_port &&
        message->packet.udp.destination_port == destination_port);
    CHECK(message->packet.udp.payload_length == fixture->expected_payload_length);
    CHECK(!memcmp(message->packet.udp.payload, fixture->expected_payload,
        fixture->expected_payload_length));
    fixture->delivered++;
    return NET_RX_SUCCESS;
}

static int retry_sink(struct rte_mbuf *chain, void *arg)
{
    struct fixture *fixture = arg;
    if (fixture->sink_reject_once) {
        fixture->sink_reject_once = false;
        return -EAGAIN;
    }
    return ker_tx_ring_sink(chain, &fixture->ring);
}

static int tx_poll(void *arg, unsigned int budget)
{
    CHECK(arg == &f);
    return ker_tx_export_poll(&f.tx, budget);
}

static int rx_poll(void *arg, unsigned int budget)
{
    struct fixture *fixture = arg;
    CHECK(arg == &f && budget == 1);
    struct rte_mbuf *chain = (void *)(uintptr_t)1;
    int taken = ker_tx_ring_take(&fixture->ring, &chain);
    if (!taken) return 0;
    CHECK(taken == 1 && chain && chain != (void *)(uintptr_t)1);
    /* TX acceptance freed its original before the RX callback runs. */
    CHECK(fixture->context.live == 0);
    char *padding = rte_pktmbuf_append(chain, 4);
    CHECK(padding);
    memset(padding, 0xa5, 4);
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&fixture->device, chain, 128, &skb) == 0);
    ker_packet_free(chain);
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&fixture->runtime, &fixture->device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct sk_buff *create_options(const void *options, unsigned int options_length,
    const void *payload, unsigned int payload_length)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_udp_ipv4_create_ip_options(&f.context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, 64, options,
        options_length, payload, payload_length, &skb) == 0);
    CHECK(skb);
    return skb;
}

static void positive_wire_and_wrapper(void)
{
    unsigned char payloads[3][16] = {
        {0x10, 0x20, 0x30, 0x40, 0x50},
        {0xa1, 0xb2, 0xc3, 0xd4},
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
    };
    unsigned char opts4[4] = {1, 1, 0, 0};
    unsigned char opts40[40];
    memset(opts40, 1, sizeof(opts40)); /* opaque IPv4 NOP option bytes */
    struct sk_buff *plain = create_options(NULL, 0, payloads[0], sizeof(payloads[0]));
    struct sk_buff *legacy = NULL;
    CHECK(ker_udp_ipv4_create(&f.context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, 64,
        payloads[0], sizeof(payloads[0]), &legacy) == 0);
    CHECK(legacy && legacy->len == plain->len &&
        !memcmp(legacy->data, plain->data, plain->len) &&
        legacy->mac_header == plain->mac_header &&
        legacy->network_header == plain->network_header &&
        legacy->transport_header == plain->transport_header);
    verify_wire(plain, NULL, 0, payloads[0], sizeof(payloads[0]));
    CHECK(ker_skb_free(legacy) == 0 && ker_skb_free(plain) == 0);

    struct sk_buff *empty = create_options(NULL, 0, NULL, 0);
    verify_wire(empty, NULL, 0, NULL, 0);
    CHECK(ker_skb_free(empty) == 0);

    struct sk_buff *four = create_options(opts4, sizeof(opts4), payloads[1], sizeof(payloads[1]));
    verify_wire(four, opts4, sizeof(opts4), payloads[1], sizeof(payloads[1]));
    CHECK(!memcmp(opts4, (unsigned char[]){1, 1, 0, 0}, sizeof(opts4)));
    CHECK(ker_skb_free(four) == 0);

    unsigned char opts_snapshot[sizeof(opts40)];
    unsigned char payload_snapshot[sizeof(payloads[2])];
    memcpy(opts_snapshot, opts40, sizeof(opts40));
    memcpy(payload_snapshot, payloads[2], sizeof(payloads[2]));
    struct sk_buff *forty = create_options(opts40, sizeof(opts40),
        payloads[2], sizeof(payloads[2]));
    CHECK(!memcmp(opts40, opts_snapshot, sizeof(opts40)) &&
        !memcmp(payloads[2], payload_snapshot, sizeof(payloads[2])));
    memset(opts40, 0xee, sizeof(opts40));
    memset(payloads[2], 0xdd, sizeof(payloads[2]));
    verify_wire(forty, opts_snapshot, sizeof(opts_snapshot),
        payload_snapshot, sizeof(payload_snapshot));
    CHECK(ker_skb_free(forty) == 0);
}

struct foreign_call { struct sk_buff *out; int result; };
static void *foreign_owner(void *arg)
{
    struct foreign_call *call = arg;
    const unsigned char opts[4] = {1, 1, 0, 0};
    call->result = ker_udp_ipv4_create_ip_options(&f.context, source_mac,
        destination_mac, source_ip, destination_ip, source_port, destination_port,
        64, opts, sizeof(opts), NULL, 0, &call->out);
    return NULL;
}

static void transactional_failures(void)
{
    unsigned char options[40] = {1};
    unsigned char payload[4] = {1, 2, 3, 4};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
#define REJECT(rc, opts, optlen, data, datalen, ttl) do { \
    CHECK(ker_udp_ipv4_create_ip_options(&f.context, source_mac, destination_mac, \
        source_ip, destination_ip, source_port, destination_port, ttl, opts, optlen, \
        data, datalen, &sentinel) == (rc)); \
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && f.context.live == 0); \
} while (0)
    REJECT(-EINVAL, NULL, 4, payload, sizeof(payload), 64);
    REJECT(-EINVAL, options, 3, payload, sizeof(payload), 64);
    REJECT(-EINVAL, options, 44, payload, sizeof(payload), 64);
    REJECT(-EINVAL, options, UINT_MAX, payload, sizeof(payload), 64);
    REJECT(-EINVAL, NULL, 0, payload, sizeof(payload), 0);
    REJECT(-EINVAL, options, 4, NULL, 1, 64);
    unsigned int max_payload = UINT16_MAX - 20U - 40U - 8U;
    REJECT(-EMSGSIZE, options, 40, payload, max_payload + 1, 64);
    REJECT(-EMSGSIZE, options, 40, payload, UINT_MAX, 64);
    /* Protocol-valid size exceeds this fixed backing's linear capacity. */
    REJECT(-ENOSPC, options, 40, payload, max_payload, 64);
    pthread_t thread;
    struct foreign_call foreign = {.out = sentinel};
    CHECK(pthread_create(&thread, NULL, foreign_owner, &foreign) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && foreign.result == -EXDEV && foreign.out == sentinel);

    ker_memory_fail_after(0);
    REJECT(-ENOMEM, options, 4, payload, sizeof(payload), 64);
    ker_memory_fail_after(-1);
    struct sk_buff *retry = create_options(options, 4, payload, sizeof(payload));
    CHECK(retry && f.context.live == 1);
    CHECK(ker_skb_free(retry) == 0 && f.context.live == 0);
#undef REJECT
}

static void worker_retry_roundtrip(void)
{
    unsigned char options[40];
    unsigned char payload[23];
    memset(options, 1, sizeof(options));
    for (unsigned int i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 17U + 9U);
    options[0] = options[1] = 1; /* opaque NOP bytes */
    unsigned char options_copy[sizeof(options)], payload_copy[sizeof(payload)];
    memcpy(options_copy, options, sizeof(options));
    memcpy(payload_copy, payload, sizeof(payload));
    f.expected_options = options_copy;
    f.expected_options_length = sizeof(options_copy);
    f.expected_payload = payload_copy;
    f.expected_payload_length = sizeof(payload_copy);

    CHECK(ker_tx_ring_init(&f.ring, "udp_opts_ring", 1, SOCKET_ID_ANY) == 0);
    f.sink_reject_once = true;
    CHECK(ker_tx_export_init_chain(&f.tx, &f.context, 2, SIZE_MAX, 13,
        retry_sink, &f) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = tx_poll, .rx = rx_poll, .arg = &f};
    CHECK(ker_worker_init(&f.worker, &f.pool, &config, &ops) == 0);

    struct sk_buff *skb = create_options(options, sizeof(options), payload, sizeof(payload));
    CHECK(ker_tx_export_enqueue(&f.tx, &skb) == 0 && !skb);
    memset(options, 0xfa, sizeof(options));
    memset(payload, 0xfb, sizeof(payload));

    struct rte_mbuf *held[POOL_SIZE];
    unsigned int available_before = rte_mempool_avail_count(f.pool.mbufs);
    unsigned int count = 0;
    while (count < POOL_SIZE && (held[count] = ker_packet_alloc(&f.pool))) count++;
    CHECK(count == available_before && count >= 16);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&f.worker, 1, &progress) == -ENOMEM);
    CHECK(f.tx.pending && f.tx.last_error == -ENOMEM && f.context.live == 1);
    for (unsigned int i = 0; i < 16; ++i) ker_packet_free(held[--count]);
    CHECK(ker_worker_poll(&f.worker, 2, &progress) == -EAGAIN);
    CHECK(f.tx.pending && f.tx.last_error == -EAGAIN && f.context.live == 1 &&
        !f.delivered && rte_ring_empty(f.ring.ring));
    CHECK(ker_worker_poll(&f.worker, 3, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && f.delivered == 1 &&
        !f.tx.pending && !f.tx.packets && f.context.live == 0);
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
    CHECK(ker_packet_pool_init(&f.pool, "udp_ip_options", POOL_SIZE, 0,
        4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&f.context, &f.pool, "udp_ip_options_skb") == 0);
    CHECK(ker_eth_device_init(&f.device, &f.context, "udp-options", 22, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&f.runtime, &f.context) == 0);
    CHECK(ker_transport_receiver_register(&f.receiver, &f.runtime, &f.device,
        receive_message, &f) == 0);

    positive_wire_and_wrapper();
    transactional_failures();
    worker_retry_roundtrip();
    CHECK(f.delivered == 1 && f.context.live == 0);
    CHECK(ker_transport_receiver_unregister(&f.receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&f.runtime) == 0);
    CHECK(ker_eth_device_cleanup(&f.device) == 0);
    CHECK(ker_skb_context_cleanup(&f.context) == 0);
    CHECK(ker_packet_pool_cleanup(&f.pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
