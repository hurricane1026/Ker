#include "check.h"
#include "eal.h"
#include "runtime/buffer.h"
#include "runtime/ethernet.h"
#include "runtime/icmp-echo-create.h"
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
#include <net/checksum.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_lcore.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define COUNT 192U
#define POOL_SIZE 127U
#define PAYLOAD_MAX 32U
struct record {
    uint8_t protocol;
    unsigned int length, ip_options_length, tcp_options_length;
    uint8_t ip_options[8], tcp_options[8], payload[PAYLOAD_MAX];
};
struct fixture {
    struct ker_tx_ring ring;
    struct ker_rx_ring rx;
    struct ker_packet_pool producer_pool, consumer_pool;
    struct ker_skb_context producer_context, consumer_context;
    struct ker_tx_export tx;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_worker worker;
    struct record expected[COUNT];
    atomic_bool consumer_ready, consumer_start, producer_done, consumer_cleaned, producer_cleaned;
    atomic_uint received;
    unsigned int consumer_lcore;
    int consumer_result;
};
static struct fixture f;
static const uint8_t source_mac[ETH_ALEN] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const uint8_t destination_mac[ETH_ALEN] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;

static uint64_t deadline_after_seconds(unsigned int seconds)
{
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec +
        (uint64_t)seconds * UINT64_C(1000000000);
}

static void check_before_deadline(uint64_t deadline)
{
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    uint64_t now = (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
    CHECK(now < deadline);
}

static uint16_t checksum(const uint8_t *bytes, size_t length)
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

/* Independent wire-byte oracle executed by producer A before ring enqueue. */
static int checksum_ring_sink(struct rte_mbuf *chain, void *arg)
{
    struct ker_tx_ring *ring = arg;
    uint8_t frame[128];
    CHECK(chain && chain->pkt_len <= sizeof(frame) && chain->nb_segs > 1);
    size_t copied = 0;
    unsigned int segments = 0;
    for (struct rte_mbuf *part = chain; part; part = part->next) {
        CHECK(part->ol_flags == 0 && copied + part->data_len <= sizeof(frame));
        memcpy(frame + copied, rte_pktmbuf_mtod(part, const void *), part->data_len);
        copied += part->data_len;
        segments++;
    }
    CHECK(copied == chain->pkt_len && segments == chain->nb_segs);
    CHECK(copied >= ETH_HLEN + 20 && frame[12] == 0x08 && frame[13] == 0x00);
    uint8_t *ip = frame + ETH_HLEN;
    size_t ihl = (size_t)(ip[0] & 0x0fU) * 4;
    CHECK((ip[0] >> 4) == 4 && ihl >= 20 && ihl <= 60);
    size_t ip_length = ((size_t)ip[2] << 8) | ip[3];
    CHECK(ip_length >= ihl && ETH_HLEN + ip_length == copied);
    CHECK(checksum(ip, ihl) == 0);
    uint8_t protocol = ip[9];
    CHECK(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP);
    size_t l4_length = ip_length - ihl;
    if (protocol == IPPROTO_ICMP) {
        CHECK(l4_length >= 8 && ip[ihl] == 8 && ip[ihl + 1] == 0);
        CHECK(checksum(ip + ihl, l4_length) == 0);
    } else {
        uint8_t pseudo[12];
        memcpy(pseudo, ip + 12, 8);
        pseudo[8] = 0;
        pseudo[9] = protocol;
        pseudo[10] = (uint8_t)(l4_length >> 8);
        pseudo[11] = (uint8_t)l4_length;
        uint8_t checksum_input[112];
        CHECK(sizeof(pseudo) + l4_length <= sizeof(checksum_input));
        memcpy(checksum_input, pseudo, sizeof(pseudo));
        memcpy(checksum_input + sizeof(pseudo), ip + ihl, l4_length);
        CHECK(checksum(checksum_input, sizeof(pseudo) + l4_length) == 0);
    }
    return ker_tx_ring_sink(chain, ring);
}

static struct sk_buff *make_packet(unsigned int index)
{
    const struct record *record = &f.expected[index];
    struct sk_buff *skb = NULL;
    if (record->protocol == IPPROTO_TCP) {
        CHECK(ker_tcp_ipv4_create_headers(&f.producer_context, source_mac, destination_mac,
            source_ip, destination_ip, source_port, destination_port,
            (__be32)(UINT32_C(0x10000000) + index), (__be32)0,
            (__be16)2048, 0x18, 63, record->ip_options,
            record->ip_options_length, record->tcp_options,
            record->tcp_options_length, record->payload, record->length, &skb) == 0);
        unsigned int start = ETH_HLEN + 20 + record->ip_options_length;
        unsigned int l4_length = skb->len - start;
        __wsum pseudo = csum_tcpudp_nofold(source_ip, destination_ip, l4_length,
            IPPROTO_TCP, 0);
        __sum16 seed = (__sum16)~csum_fold(pseudo);
        memcpy(skb->data + start + 16, &seed, sizeof(seed));
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
        skb->csum_offset = 16;
    } else if (record->protocol == IPPROTO_ICMP) {
        CHECK(ker_icmp_echo_ipv4_create_ip_options(&f.producer_context, source_mac,
            destination_mac, source_ip, destination_ip, rte_cpu_to_be_16((uint16_t)(0x1000U + index)),
            rte_cpu_to_be_16((uint16_t)index), 8, 61, record->ip_options, record->ip_options_length,
            record->payload, record->length, &skb) == 0);
        unsigned int start = ETH_HLEN + 20 + record->ip_options_length;
        const __be16 zero = 0;
        memcpy(skb->data + start + 2, &zero, sizeof(zero));
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
        skb->csum_offset = 2;
    } else {
        CHECK(ker_udp_ipv4_create_ip_options(&f.producer_context, source_mac,
            destination_mac, source_ip, destination_ip, source_port,
            destination_port, 61, record->ip_options,
            record->ip_options_length, record->payload, record->length, &skb) == 0);
    }
    return skb;
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &f && rte_lcore_id() == f.consumer_lcore);
    unsigned int index = atomic_load_explicit(&f.received, memory_order_relaxed);
    CHECK(index < COUNT);
    const struct record *record = &f.expected[index];
    CHECK(message->protocol == (record->protocol == IPPROTO_TCP ? KER_TRANSPORT_TCP :
        record->protocol == IPPROTO_ICMP ? KER_TRANSPORT_ICMP_ECHO : KER_TRANSPORT_UDP));
    CHECK(message->ipv4.header_length == 20 + record->ip_options_length);
    if (record->ip_options_length)
        CHECK(!memcmp(message->ipv4.header + 20, record->ip_options,
            record->ip_options_length));
    const uint8_t *payload;
    size_t length;
    if (record->protocol == IPPROTO_TCP) {
        CHECK(message->packet.tcp.tcp_header_length == 20 + record->tcp_options_length);
        if (record->tcp_options_length)
            CHECK(!memcmp(message->packet.tcp.header + 20, record->tcp_options,
                record->tcp_options_length));
        CHECK(message->packet.tcp.source_port == source_port &&
            message->packet.tcp.destination_port == destination_port);
        payload = message->packet.tcp.payload;
        length = message->packet.tcp.payload_length;
    } else if (record->protocol == IPPROTO_ICMP) {
        CHECK(message->packet.icmp_echo.type == 8 && message->packet.icmp_echo.code == 0 &&
            message->packet.icmp_echo.identifier == rte_cpu_to_be_16((uint16_t)(0x1000U + index)) &&
            message->packet.icmp_echo.sequence == rte_cpu_to_be_16((uint16_t)index));
        payload = message->packet.icmp_echo.payload;
        length = message->packet.icmp_echo.payload_length;
    } else {
        CHECK(message->packet.udp.source_port == source_port &&
            message->packet.udp.destination_port == destination_port);
        payload = message->packet.udp.payload;
        length = message->packet.udp.payload_length;
    }
    CHECK(length == record->length && !memcmp(payload, record->payload, length));
    atomic_store_explicit(&f.received, index + 1, memory_order_release);
    return NET_RX_SUCCESS;
}

static int worker_rx(void *arg, unsigned int budget)
{
    return ker_rx_ring_poll(arg, budget);
}

static void *consumer_main(void *arg)
{
    struct fixture *fixture = arg;
    CHECK(rte_thread_register() == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    static const uint8_t mac[ETH_ALEN] = {2, 0x30, 0, 0, 0, 1};
    CHECK(ker_packet_pool_init(&fixture->consumer_pool, "concurrent_ring_b_pool",
        POOL_SIZE, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&fixture->consumer_context, &fixture->consumer_pool,
        "concurrent_ring_b_skb") == 0);
    CHECK(ker_eth_device_init(&fixture->device, &fixture->consumer_context,
        "concurrent-b", 19, mac) == 0);
    CHECK(ker_receive_runtime_init(&fixture->runtime, &fixture->consumer_context) == 0);
    CHECK(ker_rx_ring_init(&fixture->rx, &fixture->ring, &fixture->device,
        &fixture->runtime, 128) == 0);
    CHECK(ker_transport_receiver_register(&fixture->receiver, &fixture->runtime,
        &fixture->device, receive_message, fixture) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 8,
        .rx_margin = 0};
    struct ker_worker_ops ops = {.rx = worker_rx, .arg = &fixture->rx};
    CHECK(ker_worker_init(&fixture->worker, &fixture->consumer_pool, &config, &ops) == 0);
    fixture->consumer_lcore = rte_lcore_id();
    atomic_store_explicit(&fixture->consumer_ready, true, memory_order_release);

    uint64_t deadline = deadline_after_seconds(15);
    while (!atomic_load_explicit(&fixture->consumer_start, memory_order_acquire)) {
        check_before_deadline(deadline);
        sched_yield();
    }
    int64_t now = 1;
    while (!atomic_load_explicit(&fixture->producer_done, memory_order_acquire) ||
        atomic_load_explicit(&fixture->received, memory_order_acquire) < COUNT) {
        check_before_deadline(deadline);
        struct ker_worker_result progress = {0};
        int rc = ker_worker_poll(&fixture->worker, now++, &progress);
        CHECK(rc == 0);
        sched_yield();
    }
    CHECK(rte_ring_empty(fixture->ring.ring) && !fixture->rx.pending &&
        fixture->rx.last_dropped == 0 && fixture->rx.last_error == 0);
    fixture->consumer_result = (int)atomic_load_explicit(&fixture->received,
        memory_order_acquire);

    CHECK(ker_rx_ring_cleanup(&fixture->rx) == 0);
    CHECK(ker_worker_cleanup(&fixture->worker) == 0);
    CHECK(ker_transport_receiver_unregister(&fixture->receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&fixture->runtime) == 0);
    CHECK(ker_eth_device_cleanup(&fixture->device) == 0);
    CHECK(ker_skb_context_cleanup(&fixture->consumer_context) == 0);
    CHECK(ker_packet_pool_cleanup(&fixture->consumer_pool) == 0);
    atomic_store_explicit(&fixture->consumer_cleaned, true, memory_order_release);
    while (!atomic_load_explicit(&fixture->producer_cleaned, memory_order_acquire)) {
        check_before_deadline(deadline);
        sched_yield();
    }
    CHECK(ker_memory_shutdown() == 0);
    rte_thread_unregister();
    return NULL;
}

static void fill_records(void)
{
    for (unsigned int i = 0; i < COUNT; ++i) {
        struct record *record = &f.expected[i];
        record->protocol = (i % 3U == 0) ? IPPROTO_UDP :
            (i % 3U == 1) ? IPPROTO_TCP : IPPROTO_ICMP;
        record->length = 11U + (i % 20U);
        record->ip_options_length = (i % 3U) * 4U;
        record->tcp_options_length = record->protocol == IPPROTO_TCP ? ((i / 3U) % 3U) * 4U : 0;
        for (unsigned int j = 0; j < record->ip_options_length; ++j)
            record->ip_options[j] = (uint8_t)(i * 11U + j * 7U + 1U);
        for (unsigned int j = 0; j < record->tcp_options_length; ++j)
            record->tcp_options[j] = (uint8_t)(i * 13U + j * 5U + 2U);
        for (unsigned int j = 0; j < record->length; ++j)
            record->payload[j] = (uint8_t)(i * 37U + j * 19U + 3U);
        record->payload[0] = (uint8_t)(i >> 8);
        record->payload[1] = (uint8_t)i;
    }
}

static void wait_for_consumer(uint64_t deadline)
{
    while (!atomic_load_explicit(&f.consumer_ready, memory_order_acquire)) {
        check_before_deadline(deadline);
        sched_yield();
    }
}

static void retry_export_until_accepted(uint64_t deadline)
{
    while (f.tx.packets) {
        int rc = ker_tx_export_poll(&f.tx, 1);
        CHECK(rc == 1 || rc == -EAGAIN);
        if (rc == -EAGAIN) sched_yield();
        check_before_deadline(deadline);
    }
}

int main(void)
{
    fill_records();
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&f.producer_pool, "concurrent_ring_a_pool",
        POOL_SIZE, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&f.producer_context, &f.producer_pool,
        "concurrent_ring_a_skb") == 0);
    CHECK(ker_tx_ring_init(&f.ring, "ker_cwring1", 1,
        SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init_chain_software_checksum_exact(&f.tx, &f.producer_context,
        4, 65536, 16, checksum_ring_sink, &f.ring) == 0);

    pthread_t consumer;
    CHECK(pthread_create(&consumer, NULL, consumer_main, &f) == 0);
    uint64_t deadline = deadline_after_seconds(15);
    wait_for_consumer(deadline);
    CHECK(f.consumer_lcore != f.ring.owner_lcore && f.ring.consumers == 1);

    /* Hold B before polling so a capacity-one exact ring deterministically
     * rejects the next exporter copy and retains its original skb. */
    struct sk_buff *first = make_packet(0);
    CHECK(ker_tx_export_enqueue(&f.tx, &first) == 0 && !first);
    CHECK(ker_tx_export_poll(&f.tx, 1) == 1 && rte_ring_count(f.ring.ring) == 1);
    struct sk_buff *second = make_packet(1);
    struct sk_buff *retained = second;
    CHECK(ker_tx_export_enqueue(&f.tx, &second) == 0 && !second);
    CHECK(retained && ker_tx_export_poll(&f.tx, 1) == -EAGAIN);
    CHECK(f.tx.last_error == -EAGAIN && f.tx.pending == retained && f.tx.packets == 1);
    unsigned int retained_ihl = (retained->data[ETH_HLEN] & 0x0fU) * 4U;
    unsigned int retained_thl = (retained->data[ETH_HLEN + retained_ihl + 12] >> 4) * 4U;
    CHECK(retained->len == ETH_HLEN + retained_ihl + retained_thl + f.expected[1].length &&
        !memcmp(retained->data + ETH_HLEN + retained_ihl + retained_thl,
            f.expected[1].payload, f.expected[1].length));
    CHECK(ker_packet_pool_cleanup(&f.producer_pool) == -EBUSY);
    atomic_store_explicit(&f.consumer_start, true, memory_order_release);

    for (unsigned int i = 2; i < COUNT; ++i) {
        struct sk_buff *skb = make_packet(i);
        int enqueued = ker_tx_export_enqueue(&f.tx, &skb);
        while (enqueued == -ENOSPC) {
            CHECK(skb != NULL);
            int rc = ker_tx_export_poll(&f.tx, 1);
            CHECK(rc == 1 || rc == -EAGAIN);
            if (rc == -EAGAIN) sched_yield();
            check_before_deadline(deadline);
            enqueued = ker_tx_export_enqueue(&f.tx, &skb);
        }
        CHECK(enqueued == 0 && !skb);
        (void)ker_tx_export_poll(&f.tx, 1);
        CHECK(f.tx.last_error == 0 || f.tx.last_error == -EAGAIN);
        check_before_deadline(deadline);
    }
    retry_export_until_accepted(deadline);
    atomic_store_explicit(&f.producer_done, true, memory_order_release);

    while (!atomic_load_explicit(&f.consumer_cleaned, memory_order_acquire)) {
        check_before_deadline(deadline);
        sched_yield();
    }
    CHECK(f.consumer_result == (int)COUNT &&
        atomic_load_explicit(&f.received, memory_order_acquire) == COUNT);
    CHECK(rte_ring_empty(f.ring.ring) && !f.tx.pending && f.tx.packets == 0);
    CHECK(ker_tx_export_cleanup(&f.tx) == 0);
    CHECK(ker_skb_context_cleanup(&f.producer_context) == 0);
    CHECK(ker_packet_pool_cleanup(&f.producer_pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    atomic_store_explicit(&f.producer_cleaned, true, memory_order_release);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(ker_tx_ring_cleanup(&f.ring) == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
