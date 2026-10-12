#include "check.h"
#include "eal.h"
#include "runtime/udp-neighbor-create.h"
#include "runtime/neighbor.h"
#include "runtime/ipv4-address.h"
#include "runtime/ethernet.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <linux/neighbour.h>
#include <errno.h>
#include <pthread.h>

#define PAYLOAD_MAX 32
#define FRAME_MAX (ETH_HLEN + 20 + 8 + PAYLOAD_MAX)
#define UDP_PROTOCOL 17U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static struct ker_tx_export tx;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct rte_mbuf *pending;
static struct rte_mbuf *accepted;
static int block_sink = 1;
static unsigned char expected_payload[PAYLOAD_MAX];
static unsigned int expected_length, delivered;
static unsigned char expected_ip_options[40];
static unsigned int expected_ip_options_length;
static const unsigned char source_mac[ETH_ALEN] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[ETH_ALEN] = {2, 6, 7, 8, 9, 10};
static __be32 source_ip, destination_ip;
static __be16 source_port, destination_port;
static void *foreign_create(void *arg);

static uint16_t oracle_sum(const unsigned char *p, unsigned int n)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < n; i += 2)
        sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

static uint16_t udp_oracle(const unsigned char *frame, unsigned int ihl,
    unsigned int payload_length)
{
    const unsigned char *ip = frame + ETH_HLEN;
    const unsigned char *udp = ip + ihl;
    unsigned int udp_length = 8 + payload_length;
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = UDP_PROTOCOL;
    pseudo[10] = (unsigned char)(udp_length >> 8); pseudo[11] = (unsigned char)udp_length;
    uint32_t sum = oracle_sum(pseudo, sizeof(pseudo)) + oracle_sum(udp, udp_length);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

static int tx_sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(arg == &tx && worker.polling && !worker.timers.polling);
    if (block_sink) { block_sink = 0; return -EAGAIN; }
    CHECK(!accepted && packet->ol_flags == 0);
    accepted = packet;
    return 0;
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_UDP);
    CHECK(message->ipv4.header_length == 20 + expected_ip_options_length);
    CHECK(message->ipv4.packet_length == 20 + expected_ip_options_length + 8 + expected_length);
    if (expected_ip_options_length)
        CHECK(!memcmp(message->ipv4.header + 20, expected_ip_options, expected_ip_options_length));
    CHECK(message->packet.udp.source_port == source_port &&
        message->packet.udp.destination_port == destination_port);
    CHECK(message->packet.udp.payload_length == expected_length);
    CHECK(!memcmp(message->packet.udp.payload, expected_payload, expected_length));
    ++delivered;
    return NET_RX_SUCCESS;
}

static struct rte_mbuf *split_chain(const struct rte_mbuf *source);

static int rx(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!accepted) return 0;
    CHECK(context.live == 0); /* Accepted TX copy released its original skb. */
    pending = split_chain(accepted);
    ker_packet_free(accepted); accepted = NULL;
    struct rte_mbuf *chain = pending; pending = NULL;
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, 128, &skb) == 0);
    ker_packet_free(chain); /* Release the multisegment source before dispatch. */
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == 0 && !skb);
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
    return 1;
}

static struct rte_mbuf *split_chain(const struct rte_mbuf *source)
{
    const unsigned char *bytes = rte_pktmbuf_mtod(source, const unsigned char *);
    unsigned int total = source->pkt_len;
    const unsigned int pattern[] = {13, 2, 5, 1, 7, 3, 11};
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0, index = 0;
    while (offset < total) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool); CHECK(segment);
        unsigned int length = pattern[index++ % (sizeof(pattern) / sizeof(pattern[0]))];
        if (length > total - offset) length = total - offset;
        unsigned char *data = (unsigned char *)rte_pktmbuf_append(segment, (uint16_t)length);
        CHECK(data);
        memcpy(data, bytes + offset, length);
        if (!head) head = segment;
        else CHECK(rte_pktmbuf_chain(head, segment) == 0);
        offset += length;
    }
    CHECK(head && head->nb_segs > 1 && head->pkt_len == total);
    return head;
}

static void verify_packet_options(struct sk_buff *skb, const unsigned char *options,
    unsigned int options_length, const unsigned char *payload, unsigned int length);

static void verify_packet(struct sk_buff *skb, const unsigned char *payload, unsigned int length)
{
    verify_packet_options(skb, NULL, 0, payload, length);
}

static void verify_packet_options(struct sk_buff *skb, const unsigned char *options,
    unsigned int options_length, const unsigned char *payload, unsigned int length)
{
    const unsigned char *frame = skb->data;
    unsigned int ihl = 20 + options_length;
    CHECK(skb->len == ETH_HLEN + ihl + 8 + length);
    CHECK(skb_headroom(skb) == 128 && skb->mac_header == skb_headroom(skb));
    CHECK(skb->network_header == skb_headroom(skb) + ETH_HLEN);
    CHECK(skb->transport_header == skb_headroom(skb) + ETH_HLEN + ihl);
    CHECK(!memcmp(frame, destination_mac, ETH_ALEN));
    CHECK(!memcmp(frame + 6, source_mac, ETH_ALEN));
    CHECK(frame[12] == 0x08 && frame[13] == 0x00);
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(ip[0] == (unsigned char)(0x40U | ihl / 4U) && ip[1] == 0 && ip[4] == 0 && ip[5] == 0);
    CHECK(ip[6] == 0 && ip[7] == 0 && ip[8] == 64 && ip[9] == UDP_PROTOCOL);
    CHECK(ip[2] == (unsigned char)((ihl + 8 + length) >> 8) && ip[3] == (unsigned char)(ihl + 8 + length));
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(oracle_sum(ip, ihl) == 0xffff);
    if (options_length) CHECK(!memcmp(ip + 20, options, options_length));
    const unsigned char *udp = ip + ihl;
    CHECK(!memcmp(udp, &source_port, 2) && !memcmp(udp + 2, &destination_port, 2));
    CHECK(udp[4] == (unsigned char)((8 + length) >> 8) && udp[5] == (unsigned char)(8 + length));
    CHECK(udp_oracle(frame, ihl, length) == 0xffff);
    if (length) CHECK(!memcmp(udp + 8, payload, length));
}

static void one_packet_ip_options(unsigned char *options, unsigned int options_length,
    unsigned char *payload, unsigned int length)
{
    unsigned char options_copy[40], payload_snapshot[PAYLOAD_MAX];
    if (options_length) memcpy(options_copy, options, options_length);
    if (length) memcpy(payload_snapshot, payload, length);
    if (options_length) memcpy(expected_ip_options, options_copy, options_length);
    expected_ip_options_length = options_length;
    memcpy(expected_payload, payload_snapshot, length); expected_length = length;
    struct neighbour *held = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &held) == 0);
    CHECK(refcount_read(&held->refcnt) == 2);
    struct sk_buff *skb = NULL;
    block_sink = 1;
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip,
        source_port, destination_port, 64, options, options_length, payload,
        length, &skb) == 0 && skb);
    CHECK(refcount_read(&held->refcnt) == 2);
    if (options_length) CHECK(!memcmp(options, options_copy, options_length));
    if (length) CHECK(!memcmp(payload, payload_snapshot, length));
    verify_packet_options(skb, options_copy, options_length, payload_snapshot, length);
    if (options_length) memset(options, 0xea, options_length);
    if (length) memset(payload, 0xeb, length);
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN);
    CHECK(tx.pending && context.live == 1);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && context.live == 0);
    CHECK(ker_neighbor_release(&table, held) == 0);
}

static void one_packet(unsigned char *payload, unsigned int length)
{
    unsigned char payload_snapshot[PAYLOAD_MAX];
    memcpy(payload_snapshot, payload, length);
    expected_ip_options_length = 0;
    memcpy(expected_payload, payload_snapshot, length); expected_length = length;
    struct sk_buff *skb = NULL;
    block_sink = 1;
    struct neighbour *held = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &held) == 0);
    CHECK(refcount_read(&held->refcnt) == 2);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port,
        64, payload, length, &skb) == 0);
    CHECK(refcount_read(&held->refcnt) == 2);
    CHECK(ker_neighbor_release(&table, held) == 0);
    CHECK(skb);
    CHECK(!memcmp(payload, payload_snapshot, length));
    verify_packet(skb, payload_snapshot, length);
    memset(payload, 0xee, length); /* Constructor copied bytes before returning. */
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN);
    CHECK(progress.tx == 0 && progress.rx == 0 && tx.pending && context.live == 1 && !accepted);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && !pending && !accepted && context.live == 0);
    CHECK(delivered > 0);
}

static void transactional_failures(void)
{
    unsigned char payload[4] = {1, 2, 3, 4};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
    struct neighbour *held_entry = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &held_entry) == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);
    unsigned char options[40];
    for (unsigned int i = 0; i < sizeof(options); ++i) options[i] = (unsigned char)(i * 7U + 3U);
    unsigned char options_copy[sizeof(options)]; memcpy(options_copy, options, sizeof(options));
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, NULL, 4, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 3, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, UINT_MAX, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 40, payload, UINT_MAX, &sentinel) == -EMSGSIZE);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 40, payload, UINT16_MAX - 20U - 40U - 8U,
        &sentinel) == -ENOSPC);
    const __be32 absent_options = rte_cpu_to_be_32(0xc6336403);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, absent_options, source_port,
        destination_port, 64, options, 4, payload, sizeof(payload), &sentinel) == -ENOENT);
    CHECK(refcount_read(&held_entry->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    held_entry->nud_state = NUD_STALE;
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 40, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    held_entry->nud_state = NUD_PERMANENT;
    CHECK(refcount_read(&held_entry->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    CHECK(!memcmp(options, options_copy, sizeof(options)) && context.live == 0);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 0, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, NULL, 1, &sentinel) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, payload, 65508, &sentinel) == -EMSGSIZE);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    unsigned char large[1900] = {0};
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, large, sizeof(large), &sentinel) == -ENOSPC);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);

    const __be32 absent = rte_cpu_to_be_32(0xc6336403);
    size_t free_before = rte_mempool_avail_count(pool.mbufs);
    CHECK(ker_udp_ipv4_create_neighbor(&table, absent, source_port, destination_port, 64,
        payload, sizeof(payload), &sentinel) == -ENOENT);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        rte_mempool_avail_count(pool.mbufs) == free_before);
    CHECK(refcount_read(&held_entry->refcnt) == 2);

    held_entry->nud_state = NUD_STALE;
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64,
        payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(refcount_read(&held_entry->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    held_entry->nud_state = NUD_PERMANENT;

    ker_memory_fail_after(0);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip,
        source_port, destination_port, 64, options, 40, payload, sizeof(payload),
        &sentinel) == -ENOMEM);
    CHECK(refcount_read(&held_entry->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port,
        64, payload, sizeof(payload), &sentinel) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);
    struct sk_buff *descriptor_retry = NULL;
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port,
        64, payload, sizeof(payload), &descriptor_retry) == 0);
    CHECK(descriptor_retry && ker_skb_free(descriptor_retry) == 0 && context.live == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);

    struct rte_mbuf *held[63];
    unsigned int n = 0;
    while (n < 63 && (held[n] = ker_packet_alloc(&pool))) ++n;
    CHECK(n == 63);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 40, payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        refcount_read(&held_entry->refcnt) == 2);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);
    ker_packet_free(held[--n]);
    struct sk_buff *retry = NULL;
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, payload, sizeof(payload), &retry) == 0);
    CHECK(retry && context.live == 1 && ker_skb_free(retry) == 0);
    CHECK(refcount_read(&held_entry->refcnt) == 2);
    while (n) ker_packet_free(held[--n]);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 63);

    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_create, &sentinel) == 0 && pthread_join(thread, NULL) == 0);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && refcount_read(&held_entry->refcnt) == 2);
    CHECK(ker_neighbor_release(&table, held_entry) == 0);
}

static void checksum_zero_mangling(void)
{
    unsigned char payload[2], frame[42 + 2] = {0};
    struct sk_buff *skb = NULL;
    bool found = false;
    for (unsigned int value = 0; value <= UINT16_MAX; ++value) {
        payload[0] = (unsigned char)(value >> 8); payload[1] = (unsigned char)value;
        /* Build only the independent oracle fields needed for a zero result. */
        unsigned char *ip = frame + ETH_HLEN, *udp = ip + 20;
        memcpy(ip + 12, &source_ip, 4); memcpy(ip + 16, &destination_ip, 4);
        memcpy(udp, &source_port, 2); memcpy(udp + 2, &destination_port, 2);
        udp[4] = 0; udp[5] = 10; udp[6] = udp[7] = 0;
        memcpy(udp + 8, payload, 2);
        unsigned char pseudo[12]; memcpy(pseudo, ip + 12, 8);
        pseudo[8] = 0; pseudo[9] = UDP_PROTOCOL; pseudo[10] = 0; pseudo[11] = 10;
        uint32_t sum = oracle_sum(pseudo, 12) + oracle_sum(udp, 10);
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        if ((uint16_t)~sum == 0) { found = true; break; }
    }
    CHECK(found);
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port, 64, payload, 2, &skb) == 0);
    CHECK(skb && skb->data[ETH_HLEN + 20 + 6] == 0xff && skb->data[ETH_HLEN + 20 + 7] == 0xff);
    CHECK(ker_skb_free(skb) == 0);
}

static void *foreign_create(void *arg)
{
    struct sk_buff **result = arg;
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port,
        64, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip,
        source_port, destination_port, 64, NULL, 0, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    return NULL;
}

int main(void)
{
    ker_test_eal_init();
    source_ip = rte_cpu_to_be_32(0xc0000201);
    destination_ip = rte_cpu_to_be_32(0xc6336402);
    source_port = rte_cpu_to_be_16(0x1234);
    destination_port = rte_cpu_to_be_16(0x5678);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "udp_create", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "udp_create_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "udp-neighbor0", 2, source_mac) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, source_ip, 24) == 0);
    CHECK(ker_neighbor_table_init(&table, &address, "udp_neighbor_records", 4, 2) == 0);
    CHECK(ker_neighbor_add(&table, destination_ip, destination_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_message, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    CHECK(ker_tx_export_init(&tx, &context, 2, SIZE_MAX, tx_sink, &tx) == 0);
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = rx, .arg = &tx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    unsigned char odd[5] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    unsigned char even[4] = {0xab, 0xcd, 0xef, 0x01};
    unsigned char ip4[4] = {1, 1, 0x94, 4}, ip40[40];
    for (unsigned int i = 0; i < sizeof(ip40); ++i) ip40[i] = (unsigned char)(i * 7U + 3U);
    one_packet(odd, sizeof(odd));
    one_packet(even, sizeof(even));
    one_packet(even, 0);
    one_packet_ip_options(NULL, 0, odd, sizeof(odd));
    one_packet_ip_options(ip4, sizeof(ip4), odd, sizeof(odd));
    one_packet_ip_options(ip40, sizeof(ip40), even, sizeof(even));
    checksum_zero_mangling();
    transactional_failures();

    CHECK(delivered == 6 && context.live == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_neighbor_remove(&table, destination_ip) == 0);
    CHECK(ker_neighbor_table_cleanup(&table) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("UDP packet construction, checksum and worker roundtrip passed");
    return 0;
}
