#include "check.h"
#include "eal.h"
#include "runtime/udp-neighbor-create.h"
#include "runtime/icmp-echo-neighbor-create.h"
#include "runtime/tcp-neighbor-create.h"
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
static enum ker_transport_protocol expected_protocol = KER_TRANSPORT_UDP;
static uint8_t expected_icmp_type;
static __be16 expected_icmp_id, expected_icmp_sequence;
static unsigned int rx_padding;
static bool expect_exact_icmp;
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

static void verify_profile_header(const struct sk_buff *skb,
    const struct ker_ipv4_header_fields *fields, uint8_t protocol,
    unsigned int ip_length)
{
    const unsigned char *ip = skb->data + ETH_HLEN;
    CHECK(ip[1] == fields->ds_field &&
        !memcmp(ip + 4, &fields->identification, 2) &&
        !memcmp(ip + 6, &fields->frag_off, 2));
    CHECK(ip[9] == protocol && (((unsigned int)ip[2] << 8) | ip[3]) == ip_length);
    CHECK(oracle_sum(ip, (ip[0] & 0x0fU) * 4U) == 0xffff);
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
    CHECK(message->protocol == expected_protocol);
    CHECK(message->ipv4.header_length == 20 + expected_ip_options_length);
    CHECK(message->ipv4.packet_length == 20 + expected_ip_options_length + 8 + expected_length);
    if (expected_ip_options_length)
        CHECK(!memcmp(message->ipv4.header + 20, expected_ip_options, expected_ip_options_length));
    if (expected_protocol == KER_TRANSPORT_ICMP_ECHO) {
        CHECK(message->packet.icmp_echo.type == expected_icmp_type && message->packet.icmp_echo.code == 0);
        CHECK(message->packet.icmp_echo.identifier == expected_icmp_id);
        CHECK(message->packet.icmp_echo.sequence == expected_icmp_sequence);
        CHECK(message->packet.icmp_echo.payload_length == expected_length);
        if (expected_length) CHECK(!memcmp(message->packet.icmp_echo.payload, expected_payload, expected_length));
    } else {
        CHECK(message->packet.udp.source_port == source_port &&
            message->packet.udp.destination_port == destination_port);
        CHECK(message->packet.udp.payload_length == expected_length);
        if (expected_length) CHECK(!memcmp(message->packet.udp.payload, expected_payload, expected_length));
    }
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
    if (expect_exact_icmp) {
        unsigned char checksum_bytes[2];
        CHECK(rte_pktmbuf_read(accepted, ETH_HLEN + 20 + 2, 2, checksum_bytes));
        CHECK(checksum_bytes[0] == 0 && checksum_bytes[1] == 0);
    }
    if (rx_padding) {
        unsigned char *pad = (unsigned char *)rte_pktmbuf_append(accepted, (uint16_t)rx_padding);
        CHECK(pad);
        memset(pad, 0, rx_padding);
    }
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
    unsigned int total = source->pkt_len;
    unsigned char packet_bytes[2048];
    CHECK(total <= sizeof(packet_bytes));
    const unsigned char *read = rte_pktmbuf_read(source, 0, (uint32_t)total, packet_bytes);
    CHECK(read);
    if (read != packet_bytes) memcpy(packet_bytes, read, total);
    const unsigned int pattern[] = {13, 2, 5, 1, 7, 3, 11};
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0, index = 0;
    while (offset < total) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool); CHECK(segment);
        unsigned int length = pattern[index++ % (sizeof(pattern) / sizeof(pattern[0]))];
        if (length > total - offset) length = total - offset;
        unsigned char *data = (unsigned char *)rte_pktmbuf_append(segment, (uint16_t)length);
        CHECK(data);
        memcpy(data, packet_bytes + offset, length);
        if (!head) head = segment;
        else CHECK(rte_pktmbuf_chain(head, segment) == 0);
        offset += length;
    }
    CHECK(head && head->nb_segs > 1 && head->pkt_len == total);
    unsigned int segments = 0, byte_count = 0;
    for (const struct rte_mbuf *seg = head; seg; seg = seg->next) {
        ++segments; byte_count += seg->data_len;
    }
    CHECK(segments == head->nb_segs && byte_count == head->pkt_len);
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

static void one_icmp_packet(unsigned char *options, unsigned int options_length,
    unsigned char *payload, unsigned int length, uint8_t type)
{
    unsigned char options_copy[40], payload_copy[PAYLOAD_MAX];
    if (options_length) memcpy(options_copy, options, options_length);
    if (length) memcpy(payload_copy, payload, length);
    if (options_length) memcpy(expected_ip_options, options_copy, options_length);
    expected_ip_options_length = options_length;
    if (length) memcpy(expected_payload, payload_copy, length);
    expected_length = length;
    expected_protocol = KER_TRANSPORT_ICMP_ECHO;
    expected_icmp_type = type;
    expected_icmp_id = rte_cpu_to_be_16(0x1234);
    expected_icmp_sequence = rte_cpu_to_be_16(0xabcd);
    struct neighbour *held = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &held) == 0);
    CHECK(refcount_read(&held->refcnt) == 2);
    struct sk_buff *skb = NULL;
    block_sink = 1;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip,
        expected_icmp_id, expected_icmp_sequence, type, 64,
        options_length ? options : NULL, options_length,
        length ? payload : NULL, length, &skb) == 0 && skb);
    CHECK(refcount_read(&held->refcnt) == 2);
    CHECK(!memcmp(skb->data, destination_mac, 6) && !memcmp(skb->data + 6, source_mac, 6));
    const unsigned char *ip = skb->data + ETH_HLEN;
    unsigned int ihl = 20 + options_length;
    CHECK(ip[0] == (unsigned char)(0x40U | ihl / 4U) && ip[9] == 1);
    CHECK(ip[2] == (unsigned char)((ihl + 8 + length) >> 8) && ip[3] == (unsigned char)(ihl + 8 + length));
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(oracle_sum(ip, ihl) == 0xffff);
    if (options_length) CHECK(!memcmp(ip + 20, options_copy, options_length));
    const unsigned char *icmp = ip + ihl;
    CHECK(icmp[0] == type && icmp[1] == 0);
    CHECK(!memcmp(icmp + 4, &expected_icmp_id, 2) && !memcmp(icmp + 6, &expected_icmp_sequence, 2));
    CHECK(oracle_sum(icmp, 8 + length) == 0xffff);
    if (length) CHECK(!memcmp(icmp + 8, payload_copy, length));
    if (options_length) memset(options, 0xd1, options_length);
    if (length) memset(payload, 0xd2, length);
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN);
    CHECK(tx.pending && context.live == 1 && !accepted);
    rx_padding = 9;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    rx_padding = 0;
    CHECK(progress.tx == 1 && progress.rx == 1 && context.live == 0);
    CHECK(ker_neighbor_release(&table, held) == 0);
    expected_protocol = KER_TRANSPORT_UDP;
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
    const __be32 absent_options = rte_cpu_to_be_32(0xc6336403);
    const struct ker_ipv4_header_fields valid_profile = {
        .ds_field = 0x2e, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = rte_cpu_to_be_16(0x4000)
    };
    const struct ker_ipv4_header_fields invalid_profile = {
        .ds_field = 0x5a, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = rte_cpu_to_be_16(0x2000)
    };
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, absent_options, source_port,
        destination_port, 64, &invalid_profile, options, 4, payload,
        sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, absent_options, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64,
        &invalid_profile, options, 4, options, 4, payload, sizeof(payload),
        &sentinel) == -ENOTSUP);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, absent_options,
        1, 2, 8, 64, &invalid_profile, options, 4, payload,
        sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 64, NULL, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64, NULL,
        NULL, 0, NULL, 0, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        1, 2, 8, 64, NULL, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, absent_options, source_port,
        destination_port, 64, &valid_profile, NULL, 0, payload,
        sizeof(payload), &sentinel) == -ENOENT);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, absent_options, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64, &valid_profile,
        NULL, 0, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOENT);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, absent_options,
        1, 2, 8, 64, &valid_profile, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ENOENT);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        rte_mempool_avail_count(pool.mbufs) == 63 && refcount_read(&held_entry->refcnt) == 2);
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
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, absent_options, source_port,
        destination_port, 64, options, 4, payload, sizeof(payload), &sentinel) == -ENOENT);
    CHECK(refcount_read(&held_entry->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    held_entry->nud_state = NUD_STALE;
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip, source_port,
        destination_port, 64, options, 40, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64, &valid_profile,
        options, 40, options, 40, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        1, 2, 8, 64, &valid_profile, options, 40, payload,
        sizeof(payload), &sentinel) == -ENOTSUP);
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
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 64, &valid_profile, options, 40, payload,
        sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64, &valid_profile,
        options, 40, options, 40, payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        1, 2, 8, 64, &valid_profile, options, 40, payload,
        sizeof(payload), &sentinel) == -ENOMEM);
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
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 64, &valid_profile, NULL, 0, payload, sizeof(payload),
        &descriptor_retry) == 0);
    CHECK(descriptor_retry && ker_skb_free(descriptor_retry) == 0);
    descriptor_retry = NULL;
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip, source_port,
        destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64, &valid_profile,
        NULL, 0, NULL, 0, payload, sizeof(payload), &descriptor_retry) == 0);
    CHECK(descriptor_retry && ker_skb_free(descriptor_retry) == 0);
    descriptor_retry = NULL;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        1, 2, 8, 64, &valid_profile, NULL, 0, payload, sizeof(payload),
        &descriptor_retry) == 0);
    CHECK(descriptor_retry && ker_skb_free(descriptor_retry) == 0);
    descriptor_retry = NULL;
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

static void icmp_neighbor_failures(void)
{
    unsigned char opts[40] = {0};
    unsigned char small[4] = {1, 2, 3, 4};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(NULL, destination_ip, 0, 0,
        8, 64, NULL, 0, NULL, 0, &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        4, 64, NULL, 0, NULL, 0, &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 0, NULL, 0, NULL, 0, &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, NULL, 4, small, sizeof(small), &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, UINT_MAX, small, sizeof(small), &sentinel) == -EINVAL);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, 40, small, UINT_MAX, &sentinel) == -EMSGSIZE);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    struct neighbour *held = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &held) == 0);
    CHECK(refcount_read(&held->refcnt) == 2);
    __be32 absent = rte_cpu_to_be_32(0xc6336403);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, absent, 0, 0,
        8, 64, NULL, 0, small, sizeof(small), &sentinel) == -ENOENT);
    held->nud_state = NUD_STALE;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, NULL, 0, small, sizeof(small), &sentinel) == -ENOTSUP);
    held->nud_state = NUD_PERMANENT;
    CHECK(refcount_read(&held->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    unsigned char *max_payload = malloc(65468);
    CHECK(max_payload);
    memset(max_payload, 0x6b, 65468);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, 40, max_payload, 65535 - 20 - 40 - 8, &sentinel) == -ENOSPC);
    CHECK(refcount_read(&held->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, 40, max_payload, 65535 - 20 - 40 - 8 + 1, &sentinel) == -EMSGSIZE);
    CHECK(refcount_read(&held->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    free(max_payload);
    ker_memory_fail_after(0);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, 40, small, sizeof(small), &sentinel) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(refcount_read(&held->refcnt) == 2 && context.live == 0);
    struct rte_mbuf *busy[63]; unsigned int n = 0;
    while (n < 63 && (busy[n] = ker_packet_alloc(&pool))) ++n;
    CHECK(n == 63);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        0, 64, opts, 40, small, sizeof(small), &sentinel) == -ENOMEM);
    CHECK(refcount_read(&held->refcnt) == 2 && sentinel == (void *)(uintptr_t)0x1234);
    ker_packet_free(busy[--n]);
    struct sk_buff *retry = NULL;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip, 0, 0,
        8, 64, opts, 40, small, sizeof(small), &retry) == 0);
    CHECK(retry && ker_skb_free(retry) == 0);
    while (n) ker_packet_free(busy[--n]);
    CHECK(context.live == 0 && refcount_read(&held->refcnt) == 2);
    CHECK(ker_neighbor_release(&table, held) == 0);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
}

static void exact_icmp_checksum_worker_roundtrip(void)
{
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_tx_export_init_chain_software_checksum_exact(&tx, &context, 2,
        SIZE_MAX, 1, tx_sink, &tx) == 0);
    unsigned char payload[5] = {0x51, 0x62, 0x73, 0x84, 0x95};
    unsigned char icmp[8 + sizeof(payload)] = {8, 0};
    bool found = false;
    __be16 id = 0;
    for (unsigned int candidate = 0; candidate <= UINT16_MAX; ++candidate) {
        memset(icmp, 0, 8);
        icmp[0] = 8;
        id = rte_cpu_to_be_16((uint16_t)candidate);
        memcpy(icmp + 4, &id, 2);
        memcpy(icmp + 8, payload, sizeof(payload));
        if (oracle_sum(icmp, sizeof(icmp)) == 0xffff) { found = true; break; }
    }
    CHECK(found);
    struct sk_buff *skb = NULL;
    expected_icmp_id = id;
    expected_icmp_sequence = 0;
    expected_icmp_type = 8;
    expected_protocol = KER_TRANSPORT_ICMP_ECHO;
    expected_ip_options_length = 0;
    expected_length = sizeof(payload);
    memcpy(expected_payload, payload, sizeof(payload));
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip,
        id, 0, 8, 64, NULL, 0, payload, sizeof(payload), &skb) == 0 && skb);
    CHECK(skb->data[ETH_HLEN + 20 + 2] == 0 && skb->data[ETH_HLEN + 20 + 3] == 0);
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = skb_headroom(skb) + ETH_HLEN + 20;
    skb->csum_offset = 2;
    expect_exact_icmp = true;
    block_sink = 1;
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == -EAGAIN);
    CHECK(tx.pending && context.live == 1 && !accepted);
    rx_padding = 9;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    rx_padding = 0;
    expect_exact_icmp = false;
    CHECK(progress.tx == 1 && progress.rx == 1 && context.live == 0 && delivered == 9);
    expected_protocol = KER_TRANSPORT_UDP;
}

static void *foreign_create(void *arg)
{
    struct sk_buff **result = arg;
    const struct ker_ipv4_header_fields fields = {
        .ds_field = 0x2e, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = rte_cpu_to_be_16(0x4000)
    };
    CHECK(ker_udp_ipv4_create_neighbor(&table, destination_ip, source_port, destination_port,
        64, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip,
        0, 0, 8, 64, NULL, 0, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor_ip_options(&table, destination_ip,
        source_port, destination_port, 64, NULL, 0, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, destination_ip,
        source_port, destination_port, 64, &fields, NULL, 0, NULL, 0,
        result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip,
        source_port, destination_port, 1, 2, rte_cpu_to_be_16(64), 0x18, 64,
        &fields, NULL, 0, NULL, 0, NULL, 0, result) == -EXDEV);
    CHECK(*result == (void *)(uintptr_t)0x1234);
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        1, 2, 8, 64, &fields, NULL, 0, NULL, 0, result) == -EXDEV);
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
    unsigned char profile_ip_options[40], profile_tcp_options[40];
    for (unsigned int i = 0; i < 40; ++i) {
        profile_ip_options[i] = (unsigned char)(0x31U + i * 7U);
        profile_tcp_options[i] = (unsigned char)(0x52U + i * 9U);
    }
    const struct ker_ipv4_header_fields field_profile = {
        .ds_field = 0x2e, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = rte_cpu_to_be_16(0x4000)
    };
    unsigned char profile_payload[2] = {0x34, 0x56};
    struct neighbour *profile_entry = NULL;
    CHECK(ker_neighbor_lookup(&table, destination_ip, &profile_entry) == 0);
    CHECK(refcount_read(&profile_entry->refcnt) == 2);
    struct sk_buff *profile_probe = NULL;
    CHECK(ker_udp_ipv4_create_neighbor_fields(&table, destination_ip,
        source_port, destination_port, 64, &field_profile, profile_ip_options, 40,
        profile_payload, sizeof(profile_payload), &profile_probe) == 0);
    verify_profile_header(profile_probe, &field_profile, UDP_PROTOCOL,
        20 + 40 + 8 + sizeof(profile_payload));
    CHECK(udp_oracle(profile_probe->data, 60, sizeof(profile_payload)) == 0xffff);
    CHECK(!memcmp(profile_probe->data + ETH_HLEN + 20, profile_ip_options, 40));
    CHECK(refcount_read(&profile_entry->refcnt) == 2);
    CHECK(profile_probe && ker_skb_free(profile_probe) == 0);
    profile_probe = NULL;
    CHECK(ker_tcp_ipv4_create_neighbor_fields(&table, destination_ip,
        source_port, destination_port, 1, 2, rte_cpu_to_be_16(128), 0x18, 64,
        &field_profile, profile_ip_options, 40, profile_tcp_options, 40, profile_payload,
        sizeof(profile_payload), &profile_probe) == 0);
    verify_profile_header(profile_probe, &field_profile, IPPROTO_TCP,
        20 + 40 + 20 + 40 + sizeof(profile_payload));
    CHECK(!memcmp(profile_probe->data + ETH_HLEN + 20, profile_ip_options, 40));
    {
        const unsigned char *ip = profile_probe->data + ETH_HLEN;
        const unsigned char *tcp = ip + 60;
        unsigned char pseudo[12];
        memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
        pseudo[10] = 0; pseudo[11] = (unsigned char)(60 + sizeof(profile_payload));
        uint32_t sum = oracle_sum(pseudo, sizeof(pseudo)) + oracle_sum(tcp, 60 + sizeof(profile_payload));
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        CHECK(sum == 0xffff);
        CHECK(tcp[12] >> 4 == 15 && !memcmp(tcp + 20, profile_tcp_options, 40));
    }
    CHECK(refcount_read(&profile_entry->refcnt) == 2);
    CHECK(profile_probe && ker_skb_free(profile_probe) == 0);
    profile_probe = NULL;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_fields(&table, destination_ip,
        rte_cpu_to_be_16(1), rte_cpu_to_be_16(2), 8, 64, &field_profile,
        profile_ip_options, 40, profile_payload, sizeof(profile_payload), &profile_probe) == 0);
    verify_profile_header(profile_probe, &field_profile, IPPROTO_ICMP,
        20 + 40 + 8 + sizeof(profile_payload));
    CHECK(!memcmp(profile_probe->data + ETH_HLEN + 20, profile_ip_options, 40));
    CHECK(oracle_sum(profile_probe->data + ETH_HLEN + 60,
        8 + sizeof(profile_payload)) == 0xffff);
    CHECK(refcount_read(&profile_entry->refcnt) == 2);
    CHECK(profile_probe && ker_skb_free(profile_probe) == 0);
    CHECK(ker_neighbor_release(&table, profile_entry) == 0);
    struct sk_buff *icmp_baseline = NULL;
    CHECK(ker_icmp_echo_ipv4_create_neighbor_ip_options(&table, destination_ip,
        rte_cpu_to_be_16(1), rte_cpu_to_be_16(2), 8, 64, NULL, 0, NULL, 0,
        &icmp_baseline) == 0);
    CHECK(icmp_baseline && ker_skb_free(icmp_baseline) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_message, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1, .rx_budget = 1};
    CHECK(ker_tx_export_init_chain_software_checksum_exact(&tx, &context, 2,
        SIZE_MAX, 1, tx_sink, &tx) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
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
    unsigned char echo_payload[5] = {1, 2, 3, 4, 5};
    unsigned char echo_options[40];
    for (unsigned int i = 0; i < sizeof(echo_options); ++i) echo_options[i] = (unsigned char)(i * 9U + 1U);
    one_icmp_packet(NULL, 0, echo_payload, sizeof(echo_payload), 8);
    one_icmp_packet(echo_options, sizeof(echo_options), even, sizeof(even), 0);
    checksum_zero_mangling();
    transactional_failures();
    icmp_neighbor_failures();
    exact_icmp_checksum_worker_roundtrip();

    CHECK(delivered == 9 && context.live == 0);
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
    puts("UDP/ICMP neighbor packet construction, checksum and worker roundtrip passed");
    return 0;
}
