#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-receive.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/rx-ring.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/worker.h"
#include "ker/linux_neighbor_update.h"
#include <errno.h>

#define POOL_SIZE 127U
#define MAX_RECORDS 8U
struct decoded_expectation {
    unsigned int operation;
    __be32 sender_ip, target_ip;
    const unsigned char *sender_mac, *target_mac;
    bool target_local, feedback;
    int feedback_result;
};

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device local_device, remote_device;
static struct ker_ipv4_address local_address, remote_address;
static struct ker_receive_runtime runtime;
static struct ker_arp_receiver receiver;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor monitor;
static struct ker_worker worker;
static struct ker_tx_ring ring;
static struct ker_rx_ring rx;
static struct ker_tx_export tx;
static const unsigned char local_mac[ETH_ALEN] = {2, 0x11, 0x12, 0x13, 0x14, 0x15};
static const unsigned char remote_mac[ETH_ALEN] = {2, 0x21, 0x22, 0x23, 0x24, 0x25};
static const unsigned char original_mac[ETH_ALEN] = {2, 0x31, 0x32, 0x33, 0x34, 0x35};
static const unsigned char broadcast_mac[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
static const unsigned char zero_mac[ETH_ALEN];
static __be32 local_ip, remote_ip, foreign_ip;
static unsigned char tx_expected[MAX_RECORDS][42];
static struct rte_mbuf *tx_accepted[MAX_RECORDS];
static unsigned int tx_expected_count, tx_accepted_count;
static struct decoded_expectation rx_expected[MAX_RECORDS];
static unsigned int rx_expected_count, rx_received;
static int feedback_result;
static unsigned int notifications;
static bool exhaust_during_rx;

static __be32 wire_ip(unsigned int host) { return rte_cpu_to_be_32(host); }

static void encode(unsigned char frame[42], unsigned int operation,
    __be32 source_ip, const unsigned char source_mac[ETH_ALEN],
    __be32 target_ip, const unsigned char destination_mac[ETH_ALEN],
    const unsigned char target_mac[ETH_ALEN])
{
    memset(frame, 0, 42);
    memcpy(frame, destination_mac, ETH_ALEN);
    memcpy(frame + ETH_ALEN, source_mac, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x06;
    frame[15] = ARPHRD_ETHER; frame[16] = 0x08;
    frame[18] = ETH_ALEN; frame[19] = 4;
    frame[21] = (unsigned char)operation;
    memcpy(frame + 22, source_mac, ETH_ALEN);
    memcpy(frame + 28, &source_ip, sizeof(source_ip));
    memcpy(frame + 32, target_mac, ETH_ALEN);
    memcpy(frame + 38, &target_ip, sizeof(target_ip));
}

static struct sk_buff *configured(struct ker_ipv4_address *source,
    unsigned int operation, __be32 target_ip,
    const unsigned char destination_mac[ETH_ALEN],
    const unsigned char target_mac[ETH_ALEN])
{
    struct sk_buff *skb = NULL;
    CHECK(ker_arp_create_configured(source, operation, target_ip,
        destination_mac, target_mac, &skb) == 0);
    CHECK(skb && skb->len == 42);
    return skb;
}

static void collect_chain(const struct rte_mbuf *chain, unsigned char bytes[42])
{
    CHECK(chain && chain->pkt_len == 42 && chain->nb_segs == 4);
    unsigned int offset = 0, count = 0;
    for (const struct rte_mbuf *part = chain; part; part = part->next) {
        CHECK(part->data_len && part->ol_flags == 0 &&
            offset + part->data_len <= 42 && rte_mbuf_refcnt_read(part) == 1);
        memcpy(bytes + offset, rte_pktmbuf_mtod(part, const void *), part->data_len);
        offset += part->data_len;
        ++count;
    }
    CHECK(offset == 42 && count == chain->nb_segs);
}

static int ring_sink(struct rte_mbuf *chain, void *arg)
{
    struct ker_tx_ring *target_ring = arg;
    CHECK(tx_accepted_count < tx_expected_count);
    unsigned char bytes[42];
    collect_chain(chain, bytes);
    CHECK(!memcmp(bytes, tx_expected[tx_accepted_count], sizeof(bytes)));
    int error = ker_tx_ring_sink(chain, target_ring);
    if (!error)
        tx_accepted[tx_accepted_count++] = chain;
    return error;
}

static int message(const struct ker_arp_message *m, void *arg)
{
    CHECK(arg == &receiver && rx_received < rx_expected_count);
    const struct decoded_expectation *expected = &rx_expected[rx_received++];
    CHECK(m->operation == expected->operation && m->sender_ip == expected->sender_ip &&
        m->target_ip == expected->target_ip && m->target_local == expected->target_local &&
        !memcmp(m->sender_mac, expected->sender_mac, ETH_ALEN) &&
        !memcmp(m->target_mac, expected->target_mac, ETH_ALEN));
    if (expected->feedback) {
        feedback_result = ker_arp_neighbor_feedback(&receiver, &monitor, m,
            NEIGH_UPDATE_F_OVERRIDE);
        CHECK(feedback_result == expected->feedback_result);
    }
    return NET_RX_SUCCESS;
}

static void notify(const struct ker_neighbor_event *event, void *arg)
{
    (void)arg;
    CHECK(event->ip == remote_ip);
    ++notifications;
}

static void probe(const struct ker_neighbor_event *event, void *arg)
{
    (void)event; (void)arg;
}

static int worker_tx(void *arg, unsigned int budget)
{
    (void)arg;
    return ker_tx_export_poll(&tx, budget);
}

static int worker_rx(void *arg, unsigned int budget)
{
    (void)arg;
    struct rte_mbuf *pressure = NULL;
    if (exhaust_during_rx) {
        pressure = ker_packet_alloc(&pool);
        CHECK(pressure && rte_mempool_avail_count(pool.mbufs) == 0);
    }
    int result = ker_rx_ring_poll(&rx, budget);
    if (pressure) ker_packet_free(pressure);
    exhaust_during_rx = false;
    return result;
}

static unsigned int neighbor_state(void)
{
    struct ker_neighbor_event event;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &event) == 0);
    return event.state;
}

static void poll_worker(struct ker_worker_result *result)
{
    memset(result, 0, sizeof(*result));
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, result) == 0);
}

static void add_rx_expect(unsigned int operation, __be32 sender,
    __be32 target, const unsigned char *source_mac,
    const unsigned char *target_mac, bool local, bool feedback, int result)
{
    CHECK(rx_expected_count < MAX_RECORDS);
    rx_expected[rx_expected_count++] = (struct decoded_expectation){
        .operation = operation, .sender_ip = sender, .target_ip = target,
        .sender_mac = source_mac, .target_mac = target_mac,
        .target_local = local, .feedback = feedback, .feedback_result = result
    };
}

static void add_tx_expected(unsigned int operation, __be32 source,
    const unsigned char *source_mac, __be32 target,
    const unsigned char *destination, const unsigned char *target_mac)
{
    CHECK(tx_expected_count < MAX_RECORDS);
    encode(tx_expected[tx_expected_count++], operation, source, source_mac,
        target, destination, target_mac);
}

static void expect_unchanged_after_bad_reply(struct sk_buff *skb,
    unsigned int operation, __be32 sender_ip, __be32 target_ip,
    const unsigned char *sender_mac, const unsigned char *target_mac,
    bool local, int expected_feedback)
{
    struct ker_neighbor_event before, after;
    unsigned long confirmed = monitor.entry->confirmed, updated = monitor.entry->updated;
    unsigned int refs = (unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned int old_notifications = notifications;
    int64_t deadline_before, deadline_after;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &before) == 0);
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_before) == 1);

    unsigned char expected[42];
    CHECK(skb->len == 42); memcpy(expected, skb->data, sizeof(expected));
    CHECK(tx_expected_count < MAX_RECORDS);
    memcpy(tx_expected[tx_expected_count++], expected, sizeof(expected));
    add_rx_expect(operation, sender_ip, target_ip, sender_mac, target_mac,
        local, true, expected_feedback);
    CHECK(ker_tx_export_enqueue(&tx, &skb) == 0 && !skb);
    struct ker_worker_result progress;
    poll_worker(&progress);
    CHECK(progress.tx == 1 && progress.rx == 1 && rx_received == rx_expected_count);
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &after) == 0);
    CHECK(before.state == after.state && before.probes == after.probes &&
        !memcmp(before.mac, after.mac, ETH_ALEN));
    CHECK(monitor.entry->confirmed == confirmed && monitor.entry->updated == updated &&
        (unsigned int)refcount_read(&monitor.entry->refcnt) == refs &&
        notifications == old_notifications && timer_pending(&monitor.entry->timer));
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_after) == 1 &&
        deadline_after == deadline_before);
}

static struct rte_mbuf *short_arp_chain(const unsigned char frame[42])
{
    struct rte_mbuf *head = NULL;
    struct rte_mbuf **next = &head;
    size_t offset = 0;
    const size_t length = 41;
    while (offset < length) {
        size_t amount = RTE_MIN((size_t)13, length - offset);
        struct rte_mbuf *part = ker_packet_alloc(&pool); CHECK(part);
        unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(part,
            (uint16_t)amount);
        CHECK(bytes); memcpy(bytes, frame + offset, amount);
        *next = part; next = &part->next; offset += amount;
    }
    head->pkt_len = (uint32_t)length;
    head->nb_segs = 4;
    return head;
}

static void local_worker_ring_tests(void)
{
    CHECK(ker_tx_ring_init(&ring, "arp_ring1", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init_chain(&tx, &context, 4, 8192, 13,
        ring_sink, &ring) == 0);
    struct ker_neighbor_config neighbor_config = {.retrans_ticks = 20,
        .reachable_ticks = 100, .delay_ticks = 30, .ucast_probes = 2,
        .mcast_reprobes = 1};
    CHECK(ker_neighbor_configure(&neighbors, &neighbor_config) == 0);
    CHECK(ker_neighbor_add(&neighbors, remote_ip, original_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &local_address,
        message, &receiver) == 0);
    CHECK(ker_rx_ring_init(&rx, &ring, &local_device, &runtime, 128) == 0);
    struct ker_worker_config worker_config = {.timer_budget = 1,
        .tx_budget = 2, .rx_budget = 1};
    struct ker_worker_ops worker_ops = {.tx = worker_tx, .rx = worker_rx};
    CHECK(ker_worker_init(&worker, &pool, &worker_config, &worker_ops) == 0);
    CHECK(ker_neighbor_monitor_init(&monitor, &neighbors, &worker.timers,
        remote_ip, probe, notify, NULL) == 0);
    while (neighbor_state() == NUD_REACHABLE) {
        int64_t deadline; struct ker_worker_result progress;
        CHECK(ker_runtime_next_deadline(&worker.timers, &deadline) == 1);
        CHECK(ker_worker_poll(&worker, deadline, &progress) == 0 && progress.rx == 0);
    }
    CHECK(neighbor_state() == NUD_STALE);
    CHECK(ker_neighbor_monitor_probe(&monitor) == 0 && neighbor_state() == NUD_DELAY);

    /* TX copy chains are independently checked against exact 42-byte frames.
     * Capacity one forces the reply to remain the exporter's retry head. */
    tx_expected_count = tx_accepted_count = rx_expected_count = rx_received = 0;
    add_tx_expected(ARPOP_REQUEST, local_ip, local_mac, remote_ip,
        broadcast_mac, zero_mac);
    add_tx_expected(ARPOP_REPLY, remote_ip, remote_mac, local_ip,
        broadcast_mac, local_mac);
    add_rx_expect(ARPOP_REQUEST, local_ip, remote_ip, local_mac, zero_mac,
        false, false, 0);
    add_rx_expect(ARPOP_REPLY, remote_ip, local_ip, remote_mac, local_mac,
        true, true, -ENOTSUP);
    struct sk_buff *request = configured(&local_address, ARPOP_REQUEST,
        remote_ip, broadcast_mac, zero_mac);
    struct sk_buff *reply = configured(&remote_address, ARPOP_REPLY,
        local_ip, broadcast_mac, local_mac);
    struct sk_buff *retained_reply = reply;
    CHECK(ker_tx_export_enqueue(&tx, &request) == 0 && !request);
    CHECK(ker_tx_export_enqueue(&tx, &reply) == 0 && !reply);
    struct ker_worker_result progress;
    poll_worker(&progress);
    CHECK(progress.tx == 1 && progress.rx == 1 && tx.pending == retained_reply &&
        tx.last_error == -EAGAIN && tx.packets == 1 && rx_received == 1);
    CHECK(retained_reply->len == 42 && !memcmp(retained_reply->data,
        tx_expected[1], 42));
    poll_worker(&progress);
    CHECK(progress.tx == 1 && progress.rx == 1 && !tx.pending &&
        rx_received == 2 && tx_accepted_count == 2);
    CHECK(neighbor_state() == NUD_DELAY && !memcmp(monitor.entry->ha,
        original_mac, ETH_ALEN));

    /* Native feedback remains scoped to decoded host replies and changes only
     * the matching existing monitored mapping. */
    struct sk_buff *wrong_target = ker_arp_create(&remote_device, ARPOP_REPLY,
        remote_ip, foreign_ip, local_mac, remote_mac, local_mac, &reply) == 0 ? reply : NULL;
    CHECK(wrong_target);
    expect_unchanged_after_bad_reply(wrong_target, ARPOP_REPLY, remote_ip,
        foreign_ip, remote_mac, local_mac, false, -ENOTSUP);
    struct sk_buff *wrong_sender = NULL;
    CHECK(ker_arp_create(&remote_device, ARPOP_REPLY, foreign_ip, local_ip,
        local_mac, remote_mac, local_mac, &wrong_sender) == 0);
    expect_unchanged_after_bad_reply(wrong_sender, ARPOP_REPLY, foreign_ip,
        local_ip, remote_mac, local_mac, true, -ENOENT);

    /* Broadcast reply reaches the decoder but native feedback fails closed. */
    struct sk_buff *broadcast_reply = configured(&remote_address, ARPOP_REPLY,
        local_ip, broadcast_mac, local_mac);
    expect_unchanged_after_bad_reply(broadcast_reply, ARPOP_REPLY, remote_ip,
        local_ip, remote_mac, local_mac, true, -ENOTSUP);

    /* A short ARP body is consumed as a receive-ring drop and never invokes
     * the copied-message callback or changes the neighbor timer. */
    unsigned char short_frame[42];
    encode(short_frame, ARPOP_REPLY, remote_ip, remote_mac, local_ip,
        local_mac, local_mac);
    unsigned int old_rx = rx_received;
    struct ker_neighbor_event before_short, after_short;
    unsigned long confirmed_short = monitor.entry->confirmed;
    unsigned long updated_short = monitor.entry->updated;
    unsigned int refs_short = (unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned int notifications_short = notifications;
    int64_t deadline_short;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &before_short) == 0 &&
        ker_runtime_next_deadline(&worker.timers, &deadline_short) == 1);
    CHECK(ker_tx_ring_sink(short_arp_chain(short_frame), &ring) == 0);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0 &&
        progress.rx == 1 && rx.last_completed == 1 && rx.last_dropped == 1 &&
        rx.last_error == 0 && rx_received == old_rx);
    int64_t deadline_after_short;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &after_short) == 0 &&
        before_short.state == after_short.state && before_short.probes == after_short.probes &&
        !memcmp(before_short.mac, after_short.mac, ETH_ALEN) &&
        monitor.entry->confirmed == confirmed_short && monitor.entry->updated == updated_short &&
        (unsigned int)refcount_read(&monitor.entry->refcnt) == refs_short &&
        notifications == notifications_short &&
        ker_runtime_next_deadline(&worker.timers, &deadline_after_short) == 1 &&
        deadline_short == deadline_after_short && neighbor_state() == NUD_DELAY &&
        !memcmp(monitor.entry->ha, original_mac, ETH_ALEN));

    /* Finally, a host reply for the monitored key confirms the real entry. */
    struct sk_buff *good_reply = configured(&remote_address, ARPOP_REPLY,
        local_ip, local_mac, local_mac);
    add_tx_expected(ARPOP_REPLY, remote_ip, remote_mac, local_ip,
        local_mac, local_mac);
    add_rx_expect(ARPOP_REPLY, remote_ip, local_ip, remote_mac, local_mac,
        true, true, 0);
    CHECK(ker_tx_export_enqueue(&tx, &good_reply) == 0 && !good_reply);
    poll_worker(&progress);
    CHECK(progress.tx == 1 && progress.rx == 1 && rx_received == old_rx + 1);
    CHECK(neighbor_state() == NUD_REACHABLE &&
        !memcmp(monitor.entry->ha, remote_mac, ETH_ALEN));

    /* Reinitialize only the ring adapters to a two-entry ring. Exhausting the
     * real packet pool makes RX retain its first source chain while the later
     * chain remains queued; cancellation returns the same complete chain. */
    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
    CHECK(ker_rx_ring_cleanup(&rx) == 0 && ker_tx_export_cleanup(&tx) == 0 &&
        ker_tx_ring_cleanup(&ring) == 0);
    ring = (struct ker_tx_ring){0}; rx = (struct ker_rx_ring){0};
    tx = (struct ker_tx_export){0};
    CHECK(ker_tx_ring_init(&ring, "arp_ring2", 2, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init_chain(&tx, &context, 2, 8192, 13,
        ring_sink, &ring) == 0);
    CHECK(ker_rx_ring_init(&rx, &ring, &local_device, &runtime, 128) == 0);
    tx_expected_count = tx_accepted_count = 0;
    rx_expected_count = rx_received = 0;
    add_tx_expected(ARPOP_REQUEST, local_ip, local_mac, remote_ip,
        broadcast_mac, zero_mac);
    add_tx_expected(ARPOP_REQUEST, local_ip, local_mac, foreign_ip,
        broadcast_mac, zero_mac);
    add_rx_expect(ARPOP_REQUEST, local_ip, foreign_ip, local_mac, zero_mac,
        false, false, 0);
    request = configured(&local_address, ARPOP_REQUEST, remote_ip,
        broadcast_mac, zero_mac);
    struct sk_buff *later = configured(&local_address, ARPOP_REQUEST,
        foreign_ip, broadcast_mac, zero_mac);
    CHECK(ker_tx_export_enqueue(&tx, &request) == 0 && !request);
    CHECK(ker_tx_export_enqueue(&tx, &later) == 0 && !later);
    CHECK(ker_tx_export_poll(&tx, 2) == 2 && tx_accepted_count == 2 &&
        rte_ring_count(ring.ring) == 2);
    struct rte_mbuf *held[POOL_SIZE]; unsigned int held_count = 0;
    while (rte_mempool_avail_count(pool.mbufs) > 1 &&
        held_count < POOL_SIZE &&
        (held[held_count] = ker_packet_alloc(&pool)) != NULL)
        ++held_count;
    CHECK(held_count > 0 && held_count < POOL_SIZE &&
        rte_mempool_avail_count(pool.mbufs) == 1);
    exhaust_during_rx = true;
    int pressure_rc = ker_worker_poll(&worker, worker.timers.now_ns, &progress);
    CHECK(pressure_rc == -ENOMEM &&
        rx.pending == tx_accepted[0] && rx.last_error == -ENOMEM &&
        rx.last_completed == 0 && rte_ring_count(ring.ring) == 1);
    struct rte_mbuf *cancelled = (void *)(uintptr_t)1;
    CHECK(ker_rx_ring_cancel(&rx, &cancelled) == 1 &&
        cancelled == tx_accepted[0] && !rx.pending && rte_ring_count(ring.ring) == 1);
    unsigned char cancelled_bytes[42];
    const void *read = rte_pktmbuf_read(cancelled, 0, sizeof(cancelled_bytes),
        cancelled_bytes);
    CHECK(read && read == cancelled_bytes && cancelled->pkt_len == 42 &&
        cancelled->nb_segs == 4 && !memcmp(cancelled_bytes, tx_expected[0], 42));
    unsigned int linked = 0; size_t linked_bytes = 0;
    for (struct rte_mbuf *part = cancelled; part; part = part->next) {
        CHECK(rte_mbuf_refcnt_read(part) == 1 && part->ol_flags == 0);
        linked++; linked_bytes += part->data_len;
    }
    CHECK(linked == cancelled->nb_segs && linked_bytes == cancelled->pkt_len);
    ker_packet_free(cancelled);
    for (unsigned int i = 0; i < held_count; ++i) ker_packet_free(held[i]);
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0 &&
        progress.rx == 1 && rx_received == 1 && rx.last_error == 0 &&
        rx.last_dropped == 0 && rte_ring_empty(ring.ring));

    /* All consumed or canceled records leave their exact bytes/copies owned
     * by one side, and no hidden ARP learning occurred for the bad packets. */
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_rx_ring_cleanup(&rx) == 0 && ker_tx_export_cleanup(&tx) == 0 &&
        ker_tx_ring_cleanup(&ring) == 0);
    CHECK(ker_arp_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_neighbor_remove(&neighbors, remote_ip) == 0);
    CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
    CHECK(ker_ipv4_address_cleanup(&remote_address) == 0);
    CHECK(ker_ipv4_address_cleanup(&local_address) == 0);
    CHECK(ker_eth_device_cleanup(&remote_device) == 0 &&
        ker_eth_device_cleanup(&local_device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_SIZE &&
        ker_packet_pool_cleanup(&pool) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "arp_ring_packets", POOL_SIZE, 0,
        2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "arp_ring_skb") == 0);
    local_ip = wire_ip(0xc0000201); remote_ip = wire_ip(0xc0000202);
    foreign_ip = wire_ip(0xc0000203);
    CHECK(ker_eth_device_init(&local_device, &context, "arp-local", 1,
        local_mac) == 0);
    CHECK(ker_eth_device_init(&remote_device, &context, "arp-remote", 2,
        remote_mac) == 0);
    CHECK(ker_arp_device_setup(&local_device) == 0 &&
        ker_arp_device_setup(&remote_device) == 0);
    CHECK(ker_ipv4_address_init(&local_address, &local_device, local_ip, 24) == 0);
    CHECK(ker_ipv4_address_init(&remote_address, &remote_device, remote_ip, 24) == 0);
    CHECK(ker_neighbor_table_init(&neighbors, &local_address, "arp_ring_neighbors",
        4, 2) == 0);
    local_worker_ring_tests();
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("ARP ring: configured frames, native feedback, retry, cancel ownership and pool recovery passed");
    return 0;
}
