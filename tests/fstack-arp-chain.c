#include "check.h"
#include "eal.h"
#include "runtime/arp-receive.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/neighbor-timer.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include "ker/linux_neighbor_update.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_receive_runtime receive_runtime;
static struct ker_arp_receiver receiver;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor monitor;
static struct ker_worker worker;
static const unsigned char local_mac[ETH_ALEN] = {2, 1, 2, 3, 4, 5};
static const unsigned char original_peer[ETH_ALEN] = {2, 6, 7, 8, 9, 10};
static const unsigned char learned_peer[ETH_ALEN] = {2, 10, 9, 8, 7, 6};
static __be32 local_ip, peer_ip, foreign_ip;
static struct rte_mbuf *pending_chain;
static int copy_result, feedback_result;
static unsigned int messages, notifications, callback_calls, probe_callbacks, raw_dispatch_status;
static unsigned int notification_expected_state;
static __be32 expected_sender_ip, expected_target_ip;
static bool expected_target_local;
static unsigned int expected_packet_type = PACKET_HOST;

static int receive_arp(const struct ker_arp_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    ++messages;
    CHECK(message->operation == ARPOP_REPLY && message->sender_ip == expected_sender_ip);
    CHECK(message->target_ip == expected_target_ip && message->target_local == expected_target_local);
    CHECK(!memcmp(message->sender_mac, learned_peer, ETH_ALEN));
    CHECK(!memcmp(message->target_mac, local_mac, ETH_ALEN));
    ++callback_calls;
    feedback_result = ker_arp_neighbor_feedback(&receiver, &monitor, message,
        NEIGH_UPDATE_F_OVERRIDE);
    return NET_RX_SUCCESS;
}

static void monitor_notify(const struct ker_neighbor_event *event, void *arg)
{
    (void)arg;
    CHECK(event->ip == peer_ip);
    if (notification_expected_state)
        CHECK(event->state == notification_expected_state);
    ++notifications;
}

static int receive_chain(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!pending_chain)
        return 0;
    struct rte_mbuf *chain = pending_chain;
    pending_chain = NULL;
    struct sk_buff *skb = (void *)(uintptr_t)1;
    copy_result = ker_eth_receive_copy_chain(&device, chain, 192, &skb);
    ker_packet_free(chain); /* Caller releases the source before protocol dispatch. */
    if (copy_result)
        return 1;
    CHECK(skb && skb->pkt_type == expected_packet_type && skb->protocol == rte_cpu_to_be_16(ETH_P_ARP));
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&receive_runtime, &device, &skb, &result) == 0 && !skb);
    raw_dispatch_status = result.status;
    return 1;
}

static struct rte_mbuf *arp_reply_chain(const unsigned char destination[ETH_ALEN],
    __be32 sender_ip, __be32 target_ip, bool complete)
{
    unsigned char frame[ETH_HLEN + 28] = {0};
    memcpy(frame, destination, ETH_ALEN);
    memcpy(frame + ETH_ALEN, learned_peer, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x06;
    frame[14] = 0; frame[15] = ARPHRD_ETHER;
    frame[16] = 0x08; frame[17] = 0x00;
    frame[18] = ETH_ALEN; frame[19] = 4;
    frame[20] = 0; frame[21] = ARPOP_REPLY;
    memcpy(frame + 22, learned_peer, ETH_ALEN);
    memcpy(frame + 28, &sender_ip, sizeof(sender_ip));
    memcpy(frame + 32, local_mac, ETH_ALEN);
    memcpy(frame + 38, &target_ip, sizeof(target_ip));
    static const uint16_t pieces[] = {5, 9, 0, 4, 5, 19};
    struct rte_mbuf *segments[6];
    unsigned int offset = 0, total = complete ? sizeof(frame) : sizeof(frame) - 1;
    for (unsigned int i = 0; i < 6; ++i) {
        segments[i] = ker_packet_alloc(&pool);
        CHECK(segments[i]);
        uint16_t length = pieces[i];
        if (offset + length > total) length = (uint16_t)(total - offset);
        unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(segments[i], length);
        CHECK(!length || bytes);
        if (length) memcpy(bytes, frame + offset, length);
        offset += length;
    }
    CHECK(offset == total);
    for (int i = 4; i >= 0; --i) CHECK(rte_pktmbuf_chain(segments[i], segments[i + 1]) == 0);
    CHECK(segments[0]->nb_segs == 6 && segments[0]->pkt_len == total);
    return segments[0];
}

static unsigned int monitor_state(void)
{
    struct ker_neighbor_event event;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &event) == 0);
    return event.state;
}

static void poll_one(struct rte_mbuf *chain)
{
    struct ker_worker_result result = {0};
    CHECK(!pending_chain);
    pending_chain = chain;
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &result) == 0);
    CHECK(result.rx == 1 && !pending_chain && context.live == 0);
}

static void check_unchanged_feedback(struct rte_mbuf *chain, int expected_feedback,
    int expected_dispatch, __be32 sender_ip, __be32 target_ip, bool target_local,
    unsigned int packet_type)
{
    struct ker_neighbor_event before, after;
    int64_t before_deadline, after_deadline;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &before) == 0);
    CHECK(ker_runtime_next_deadline(&worker.timers, &before_deadline) == 1);
    unsigned int refs = (unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned long confirmed = monitor.entry->confirmed, updated = monitor.entry->updated;
    unsigned int old_messages = messages, old_notifications = notifications;
    expected_sender_ip = sender_ip;
    expected_target_ip = target_ip;
    expected_target_local = target_local;
    expected_packet_type = packet_type;
    feedback_result = -EFAULT;
    poll_one(chain);
    CHECK(feedback_result == expected_feedback && raw_dispatch_status == (unsigned int)expected_dispatch);
    CHECK(messages == old_messages + 1);
    CHECK(notifications == old_notifications);
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &after) == 0);
    CHECK(before.state == after.state && before.probes == after.probes && before.ip == after.ip &&
        !memcmp(before.mac, after.mac, ETH_ALEN));
    CHECK(monitor.entry->confirmed == confirmed && monitor.entry->updated == updated &&
        (unsigned int)refcount_read(&monitor.entry->refcnt) == refs && timer_pending(&monitor.entry->timer));
    CHECK(ker_runtime_next_deadline(&worker.timers, &after_deadline) == 1 && after_deadline == before_deadline);
}

static void monitor_probe(const struct ker_neighbor_event *event, void *arg)
{
    (void)event;
    (void)arg;
    ++probe_callbacks;
}

int main(void)
{
    ker_test_eal_init();
    local_ip = rte_cpu_to_be_32(0xc0000201);
    peer_ip = rte_cpu_to_be_32(0xc0000202);
    foreign_ip = rte_cpu_to_be_32(0xc0000203);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "fstack_arp_chain", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "fstack_arp_chain_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "arp-chain", 8, local_mac) == 0);
    CHECK(ker_arp_device_setup(&device) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
    CHECK(ker_neighbor_table_init(&neighbors, &address, "arp_chain_neighbors", 4, 2) == 0);
    struct ker_neighbor_config config = {.retrans_ticks = 20, .reachable_ticks = 100,
        .delay_ticks = 30, .ucast_probes = 2, .mcast_reprobes = 1};
    CHECK(ker_neighbor_configure(&neighbors, &config) == 0);
    CHECK(ker_neighbor_add(&neighbors, peer_ip, original_peer) == 0);
    CHECK(ker_receive_runtime_init(&receive_runtime, &context) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &receive_runtime, &address, receive_arp, &receiver) == 0);
    struct ker_worker_config worker_config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops worker_ops = {.rx = receive_chain};
    CHECK(ker_worker_init(&worker, &pool, &worker_config, &worker_ops) == 0);
    CHECK(ker_neighbor_monitor_init(&monitor, &neighbors, &worker.timers, peer_ip, monitor_probe,
        monitor_notify, NULL) == 0);
    struct ker_neighbor_event event;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &event) == 0 && event.state == NUD_REACHABLE);
    notification_expected_state = NUD_STALE;
    while (monitor_state() == NUD_REACHABLE) {
        int64_t deadline; struct ker_worker_result result;
        CHECK(ker_runtime_next_deadline(&worker.timers, &deadline) == 1);
        CHECK(ker_worker_poll(&worker, deadline, &result) == 0 && result.rx == 0);
    }
    notification_expected_state = 0;
    CHECK(notifications == 1);
    CHECK(monitor_state() == NUD_STALE);
    CHECK(ker_neighbor_monitor_probe(&monitor) == 0 && monitor_state() == NUD_DELAY);

    /* Broadcast Ethernet replies and replies for another local address are
     * decoded but cannot feed the monitored entry. */
    const unsigned char broadcast[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
    check_unchanged_feedback(arp_reply_chain(broadcast, peer_ip, local_ip, true), -ENOTSUP,
        NET_RX_SUCCESS, peer_ip, local_ip, true, PACKET_BROADCAST);
    check_unchanged_feedback(arp_reply_chain(local_mac, peer_ip, foreign_ip, true), -ENOTSUP,
        NET_RX_SUCCESS, peer_ip, foreign_ip, false, PACKET_HOST);
    check_unchanged_feedback(arp_reply_chain(local_mac, foreign_ip, local_ip, true), -ENOENT,
        NET_RX_SUCCESS, foreign_ip, local_ip, true, PACKET_HOST);

    /* A short ARP body is consumed by the original gate, with no decoded
     * callback or neighbor/timer mutation. */
    unsigned int before_messages = messages;
    struct ker_neighbor_event before_short, after_short;
    int64_t deadline_before, deadline_after;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &before_short) == 0);
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_before) == 1);
    raw_dispatch_status = NET_RX_SUCCESS;
    unsigned int refs_before_short = (unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned long confirmed_before_short = monitor.entry->confirmed;
    unsigned long updated_before_short = monitor.entry->updated;
    unsigned int notifications_before_short = notifications;
    poll_one(arp_reply_chain(local_mac, peer_ip, local_ip, false));
    CHECK(messages == before_messages && ker_neighbor_monitor_snapshot(&monitor, &after_short) == 0);
    CHECK(raw_dispatch_status == NET_RX_DROP);
    CHECK(before_short.state == after_short.state && before_short.probes == after_short.probes &&
        !memcmp(before_short.mac, after_short.mac, ETH_ALEN));
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_after) == 1 && deadline_after == deadline_before);
    CHECK((unsigned int)refcount_read(&monitor.entry->refcnt) == refs_before_short &&
        monitor.entry->confirmed == confirmed_before_short && monitor.entry->updated == updated_before_short &&
        notifications == notifications_before_short);

    /* Exhaust every remaining mbuf after constructing the input chain; copy
     * failure leaves the source releasable and the worker/context recoverable. */
    struct rte_mbuf *exhausted_chain = arp_reply_chain(local_mac, peer_ip, local_ip, true);
    struct rte_mbuf *held[25];
    for (unsigned int i = 0; i < 25; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    before_messages = messages;
    struct ker_neighbor_event before_oom, after_oom;
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &before_oom) == 0);
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_before) == 1);
    unsigned int refs_before_oom = (unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned long confirmed_before_oom = monitor.entry->confirmed;
    unsigned long updated_before_oom = monitor.entry->updated;
    unsigned int notifications_before_oom = notifications;
    struct sk_buff *output_skb = (void *)(uintptr_t)1;
    copy_result = ker_eth_receive_copy_chain(&device, exhausted_chain, 192, &output_skb);
    CHECK(copy_result == -ENOMEM && output_skb == (void *)(uintptr_t)1 && context.live == 0 && messages == before_messages);
    CHECK(exhausted_chain->nb_segs == 6 && exhausted_chain->pkt_len == ETH_HLEN + 28);
    const struct rte_mbuf *segment = exhausted_chain;
    for (unsigned int i = 0; i < 6; ++i) {
        CHECK(segment && rte_mbuf_refcnt_read(segment) == 1);
        segment = segment->next;
    }
    CHECK(!segment);
    ker_packet_free(exhausted_chain);
    for (unsigned int i = 0; i < 25; ++i) ker_packet_free(held[i]);
    CHECK(ker_neighbor_monitor_snapshot(&monitor, &after_oom) == 0);
    CHECK(before_oom.state == after_oom.state && before_oom.probes == after_oom.probes &&
        !memcmp(before_oom.mac, after_oom.mac, ETH_ALEN));
    CHECK(ker_runtime_next_deadline(&worker.timers, &deadline_after) == 1 && deadline_after == deadline_before);
    CHECK((unsigned int)refcount_read(&monitor.entry->refcnt) == refs_before_oom &&
        monitor.entry->confirmed == confirmed_before_oom && monitor.entry->updated == updated_before_oom &&
        notifications == notifications_before_oom);

    unsigned int notifications_before = notifications;
    notification_expected_state = NUD_REACHABLE;
    expected_sender_ip = peer_ip;
    expected_target_ip = local_ip;
    expected_target_local = true;
    expected_packet_type = PACKET_HOST;
    feedback_result = -EFAULT;
    poll_one(arp_reply_chain(local_mac, peer_ip, local_ip, true));
    CHECK(copy_result == 0 && callback_calls == 4 && messages == before_messages + 1 &&
        feedback_result == 0 && raw_dispatch_status == NET_RX_SUCCESS);
    CHECK(monitor_state() == NUD_REACHABLE && !memcmp(monitor.entry->ha, learned_peer, ETH_ALEN));
    CHECK(refcount_read(&monitor.entry->refcnt) == 3 && timer_pending(&monitor.entry->timer));
    CHECK(notifications == notifications_before + 1 && rte_mempool_avail_count(pool.mbufs) == 31);
    notification_expected_state = 0;
    CHECK(probe_callbacks == 0); /* This bounded DELAY case doesn't claim ARP probe transmission. */

    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
    struct neighbour *entry = NULL; unsigned char restored[ETH_ALEN];
    CHECK(ker_neighbor_lookup(&neighbors, peer_ip, &entry) == 0);
    CHECK(ker_neighbor_mac(&neighbors, entry, restored) == 0 && !memcmp(restored, original_peer, ETH_ALEN));
    CHECK(ker_neighbor_release(&neighbors, entry) == 0);
    CHECK(ker_neighbor_remove(&neighbors, peer_ip) == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_arp_receiver_unregister(&receiver) == 0);
    CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
    CHECK(ker_receive_runtime_cleanup(&receive_runtime) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("F-Stack multisegment ARP feedback integration passed");
    return 0;
}
