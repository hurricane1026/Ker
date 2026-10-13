/* Ker flow-owner receive adapter: segmented transport packets through service. */
#include "check.h"
#include "eal.h"
#include "runtime/flow-receive.h"
#include "runtime/flow-ring.h"
#include "runtime/memory.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <string.h>

struct endpoint {
    struct ker_packet_pool pool;
    struct ker_skb_context skb;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_worker worker;
    struct ker_flow_receive receive;
    uint8_t ids[16];
    unsigned int count;
    unsigned int rx_calls;
    struct rte_mbuf *held[127];
    unsigned int held_count;
    bool release_held_on_tx;
    bool reenter;
    int reenter_cleanup, reenter_cancel, reenter_detach;
};
static struct endpoint *active;

static uint32_t sum_bytes(const uint8_t *p, unsigned int n, uint32_t sum)
{
    for (unsigned int i = 0; i < n; i += 2)
        sum += ((uint32_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return sum;
}
static uint16_t checksum(const uint8_t *p, unsigned int n, uint32_t sum)
{
    return (uint16_t)~sum_bytes(p, n, sum);
}
static void put16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }

static int message(const struct ker_transport_message *m, void *arg)
{
    struct endpoint *e = arg;
    CHECK(active == e && e->runtime.dispatching);
    const uint8_t *payload;
    if (m->protocol == KER_TRANSPORT_UDP) {
        CHECK(m->packet.udp.payload_length == 1);
        payload = m->packet.udp.payload;
    } else {
        CHECK(m->protocol == KER_TRANSPORT_TCP && m->packet.tcp.payload_length == 1);
        payload = m->packet.tcp.payload;
    }
    CHECK(payload[0] != 0);
    CHECK(e->count < sizeof(e->ids));
    e->ids[e->count++] = payload[0];
    if (e->reenter) {
        struct rte_mbuf *out = NULL;
        e->reenter_cleanup = ker_flow_receive_cleanup(&e->receive);
        e->reenter_cancel = ker_flow_receive_cancel(&e->receive, &out);
        e->reenter_detach = ker_flow_detach(ker_flow_receive_context(&e->receive));
        CHECK(!out);
    }
    return NET_RX_SUCCESS;
}

static unsigned int make_frame(uint8_t b[64], uint8_t id, unsigned int protocol,
    unsigned int options, bool corrupt)
{
    unsigned int ihl = 20 + options;
    unsigned int l4len = (protocol == IPPROTO_TCP ? 20U : 8U) + 1;
    unsigned int length = 14 + ihl + l4len;
    memset(b, 0, 64);
    b[0] = 2; b[6] = 2; b[12] = 8;
    uint8_t *ip = b + 14;
    ip[0] = (uint8_t)(0x40 | (ihl / 4)); put16(ip + 2, (uint16_t)(ihl + l4len));
    ip[8] = 64; ip[9] = (uint8_t)protocol;
    if (options) { memset(ip + 20, 1, options); ip[20 + options - 1] = 0; }
    const uint8_t addresses[8] = {192,0,2,1,10,0,0,1};
    memcpy(ip + 12, addresses, sizeof(addresses));
    put16(ip + 10, checksum(ip, ihl, 0));
    uint8_t *l4 = ip + ihl;
    put16(l4, 1234); put16(l4 + 2, 443);
    if (protocol == IPPROTO_UDP) {
        put16(l4 + 4, (uint16_t)l4len); l4[8] = id;
    } else {
        l4[12] = 0x50; l4[13] = 0x10; l4[20] = id;
    }
    uint8_t pseudo[12] = {192,0,2,1,10,0,0,1,0,(uint8_t)protocol,0,0};
    put16(pseudo + 10, (uint16_t)l4len);
    put16(l4 + (protocol == IPPROTO_TCP ? 16 : 6),
        checksum(l4, l4len, sum_bytes(pseudo, sizeof(pseudo), 0)));
    if (corrupt) l4[protocol == IPPROTO_TCP ? 16 : 6] ^= 0x20;
    return length;
}
static struct rte_mbuf *packet_variant(struct ker_packet_pool *pool, uint8_t id,
    unsigned int protocol, unsigned int options, bool corrupt)
{
    uint8_t bytes[64]; unsigned int length = make_frame(bytes, id, protocol, options, corrupt);
    unsigned int sizes[] = {13, 9, 7, length - 29};
    struct rte_mbuf *head = NULL; unsigned int offset = 0;
    for (unsigned int i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        struct rte_mbuf *part = ker_packet_alloc(pool); CHECK(part);
        void *dst = rte_pktmbuf_append(part, sizes[i]); CHECK(dst);
        memcpy(dst, bytes + offset, sizes[i]); offset += sizes[i];
        if (!head) head = part;
        else CHECK(rte_pktmbuf_chain(head, part) == 0);
    }
    CHECK(offset == length && head->nb_segs == 4);
    return head;
}
static struct rte_mbuf *packet(struct ker_packet_pool *pool, uint8_t id, bool corrupt)
{ return packet_variant(pool, id, IPPROTO_UDP, 0, corrupt); }
static int service_poll(void *arg, unsigned int budget)
{ struct endpoint *e = arg; return ker_flow_receive_poll(&e->receive, budget); }
static int tx_poll(void *arg, unsigned int budget)
{
    struct endpoint *e = arg;
    CHECK(budget == 1);
    if (e->release_held_on_tx) {
        e->release_held_on_tx = false;
        while (e->held_count) ker_packet_free(e->held[--e->held_count]);
    }
    return 0;
}
static int rx_probe(void *arg, unsigned int budget)
{ struct endpoint *e = arg; CHECK(budget <= 1); e->rx_calls++; return 0; }
struct foreign_calls {
    struct ker_flow_receive *receive;
    struct ker_flow_fabric *fabric;
    struct ker_worker *worker;
    struct ker_eth_device *device;
    struct ker_receive_runtime *runtime;
    int poll, cancel, cleanup, init;
};
static void *foreign_lifecycle(void *arg)
{
    struct foreign_calls *calls = arg;
    struct rte_mbuf *out = NULL;
    calls->poll = ker_flow_receive_poll(calls->receive, 1);
    calls->cancel = ker_flow_receive_cancel(calls->receive, &out);
    calls->cleanup = ker_flow_receive_cleanup(calls->receive);
    struct ker_flow_receive other = {0};
    struct ker_flow_receive_config config = {.name="fo_foreign", .capacity=1,
        .socket_id=SOCKET_ID_ANY, .headroom=128};
    calls->init = ker_flow_receive_init(&other, calls->fabric, calls->worker, 0,
        calls->device, calls->runtime, &config);
    CHECK(!out && !other.initialized && !other.queue.ring && !other.rx.ring);
    return NULL;
}
static void init_endpoint(struct endpoint *e, unsigned int id,
    struct ker_flow_fabric *fabric)
{
    CHECK(ker_packet_pool_init(&e->pool, id ? "fo_rx_pool1" : "fo_rx_pool0",
        127, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&e->skb, &e->pool, id ? "fo_rx_skb1" : "fo_rx_skb0") == 0);
    CHECK(ker_eth_device_init(&e->device, &e->skb, id ? "fo_rx1" : "fo_rx0", id + 1,
        (const uint8_t[]){2,0,0,0,0,1}) == 0);
    CHECK(ker_receive_runtime_init(&e->runtime, &e->skb) == 0);
    CHECK(ker_transport_receiver_register(&e->receiver, &e->runtime, &e->device,
        message, e) == 0);
    struct ker_worker_config wc = {.timer_budget=1, .service_budget=2,
        .handoff_budget=2, .tx_budget=1, .rx_budget=1, .packet_low=8, .packet_high=16};
    struct ker_worker_ops ops = {.service=service_poll, .tx=tx_poll, .rx=rx_probe, .arg=e};
    CHECK(ker_worker_init(&e->worker, &e->pool, &wc, &ops) == 0);
    struct ker_flow_receive_config rc = {.name=id ? "fo_rx_queue1" : "fo_rx_queue0",
        .capacity=1, .socket_id=SOCKET_ID_ANY, .headroom=128};
    CHECK(ker_flow_receive_init(&e->receive, fabric, &e->worker, id,
        &e->device, &e->runtime, &rc) == 0);
}
static int poll_worker(struct endpoint *e, unsigned int *handoff, unsigned int *service)
{
    struct ker_worker_result result = {0}; active = e;
    int error = ker_worker_poll(&e->worker, 0, &result); active = NULL;
    *handoff = result.handoff; *service = result.service;
    return error;
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    uint16_t owners[KER_FLOW_BUCKETS];
    for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i) owners[i] = 1;
    struct ker_flow_fabric fabric = {0};
    struct ker_flow_config fc = {.worker_count=2, .bucket_owner=owners,
        .inbox_capacity=2, .name="fo_receive_fabric", .socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&fabric, &fc) == 0);
    struct endpoint e[2] = {0}; init_endpoint(&e[0], 0, &fabric); init_endpoint(&e[1], 1, &fabric);
    struct ker_flow_context *source = ker_flow_receive_context(&e[0].receive);
    struct ker_flow_context *owner = ker_flow_receive_context(&e[1].receive);
    CHECK(source && owner && ker_flow_receive_context(NULL) == NULL);
    CHECK(ker_flow_detach(owner) == -EBUSY);
    struct foreign_calls foreign = {.receive=&e[1].receive, .fabric=&fabric,
        .worker=&e[0].worker, .device=&e[0].device, .runtime=&e[0].runtime};
    pthread_t foreign_thread;
    CHECK(pthread_create(&foreign_thread, NULL, foreign_lifecycle, &foreign) == 0);
    CHECK(pthread_join(foreign_thread, NULL) == 0);
    CHECK(foreign.poll == -EXDEV && foreign.cancel == -EXDEV &&
        foreign.cleanup == -EXDEV && foreign.init == -EXDEV);
    struct ker_tx_ring pin_source = {0}; struct ker_flow_ring pin = {0};
    CHECK(ker_tx_ring_init(&pin_source, "fo_pin_source", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_flow_ring_init(&pin, &pin_source, owner, 7, KER_FLOW_INGRESS) == 0);
    CHECK(ker_flow_receive_cleanup(&e[1].receive) == -EBUSY);
    CHECK(ker_flow_ring_cleanup(&pin) == 0);
    CHECK(ker_tx_ring_cleanup(&pin_source) == 0);

    /* Local delivery queues first and only dispatches in the worker service stage. */
    struct rte_mbuf *m = packet(&e[1].pool, 1, false);
    CHECK(ker_flow_submit(owner, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(e[1].count == 0);
    CHECK(ker_flow_receive_cleanup(&e[1].receive) == -EBUSY);
    e[1].reenter = true;
    unsigned int handoff, service;
    CHECK(poll_worker(&e[1], &handoff, &service) == 0);
    CHECK(handoff == 0 && service == 1 && e[1].count == 1 && e[1].ids[0] == 1);
    CHECK(e[1].reenter_cleanup == -EBUSY && e[1].reenter_cancel == -EBUSY &&
        e[1].reenter_detach == -EBUSY);
    e[1].reenter = false;

    /* Establish packet pressure, then hand off a valid segmented datagram. The
     * owner retains it on ENOMEM and services retries despite RX pressure. */
    while (e[1].held_count < 127 &&
        (e[1].held[e[1].held_count] = ker_packet_alloc(&e[1].pool))) e[1].held_count++;
    CHECK(e[1].held_count == 127);
    unsigned int rx_calls_before_pressure = e[1].rx_calls;
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && !handoff && !service);
    CHECK(e[1].worker.packet_pressure && e[1].rx_calls == rx_calls_before_pressure);
    m = packet(&e[0].pool, 2, false);
    struct rte_mbuf *original = m;
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(ker_flow_receive_cleanup(&e[1].receive) == -EBUSY);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && !service);
    CHECK(e[1].receive.rx.pending && e[1].receive.rx.last_error == -ENOMEM);
    CHECK(e[1].held_count == 127);
    CHECK(e[1].receive.rx.pending == original && original->nb_segs == 4 && original->pkt_len == 43);
    for (struct rte_mbuf *seg = original; seg; seg = seg->next)
        CHECK(rte_mbuf_refcnt_read(seg) == 1);
    uint8_t expected[64], scratch[43];
    make_frame(expected, 2, IPPROTO_UDP, 0, false);
    const void *read = rte_pktmbuf_read(original, 0, sizeof(scratch), scratch);
    CHECK(read && memcmp(read, expected, sizeof(scratch)) == 0);
    m = packet(&e[0].pool, 3, false);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && !service);
    CHECK(e[1].receive.rx.pending == original && e[1].receive.rx.last_error == -ENOMEM);
    CHECK(original->nb_segs == 4 && original->pkt_len == 43);
    for (struct rte_mbuf *seg = original; seg; seg = seg->next)
        CHECK(rte_mbuf_refcnt_read(seg) == 1);
    read = rte_pktmbuf_read(original, 0, sizeof(scratch), scratch);
    CHECK(read && memcmp(read, expected, sizeof(scratch)) == 0);
    m = packet(&e[0].pool, 4, false);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    e[1].release_held_on_tx = true;
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && !service);
    CHECK(e[1].receive.overflow_dropped == 1 && e[1].receive.last_enqueue_error == -EAGAIN);
    CHECK(!e[1].release_held_on_tx && !e[1].held_count &&
        e[1].receive.rx.pending == original && e[1].receive.rx.last_error == -ENOMEM);
    CHECK(original->nb_segs == 4 && original->pkt_len == 43);
    for (struct rte_mbuf *seg = original; seg; seg = seg->next)
        CHECK(rte_mbuf_refcnt_read(seg) == 1);
    read = rte_pktmbuf_read(original, 0, sizeof(scratch), scratch);
    CHECK(read && memcmp(read, expected, sizeof(scratch)) == 0);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && !handoff && service == 2);
    CHECK(e[1].count == 3 && e[1].ids[1] == 2 && e[1].ids[2] == 3);
    CHECK(!e[1].receive.rx.pending && !e[1].worker.packet_pressure);
    CHECK(e[1].rx_calls == rx_calls_before_pressure + 2);

    /* Bad transport checksum is consumed as a receive drop. */
    m = packet(&e[0].pool, 6, true);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && service == 1);
    CHECK(e[1].count == 3 && e[1].receive.rx.last_dropped == 1);
    CHECK(e[1].receiver.validation_error == -EBADMSG);

    /* TCP with IPv4 options traverses the same queued owner dispatch. */
    m = packet_variant(&e[0].pool, 8, IPPROTO_TCP, 4, false);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && service == 1);
    CHECK(e[1].count == 4 && e[1].ids[3] == 8 && e[1].receiver.validation_error == 0);

    /* Pending-only cancellation returns the whole original chain. */
    while (e[1].held_count < 127 &&
        (e[1].held[e[1].held_count] = ker_packet_alloc(&e[1].pool))) e[1].held_count++;
    CHECK(e[1].held_count == 127);
    m = packet(&e[0].pool, 7, false);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && !service);
    CHECK(e[1].receive.rx.pending && e[1].receive.rx.last_error == -ENOMEM);
    m = packet(&e[0].pool, 9, false);
    CHECK(ker_flow_submit(source, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && handoff == 1 && !service);
    CHECK(e[1].receive.rx.last_error == -ENOMEM);
    CHECK(ker_flow_receive_cleanup(&e[1].receive) == -EBUSY);
    struct rte_mbuf *cancelled = NULL;
    CHECK(ker_flow_receive_cancel(&e[1].receive, &cancelled) == 1 && cancelled);
    CHECK(cancelled->nb_segs == 4 && cancelled->pkt_len == 43);
    ker_packet_free(cancelled);
    while (e[1].held_count) ker_packet_free(e[1].held[--e[1].held_count]);
    CHECK(poll_worker(&e[1], &handoff, &service) == 0 && !handoff && service == 1);
    CHECK(e[1].count == 5 && e[1].ids[4] == 9);

    /* Flow attach failure occurs after RX binding; rollback releases both pins
     * and frees the local queue so its DPDK name can be reused. */
    struct ker_packet_pool dup_pool = {0}; struct ker_skb_context dup_skb = {0};
    struct ker_eth_device dup_device = {0}; struct ker_receive_runtime dup_runtime = {0};
    struct ker_worker dup_worker = {0}; struct ker_flow_receive dup_receive = {0};
    CHECK(ker_packet_pool_init(&dup_pool, "fo_dup_pool", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&dup_skb, &dup_pool, "fo_dup_skb") == 0);
    CHECK(ker_eth_device_init(&dup_device, &dup_skb, "fo_dup", 3,
        (const uint8_t[]){2,0,0,0,0,1}) == 0);
    CHECK(ker_receive_runtime_init(&dup_runtime, &dup_skb) == 0);
    struct ker_worker_config dup_wc = {.timer_budget=1, .handoff_budget=1};
    CHECK(ker_worker_init(&dup_worker, &dup_pool, &dup_wc, &(struct ker_worker_ops){0}) == 0);
    struct ker_flow_receive_config dup_rc = {.name="fo_dup_attach", .capacity=1,
        .socket_id=SOCKET_ID_ANY, .headroom=128};
    CHECK(ker_flow_receive_init(&dup_receive, &fabric, &dup_worker, 0,
        &dup_device, &dup_runtime, &dup_rc) == -EEXIST);
    CHECK(!dup_receive.initialized && !dup_receive.queue.ring && !dup_receive.rx.ring);
    CHECK(dup_device.rx_ring_live == 0 && dup_runtime.rx_ring_live == 0);
    struct ker_tx_ring reuse = {0};
    CHECK(ker_tx_ring_init(&reuse, "fo_dup_attach", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_ring_cleanup(&reuse) == 0);
    CHECK(ker_worker_cleanup(&dup_worker) == 0);
    CHECK(ker_receive_runtime_cleanup(&dup_runtime) == 0);
    CHECK(ker_eth_device_cleanup(&dup_device) == 0);
    CHECK(ker_skb_context_cleanup(&dup_skb) == 0);
    CHECK(ker_packet_pool_cleanup(&dup_pool) == 0);

    /* Invalid RX geometry fails after queue creation and rolls the queue back. */
    struct ker_flow_receive bad = {0};
    struct ker_flow_receive_config bad_config = {.name="fo_bad_headroom", .capacity=1,
        .socket_id=SOCKET_ID_ANY, .headroom=UINT16_MAX};
    CHECK(ker_flow_receive_init(&bad, &fabric, &e[0].worker, 0, &e[0].device,
        &e[0].runtime, &bad_config) < 0);
    CHECK(!bad.initialized && !bad.queue.ring && !bad.rx.ring);
    CHECK(e[0].device.rx_ring_live == 1 && e[0].runtime.rx_ring_live == 1);

    CHECK(ker_flow_receive_cleanup(&e[1].receive) == 0);
    CHECK(ker_flow_receive_cleanup(&e[0].receive) == 0);
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK(ker_worker_cleanup(&e[i].worker) == 0);
        CHECK(ker_transport_receiver_unregister(&e[i].receiver) == 0);
        CHECK(ker_receive_runtime_cleanup(&e[i].runtime) == 0);
        CHECK(ker_eth_device_cleanup(&e[i].device) == 0);
        CHECK(ker_skb_context_cleanup(&e[i].skb) == 0);
        CHECK(ker_packet_pool_cleanup(&e[i].pool) == 0);
    }
    CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
    CHECK(ker_memory_shutdown() == 0); CHECK(rte_eal_cleanup() == 0);
    puts("flow owner receive: segmented transport dispatch, overflow, pressure retry/FIFO and lifecycle passed");
    return 0;
}
