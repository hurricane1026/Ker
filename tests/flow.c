#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <linux/irqflags.h>
#include <linux/slab.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_lcore.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <errno.h>
#include <string.h>

struct test_state {
    struct ker_packet_pool pool;
    struct ker_flow_fabric fabric;
    struct ker_worker workers[3];
    struct ker_flow_context contexts[3];
    pthread_barrier_t barrier;
    pthread_mutex_t setup_lock;
    atomic_uint delivered;
    atomic_int callback_error;
    atomic_bool stream_done;
    atomic_uint stream_polls;
    unsigned int destination_lcore;
    unsigned int main_lcore;
};
struct receive_expect {
    struct test_state *state;
    struct ker_flow_context *context;
    struct ker_worker *worker;
    unsigned int lcore;
};

static struct rte_mbuf *udp_packet(struct ker_packet_pool *pool, bool reverse)
{
    struct rte_mbuf *packet = ker_packet_alloc(pool);
    CHECK(packet != NULL);
    uint8_t *bytes = (uint8_t *)rte_pktmbuf_append(packet, 42);
    CHECK(bytes != NULL);
    memset(bytes, 0, 42);
    bytes[12] = 0x08; bytes[13] = 0x00;
    uint8_t *ip = bytes + 14;
    ip[0] = 0x45; ip[2] = 0; ip[3] = 28; ip[8] = 64; ip[9] = IPPROTO_UDP;
    ip[12] = reverse ? 10 : 192; ip[13] = reverse ? 0 : 0; ip[14] = reverse ? 0 : 2; ip[15] = reverse ? 1 : 1;
    ip[16] = reverse ? 192 : 10; ip[17] = reverse ? 0 : 0; ip[18] = reverse ? 2 : 0; ip[19] = 1;
    uint8_t *udp = ip + 20;
    uint16_t src = reverse ? 443 : 1234, dst = reverse ? 1234 : 443;
    udp[0] = (uint8_t)(src >> 8); udp[1] = (uint8_t)src;
    udp[2] = (uint8_t)(dst >> 8); udp[3] = (uint8_t)dst;
    udp[4] = 0; udp[5] = 8;
    return packet;
}

static struct rte_mbuf *ipv4_tcp_packet(struct ker_packet_pool *pool)
{
    struct rte_mbuf *packet = ker_packet_alloc(pool);
    CHECK(packet != NULL);
    uint8_t *bytes = (uint8_t *)rte_pktmbuf_append(packet, 54);
    CHECK(bytes != NULL); memset(bytes, 0, 54);
    bytes[12] = 0x08; bytes[13] = 0x00;
    uint8_t *ip = bytes + 14;
    ip[0] = 0x45; ip[2] = 0; ip[3] = 40; ip[8] = 64; ip[9] = IPPROTO_TCP;
    ip[12] = 192; ip[14] = 2; ip[15] = 1; ip[16] = 10; ip[19] = 1;
    uint8_t *tcp = ip + 20;
    tcp[0] = 0x04; tcp[1] = 0xd2; tcp[2] = 0x01; tcp[3] = 0xbb; tcp[12] = 0x50;
    return packet;
}

static struct rte_mbuf *ipv6_packet(struct ker_packet_pool *pool, uint8_t protocol)
{
    size_t transport_length = protocol == IPPROTO_TCP ? 20 : 8;
    struct rte_mbuf *packet = ker_packet_alloc(pool);
    CHECK(packet != NULL);
    uint8_t *bytes = (uint8_t *)rte_pktmbuf_append(packet, (uint16_t)(14 + 40 + transport_length));
    CHECK(bytes != NULL); memset(bytes, 0, 14 + 40 + transport_length);
    bytes[12] = 0x86; bytes[13] = 0xdd;
    uint8_t *ip = bytes + 14;
    ip[0] = 0x60; ip[4] = 0; ip[5] = (uint8_t)transport_length; ip[6] = protocol; ip[7] = 64;
    ip[8] = 0x20; ip[23] = 1; ip[24] = 0x20; ip[39] = 2;
    uint8_t *transport = ip + 40;
    transport[0] = 0x04; transport[1] = 0xd2; transport[2] = 0x01; transport[3] = 0xbb;
    if (protocol == IPPROTO_TCP) transport[12] = 0x50;
    else { transport[4] = 0; transport[5] = 8; }
    return packet;
}

static void receive(void *arg, const struct ker_flow_key *key, struct rte_mbuf *packet)
{
    struct receive_expect *expect = arg;
    struct test_state *state = expect->state;
    if (rte_lcore_id() != expect->lcore || key->family != 4 ||
        key->protocol != IPPROTO_UDP || key->local_port != 443 || key->remote_port != 1234)
        atomic_store(&state->callback_error, 1);
    struct ker_worker_result nested = {.rx = 99};
    if (ker_flow_poll(expect->context, 1) != -EBUSY ||
        ker_worker_poll(expect->worker, expect->worker->timers.now_ns, &nested) != -EBUSY || nested.rx != 99)
        atomic_store(&state->callback_error, 2);
    atomic_fetch_add(&state->delivered, 1);
    rte_pktmbuf_free(packet);
}

static void barrier(struct test_state *state)
{
    int error = pthread_barrier_wait(&state->barrier);
    CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
}

static int rx_probe(void *arg, unsigned int budget)
{
    unsigned int *calls = arg;
    CHECK(budget == 1);
    ++*calls;
    return 0;
}

static void *destination_thread(void *arg)
{
    struct test_state *state = arg;
    CHECK(rte_thread_register() == 0);
    state->destination_lcore = rte_lcore_id();
    CHECK(state->destination_lcore != rte_get_main_lcore());
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_memory_budget_config pressure_config = {RTE_CACHE_LINE_SIZE, RTE_CACHE_LINE_SIZE, 0};
    CHECK(ker_memory_budget_configure(KER_MEMORY_CONTROL, &pressure_config) == 0);
    unsigned int rx_calls = 0;
    struct ker_worker_config config = {.timer_budget = 1, .handoff_budget = 2, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = rx_probe, .arg = &rx_calls};
    CHECK(ker_worker_init(&state->workers[1], &state->pool, &config, &ops) == 0);
    struct receive_expect expect = {.state = state, .context = &state->contexts[1],
        .worker = &state->workers[1], .lcore = state->destination_lcore};
    CHECK(pthread_mutex_lock(&state->setup_lock) == 0);
    CHECK(ker_flow_attach(&state->contexts[1], &state->fabric, &state->workers[1], 1,
        receive, &expect) == 0);
    CHECK(pthread_mutex_unlock(&state->setup_lock) == 0);
    barrier(state); /* All workers attached; both producer lcores may start together. */
    barrier(state); /* Both first enqueues completed. */
    barrier(state); /* Main verified full-ring retention before the owner drains. */
    barrier(state); /* Main completed its pool/fabric teardown checks. */
    CHECK(ker_flow_detach(&state->contexts[1]) == -EBUSY);
    void *pressure = kmalloc(1, GFP_KERNEL);
    CHECK(pressure != NULL);
    struct ker_worker_result result;
    CHECK(ker_worker_poll(&state->workers[1], 1, &result) == 0);
    CHECK(result.handoff == 2);
    CHECK(result.pressure & (1U << KER_MEMORY_CONTROL));
    CHECK(result.rx == 0 && rx_calls == 0);
    kfree(pressure);
    barrier(state); /* Owner delivered all queued mbufs. */
    while (!atomic_load(&state->stream_done) || atomic_load(&state->delivered) < 35) {
        CHECK(ker_worker_poll(&state->workers[1], 1, &result) == 0);
        atomic_fetch_add(&state->stream_polls, 1);
        sched_yield();
    }
    barrier(state); /* Concurrent streaming stage is complete. */
    barrier(state); /* Producers detached after their final enqueue. */
    CHECK(ker_flow_detach(&state->contexts[1]) == 0);
    CHECK(ker_worker_cleanup(&state->workers[1]) == 0);
    CHECK(ker_memory_shutdown() == 0);
    rte_thread_unregister();
    return NULL;
}

static void *second_producer_thread(void *arg)
{
    struct test_state *state = arg;
    CHECK(rte_thread_register() == 0);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .handoff_budget = 2};
    struct ker_worker_ops ops = {0};
    CHECK(ker_worker_init(&state->workers[2], &state->pool, &config, &ops) == 0);
    struct receive_expect expect = {.state = state, .context = &state->contexts[2],
        .worker = &state->workers[2], .lcore = rte_lcore_id()};
    CHECK(pthread_mutex_lock(&state->setup_lock) == 0);
    CHECK(ker_flow_attach(&state->contexts[2], &state->fabric, &state->workers[2], 2,
        receive, &expect) == 0);
    CHECK(pthread_mutex_unlock(&state->setup_lock) == 0);
    struct ker_flow_key key = {.domain = 7, .family = 4, .protocol = IPPROTO_UDP};
    unsigned int owner;
    CHECK(ker_flow_owner(&state->contexts[0], &key, &owner) == -EXDEV);
    barrier(state);
    struct rte_mbuf *packet = udp_packet(&state->pool, false);
    barrier(state); /* Synchronize both producers immediately before enqueue. */
    CHECK(ker_flow_submit(&state->contexts[2], 7, KER_FLOW_INGRESS, &packet) == 0 && packet == NULL);
    barrier(state);
    barrier(state);
    barrier(state); /* Initial target drain completed. */
    for (unsigned int i = 0; i < 32; ++i) {
        struct rte_mbuf *packet = udp_packet(&state->pool, false);
        int error;
        do {
            error = ker_flow_submit(&state->contexts[2], 7, KER_FLOW_INGRESS, &packet);
            if (error == -ENOBUFS) sched_yield();
        } while (error == -ENOBUFS);
        CHECK(error == 0 && packet == NULL);
    }
    atomic_store(&state->stream_done, true);
    barrier(state);
    CHECK(ker_flow_detach(&state->contexts[2]) == 0);
    CHECK(ker_worker_cleanup(&state->workers[2]) == 0);
    CHECK(ker_memory_shutdown() == 0);
    barrier(state);
    rte_thread_unregister();
    return NULL;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct test_state state = {0};
    CHECK(ker_packet_pool_init(&state.pool, "ker_flow_packets", 31, 0, 256, SOCKET_ID_ANY) == 0);
    struct ker_flow_key ingress, egress, udp_key;
    struct rte_mbuf *sample = udp_packet(&state.pool, false);
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &ingress) == 0);
    rte_pktmbuf_free(sample);
    sample = udp_packet(&state.pool, true);
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_EGRESS, &egress) == 0);
    CHECK(ingress.domain == egress.domain && ingress.family == egress.family &&
        ingress.protocol == egress.protocol && !memcmp(ingress.local, egress.local, 16) &&
        !memcmp(ingress.remote, egress.remote, 16) && ingress.local_port == egress.local_port &&
        ingress.remote_port == egress.remote_port);
    udp_key = ingress;
    rte_pktmbuf_free(sample);
    struct ker_flow_key untouched = {.domain = 55, .family = 6, .protocol = IPPROTO_TCP};
    sample = udp_packet(&state.pool, false);
    uint8_t *raw = rte_pktmbuf_mtod(sample, uint8_t *);
    raw[20] = 0x20; raw[21] = 0; /* IPv4 more-fragments bit */
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -ENOTSUP);
    CHECK(untouched.domain == 55 && untouched.family == 6 && untouched.protocol == IPPROTO_TCP);
    raw[20] = raw[21] = 0; raw[12] = 0x81; raw[13] = 0x00;
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -ENOTSUP);
    CHECK(ker_flow_parse(sample, 7, (enum ker_flow_direction)-1, &untouched) == -EINVAL);
    sample->ol_flags |= RTE_MBUF_F_RX_VLAN_STRIPPED;
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -ENOTSUP);
    rte_pktmbuf_free(sample);
    sample = ipv4_tcp_packet(&state.pool);
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &ingress) == 0 &&
        ingress.family == 4 && ingress.protocol == IPPROTO_TCP);
    uint8_t *tcp_bytes = rte_pktmbuf_mtod(sample, uint8_t *);
    tcp_bytes[46] = 0x40;
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -EINVAL);
    tcp_bytes[46] = 0x50;
    tcp_bytes[16] = 0; tcp_bytes[17] = 60;
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -EMSGSIZE);
    rte_pktmbuf_free(sample);
    sample = ipv6_packet(&state.pool, IPPROTO_UDP);
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &ingress) == 0 &&
        ingress.family == 6 && ingress.protocol == IPPROTO_UDP);
    rte_pktmbuf_free(sample);
    sample = ipv6_packet(&state.pool, IPPROTO_TCP);
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &ingress) == 0 &&
        ingress.family == 6 && ingress.protocol == IPPROTO_TCP);
    uint8_t *ipv6_bytes = rte_pktmbuf_mtod(sample, uint8_t *);
    ipv6_bytes[20] = 0; /* IPv6 extension header in the fixed header's next-header field. */
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -ENOTSUP);
    ipv6_bytes[20] = IPPROTO_TCP; ipv6_bytes[19] = 60;
    CHECK(ker_flow_parse(sample, 7, KER_FLOW_INGRESS, &untouched) == -EMSGSIZE);
    rte_pktmbuf_free(sample);
    ingress = udp_key;
    uint16_t owners[KER_FLOW_BUCKETS];
    for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i) owners[i] = 1;
    struct ker_flow_key local_key = ingress;
    local_key.domain = 8;
    struct ker_flow_key unavailable_key = ingress;
    unavailable_key.domain = 10;
    struct ker_flow_special special[3] = {{.key = ingress, .owner = 1},
        {.key = local_key, .owner = 0}, {.key = unavailable_key, .owner = 2}};
    struct ker_flow_config fc = {.worker_count = 3, .bucket_owner = owners,
        .seed = UINT64_C(0x123456789abcdef0), .special = special, .special_count = 3,
        .inbox_capacity = 2,
        .name = "ker_flow_test", .socket_id = SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&state.fabric, &fc) == 0);
    memset(owners, 0, sizeof(owners));
    special[0].key.domain = 999; special[0].owner = 0;
    special[1].key.domain = 998; special[1].owner = 1;
    special[2].key.domain = 997; special[2].owner = 1;
    uint32_t a, b;
    CHECK(ker_flow_hash(&ingress, fc.seed, &a) == 0 && a == UINT32_C(0xcccabd24));
    CHECK(ker_flow_hash(&ingress, fc.seed, &b) == 0 && a == b);

    struct ker_worker_config config = {.timer_budget = 1, .handoff_budget = 2};
    struct ker_worker_ops ops = {0};
    CHECK(ker_worker_init(&state.workers[0], &state.pool, &config, &ops) == 0);
    state.main_lcore = rte_lcore_id();
    struct receive_expect local_expect = {.state = &state, .context = &state.contexts[0],
        .worker = &state.workers[0], .lcore = state.main_lcore};
    CHECK(ker_flow_attach(&state.contexts[0], &state.fabric, &state.workers[0], 0,
        receive, &local_expect) == 0);
    unsigned int resolved;
    CHECK(ker_flow_owner(&state.contexts[0], &ingress, &resolved) == 0 && resolved == 1);
    CHECK(ker_flow_owner(&state.contexts[0], &local_key, &resolved) == 0 && resolved == 0);
    CHECK(ker_flow_owner(&state.contexts[0], &unavailable_key, &resolved) == 0 && resolved == 2);
    struct ker_flow_key ordinary = ingress; ordinary.domain = 9;
    CHECK(ker_flow_owner(&state.contexts[0], &ordinary, &resolved) == 0 && resolved == 1);
    CHECK(ker_worker_cleanup(&state.workers[0]) == -EBUSY);
    struct rte_mbuf *not_ready = udp_packet(&state.pool, false);
    CHECK(ker_flow_submit(&state.contexts[0], 10, KER_FLOW_INGRESS, &not_ready) == -ESHUTDOWN);
    CHECK(not_ready != NULL);
    rte_pktmbuf_free(not_ready);
    unsigned long flags;
    struct rte_mbuf *masked = udp_packet(&state.pool, false);
    local_irq_save(flags);
    CHECK(ker_flow_submit(&state.contexts[0], 7, KER_FLOW_INGRESS, &masked) == -EBUSY && masked != NULL);
    CHECK(ker_flow_poll(&state.contexts[0], 1) == -EBUSY);
    local_irq_restore(flags);
    rte_pktmbuf_free(masked);
    CHECK(pthread_barrier_init(&state.barrier, NULL, 3) == 0);
    CHECK(pthread_mutex_init(&state.setup_lock, NULL) == 0);
    pthread_t thread, producer;
    CHECK(pthread_create(&thread, NULL, destination_thread, &state) == 0);
    CHECK(pthread_create(&producer, NULL, second_producer_thread, &state) == 0);
    barrier(&state);

    struct rte_mbuf *local_packet = udp_packet(&state.pool, false);
    CHECK(ker_flow_submit(&state.contexts[0], 8, KER_FLOW_INGRESS, &local_packet) == 0 && local_packet == NULL);
    CHECK(atomic_load(&state.delivered) == 1);

    struct rte_mbuf *packets[2];
    for (unsigned int i = 0; i < 2; ++i) packets[i] = udp_packet(&state.pool, false);
    barrier(&state); /* Both producers become runnable at the same time. */
    CHECK(ker_flow_submit(&state.contexts[0], 7, KER_FLOW_INGRESS, &packets[0]) == 0 && packets[0] == NULL);
    barrier(&state); /* The second lcore enqueued concurrently to this same ring. */
    CHECK(ker_flow_submit(&state.contexts[0], 7, KER_FLOW_INGRESS, &packets[1]) == -ENOBUFS && packets[1] != NULL);
    rte_pktmbuf_free(packets[1]);
    CHECK(ker_flow_fabric_cleanup(&state.fabric) == -EBUSY);
    CHECK(ker_packet_pool_cleanup(&state.pool) == -EBUSY);
    barrier(&state);
    barrier(&state);
    barrier(&state); /* Concurrent streaming stage completed. */
    CHECK(atomic_load(&state.delivered) == 35 && atomic_load(&state.callback_error) == 0);
    CHECK(atomic_load(&state.stream_polls) > 0);
    CHECK(ker_flow_detach(&state.contexts[0]) == 0);
    CHECK(ker_worker_cleanup(&state.workers[0]) == 0);
    barrier(&state);
    CHECK(pthread_join(producer, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(pthread_barrier_destroy(&state.barrier) == 0);
    CHECK(ker_flow_fabric_cleanup(&state.fabric) == 0);
    CHECK(ker_packet_pool_cleanup(&state.pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Flow steering: canonical seeded tuples, bounded cross-lcore handoff and worker poll delivery passed");
    return 0;
}
