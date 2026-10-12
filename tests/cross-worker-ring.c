#include "check.h"
#include "eal.h"
#include "runtime/buffer.h"
#include "runtime/ethernet.h"
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
#include <string.h>
#include <time.h>

#define POOL_SIZE 63U
#define MAX_EXPECTED 8U
enum command { CMD_NONE, CMD_POLL, CMD_DIRECT_POLL, CMD_EXHAUST, CMD_RELEASE,
    CMD_WRONG_PRODUCER, CMD_CLEANUP };
struct expected { bool tcp; const uint8_t *bytes; size_t len; };
struct fixture {
    struct ker_tx_ring ring;
    struct ker_rx_ring rx;
    struct ker_tx_export tx;
    struct ker_packet_pool producer_pool;
    struct ker_skb_context producer_context;
    struct ker_packet_pool consumer_pool;
    struct ker_skb_context consumer_context;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_worker worker;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    enum command command;
    unsigned int argument;
    unsigned int consumer_lcore;
    bool ready, done, allow_shutdown;
    int init_result, command_result;
    unsigned int held_count, expected_count, received;
    struct rte_mbuf *held[POOL_SIZE];
    struct expected expected[MAX_EXPECTED];
    unsigned int rx_completed, rx_dropped;
    int rx_error;
};
static struct fixture f;
static const uint8_t src_mac[6] = {2, 0x10, 0, 0, 0, 1};
static const uint8_t dst_mac[6] = {2, 0x20, 0, 0, 0, 1};
static const __be32 src_ip = (__be32)0x010200c0;
static const __be32 dst_ip = (__be32)0x026433c6;
static const __be16 src_port = (__be16)0x3412;
static const __be16 dst_port = (__be16)0x7856;

static void timed_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 10;
    CHECK(pthread_cond_timedwait(cond, mutex, &deadline) == 0);
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    struct fixture *fixture = arg;
    CHECK(arg == &f && rte_lcore_id() == fixture->consumer_lcore);
    CHECK(fixture->received < fixture->expected_count);
    const struct expected *want = &fixture->expected[fixture->received];
    CHECK(message->protocol == (want->tcp ? KER_TRANSPORT_TCP : KER_TRANSPORT_UDP));
    const uint8_t *payload;
    size_t length;
    if (want->tcp) {
        CHECK(message->packet.tcp.source_port == src_port &&
            message->packet.tcp.destination_port == dst_port);
        payload = message->packet.tcp.payload;
        length = message->packet.tcp.payload_length;
    } else {
        CHECK(message->packet.udp.source_port == src_port &&
            message->packet.udp.destination_port == dst_port);
        payload = message->packet.udp.payload;
        length = message->packet.udp.payload_length;
    }
    CHECK(length == want->len && !memcmp(payload, want->bytes, length));
    fixture->received++;
    return NET_RX_SUCCESS;
}

static struct sk_buff *make_packet(struct ker_skb_context *context, bool tcp,
    bool partial, const uint8_t *payload, size_t length)
{
    struct sk_buff *skb = NULL;
    if (tcp) {
        CHECK(ker_tcp_ipv4_create(context, src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, (__be32)0x10203040, (__be32)0x50607080,
            (__be16)4096, 0x18, 61, payload, (unsigned int)length, &skb) == 0);
    } else {
        CHECK(ker_udp_ipv4_create(context, src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port, 63, payload, (unsigned int)length, &skb) == 0);
    }
    if (partial) {
        unsigned int start = ETH_HLEN + 20;
        unsigned int offset = tcp ? 16 : 6;
        unsigned int l4_length = skb->len - start;
        __wsum pseudo = csum_tcpudp_nofold(src_ip, dst_ip, l4_length,
            tcp ? IPPROTO_TCP : IPPROTO_UDP, 0);
        __sum16 seed = (__sum16)~csum_fold(pseudo);
        memcpy(skb->data + start + offset, &seed, sizeof(seed));
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
        skb->csum_offset = (uint16_t)offset;
    }
    return skb;
}

static void expect(bool tcp, const uint8_t *bytes, size_t length)
{
    CHECK(f.expected_count < MAX_EXPECTED);
    f.expected[f.expected_count++] = (struct expected){tcp, bytes, length};
}

static void send_packet(bool tcp, bool partial, const uint8_t *bytes, size_t length)
{
    struct sk_buff *skb = make_packet(&f.producer_context, tcp, partial, bytes, length);
    CHECK(ker_tx_export_enqueue(&f.tx, &skb) == 0 && !skb);
    CHECK(ker_tx_export_poll(&f.tx, 1) == 1 && !f.tx.last_error);
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
    CHECK(ker_packet_pool_init(&fixture->consumer_pool, "cross_b_pool", POOL_SIZE,
        0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&fixture->consumer_context, &fixture->consumer_pool,
        "cross_b_skb") == 0);
    CHECK(ker_eth_device_init(&fixture->device, &fixture->consumer_context,
        "crossb", 18, mac) == 0);
    CHECK(ker_receive_runtime_init(&fixture->runtime, &fixture->consumer_context) == 0);
    fixture->init_result = ker_rx_ring_init(&fixture->rx, &fixture->ring,
        &fixture->device, &fixture->runtime, 128);
    if (!fixture->init_result) {
        struct ker_rx_ring duplicate = {0};
        CHECK(ker_rx_ring_init(&duplicate, &fixture->ring, &fixture->device,
            &fixture->runtime, 128) == -EBUSY && !duplicate.ring);
        CHECK(ker_transport_receiver_register(&fixture->receiver, &fixture->runtime,
            &fixture->device, receive_message, fixture) == 0);
        struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 0,
            .rx_budget = 8, .rx_margin = 0};
        struct ker_worker_ops ops = {.rx = worker_rx, .arg = &fixture->rx};
        CHECK(ker_worker_init(&fixture->worker, &fixture->consumer_pool,
            &config, &ops) == 0);
    }
    fixture->consumer_lcore = rte_lcore_id();
    CHECK(pthread_mutex_lock(&fixture->mutex) == 0);
    fixture->ready = true;
    CHECK(pthread_cond_broadcast(&fixture->cond) == 0);
    while (fixture->command == CMD_NONE) timed_wait(&fixture->cond, &fixture->mutex);
    for (;;) {
        enum command command = fixture->command;
        unsigned int argument = fixture->argument;
        fixture->command = CMD_NONE;
        CHECK(pthread_mutex_unlock(&fixture->mutex) == 0);
        int result = 0;
        switch (command) {
        case CMD_POLL: {
            struct ker_worker_result progress = {0};
            result = ker_worker_poll(&fixture->worker, fixture->worker.timers.now_ns + 1,
                &progress);
            break;
        }
        case CMD_DIRECT_POLL:
            result = ker_rx_ring_poll(&fixture->rx, argument);
            break;
        case CMD_EXHAUST:
            while (fixture->held_count < POOL_SIZE) {
                struct rte_mbuf *mbuf = ker_packet_alloc(&fixture->consumer_pool);
                if (!mbuf) break;
                fixture->held[fixture->held_count++] = mbuf;
            }
            result = (int)fixture->held_count;
            break;
        case CMD_RELEASE:
            while (argument-- && fixture->held_count)
                ker_packet_free(fixture->held[--fixture->held_count]);
            result = (int)fixture->held_count;
            break;
        case CMD_WRONG_PRODUCER: {
            struct rte_mbuf *mbuf = ker_packet_alloc(&fixture->consumer_pool);
            CHECK(mbuf && rte_pktmbuf_append(mbuf, 1));
            result = ker_tx_ring_sink(mbuf, &fixture->ring);
            CHECK(result == -EXDEV && rte_ring_count(fixture->ring.ring) == 0);
            ker_packet_free(mbuf);
            break;
        }
        case CMD_CLEANUP:
            CHECK(!fixture->rx.pending);
            CHECK(ker_rx_ring_cleanup(&fixture->rx) == 0);
            CHECK(ker_worker_cleanup(&fixture->worker) == 0);
            CHECK(ker_transport_receiver_unregister(&fixture->receiver) == 0);
            CHECK(ker_receive_runtime_cleanup(&fixture->runtime) == 0);
            CHECK(ker_eth_device_cleanup(&fixture->device) == 0);
            CHECK(ker_skb_context_cleanup(&fixture->consumer_context) == 0);
            CHECK(ker_packet_pool_cleanup(&fixture->consumer_pool) == 0);
            CHECK(fixture->held_count == 0);
            result = 0;
            break;
        default:
            CHECK(false);
        }
        CHECK(pthread_mutex_lock(&fixture->mutex) == 0);
        fixture->command_result = result;
        fixture->rx_completed = fixture->rx.last_completed;
        fixture->rx_dropped = fixture->rx.last_dropped;
        fixture->rx_error = fixture->rx.last_error;
        fixture->done = true;
        pthread_cond_broadcast(&fixture->cond);
        if (command == CMD_CLEANUP) {
            while (!fixture->allow_shutdown) timed_wait(&fixture->cond, &fixture->mutex);
            CHECK(pthread_mutex_unlock(&fixture->mutex) == 0);
            CHECK(ker_memory_shutdown() == 0);
            rte_thread_unregister();
            return NULL;
        }
        while (fixture->command == CMD_NONE) timed_wait(&fixture->cond, &fixture->mutex);
        fixture->done = false;
    }
}

static int command(enum command command, unsigned int argument)
{
    CHECK(pthread_mutex_lock(&f.mutex) == 0);
    f.command = command;
    f.argument = argument;
    f.done = false;
    CHECK(pthread_cond_broadcast(&f.cond) == 0);
    while (!f.done) timed_wait(&f.cond, &f.mutex);
    int result = f.command_result;
    CHECK(pthread_mutex_unlock(&f.mutex) == 0);
    return result;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&f.producer_pool, "cross_a_pool", 127, 0,
        4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&f.producer_context, &f.producer_pool,
        "cross_a_skb") == 0);
    CHECK(ker_tx_ring_init(&f.ring, "cross_worker_ring", 8, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init_chain_software_checksum(&f.tx, &f.producer_context,
        8, SIZE_MAX, 16, ker_tx_ring_sink, &f.ring) == 0);
    CHECK(pthread_mutex_init(&f.mutex, NULL) == 0);
    CHECK(pthread_cond_init(&f.cond, NULL) == 0);
    pthread_t consumer;
    CHECK(pthread_create(&consumer, NULL, consumer_main, &f) == 0);
    CHECK(pthread_mutex_lock(&f.mutex) == 0);
    while (!f.ready) timed_wait(&f.cond, &f.mutex);
    CHECK(pthread_mutex_unlock(&f.mutex) == 0);
    CHECK(f.init_result == 0 && f.consumer_lcore != f.ring.owner_lcore);

    CHECK(ker_tx_ring_cleanup(&f.ring) == -EBUSY);
    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_tx_ring_take(&f.ring, &sentinel) == -EBUSY && sentinel == (void *)(uintptr_t)1);
    CHECK(ker_rx_ring_poll(&f.rx, 1) == -EXDEV);
    CHECK(ker_rx_ring_cancel(&f.rx, &sentinel) == -EXDEV && sentinel == (void *)(uintptr_t)1);
    CHECK(ker_rx_ring_cleanup(&f.rx) == -EXDEV && f.rx.ring == &f.ring);
    CHECK(command(CMD_WRONG_PRODUCER, 0) == -EXDEV);

    static const uint8_t udp[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t tcp[] = {0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37};
    expect(false, udp, sizeof(udp));
    send_packet(false, false, udp, sizeof(udp));
    CHECK(ker_packet_pool_cleanup(&f.producer_pool) == -EBUSY);
    CHECK(command(CMD_POLL, 0) == 0 && f.received == 1);
    expect(true, tcp, sizeof(tcp));
    send_packet(true, true, tcp, sizeof(tcp));
    CHECK(command(CMD_POLL, 0) == 0 && f.received == 2);

    static const uint8_t pending[] = {1, 3, 5, 7};
    static const uint8_t later[] = {2, 4, 6, 8};
    expect(false, pending, sizeof(pending));
    send_packet(false, false, pending, sizeof(pending));
    CHECK(command(CMD_EXHAUST, 0) > 0);
    CHECK(command(CMD_DIRECT_POLL, 1) == -ENOMEM && f.rx_error == -ENOMEM &&
        f.rx_completed == 0 && f.rx.pending && f.rx.pending->nb_segs > 1);
    uint32_t pending_bytes = 0;
    unsigned int pending_segments = 0;
    for (struct rte_mbuf *segment = f.rx.pending; segment; segment = segment->next) {
        pending_bytes += segment->data_len;
        pending_segments++;
    }
    CHECK(pending_segments == f.rx.pending->nb_segs && pending_bytes == f.rx.pending->pkt_len);
    expect(false, later, sizeof(later));
    send_packet(false, false, later, sizeof(later));
    CHECK(command(CMD_RELEASE, 4) >= 0);
    CHECK(command(CMD_POLL, 0) == 0);
    CHECK(f.received == 4 && !f.rx.pending && rte_ring_count(f.ring.ring) == 0);
    CHECK(command(CMD_RELEASE, POOL_SIZE) == 0);

    CHECK(command(CMD_CLEANUP, 0) == 0);
    CHECK(ker_tx_export_cleanup(&f.tx) == 0);
    CHECK(ker_skb_context_cleanup(&f.producer_context) == 0);
    CHECK(ker_packet_pool_cleanup(&f.producer_pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(pthread_mutex_lock(&f.mutex) == 0);
    f.allow_shutdown = true;
    pthread_cond_broadcast(&f.cond);
    CHECK(pthread_mutex_unlock(&f.mutex) == 0);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(ker_tx_ring_cleanup(&f.ring) == 0);
    CHECK(pthread_cond_destroy(&f.cond) == 0);
    CHECK(pthread_mutex_destroy(&f.mutex) == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
