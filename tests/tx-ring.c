#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/tcp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <net/checksum.h>
#include <pthread.h>
#include <netinet/in.h>
#include <rte_ring.h>
#include <string.h>

#define RING_POOL_SIZE 127U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_tx_ring ring;
static struct ker_tx_export tx;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static const uint8_t source_mac[6] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const uint8_t destination_mac[6] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x026433c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;
static enum ker_transport_protocol expected_protocol[2];
static uint8_t expected_payload[2][16];
static unsigned int expected_payload_length[2];
static unsigned int received;

struct consumer_call {
    struct ker_tx_ring *ring;
    const uint8_t *expected;
    size_t length;
    int result;
};
struct producer_call { struct ker_tx_ring *ring; struct rte_mbuf *packet; int result; };

static void *foreign_producer(void *arg)
{
    struct producer_call *call = arg;
    struct rte_mbuf *packet = call->packet;
    call->result = ker_tx_ring_sink(packet, call->ring);
    CHECK(call->result == -EXDEV && packet == call->packet);
    return NULL;
}

static void *pthread_consumer(void *arg)
{
    struct consumer_call *call = arg;
    struct rte_mbuf *packet = (void *)(uintptr_t)1;
    call->result = ker_tx_ring_take(call->ring, &packet);
    if (call->result != 1 || !packet || packet == (void *)(uintptr_t)1) {
        call->result = -1;
    } else {
        uint8_t bytes[64];
        size_t copied = 0;
        unsigned int segments = 0;
        for (struct rte_mbuf *part = packet; part; part = part->next) {
            if (copied + part->data_len > sizeof(bytes)) { call->result = -1; break; }
            memcpy(bytes + copied, rte_pktmbuf_mtod(part, const void *), part->data_len);
            copied += part->data_len;
            segments++;
        }
        if (packet->pkt_len != call->length || packet->nb_segs < 2 ||
            segments != packet->nb_segs || copied != call->length ||
            memcmp(bytes, call->expected, call->length))
            call->result = -1;
        ker_packet_free(packet);
    }
    return NULL;
}

static struct rte_mbuf *test_mbuf(const uint8_t *bytes, size_t length)
{
    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    CHECK(packet);
    void *data = rte_pktmbuf_append(packet, (uint16_t)length);
    CHECK(data);
    memcpy(data, bytes, length);
    return packet;
}

static struct rte_mbuf *test_chain(const uint8_t *bytes, size_t length)
{
    CHECK(length >= 2 && length <= UINT16_MAX);
    struct rte_mbuf *head = NULL;
    struct rte_mbuf **tail = &head;
    for (size_t i = 0; i < length; i++) {
        struct rte_mbuf *part = test_mbuf(bytes + i, 1);
        *tail = part;
        tail = &part->next;
    }
    head->pkt_len = (uint32_t)length;
    head->nb_segs = (uint16_t)length;
    return head;
}

static uint16_t oracle_checksum(const uint8_t *bytes, size_t length)
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

static void verify_transport_checksum(const struct rte_mbuf *chain, bool tcp)
{
    uint8_t frame[256];
    CHECK(chain && chain->pkt_len <= sizeof(frame));
    size_t copied = 0;
    unsigned int segments = 0;
    for (const struct rte_mbuf *part = chain; part; part = part->next) {
        CHECK(part->ol_flags == 0 && copied + part->data_len <= sizeof(frame));
        memcpy(frame + copied, rte_pktmbuf_mtod(part, const void *), part->data_len);
        copied += part->data_len;
        segments++;
    }
    CHECK(copied == chain->pkt_len && segments == chain->nb_segs && segments > 1);
    uint8_t *ip = frame + ETH_HLEN;
    uint8_t *l4 = ip + 20;
    size_t l4len = chain->pkt_len - ETH_HLEN - 20;
    uint8_t pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    pseudo[10] = (uint8_t)(l4len >> 8);
    pseudo[11] = (uint8_t)l4len;
    uint8_t input[268];
    memcpy(input, pseudo, sizeof(pseudo));
    memcpy(input + sizeof(pseudo), l4, l4len);
    CHECK(oracle_checksum(input, sizeof(pseudo) + l4len) == 0);
}

static struct sk_buff *partial_packet(bool tcp, const uint8_t *payload,
    unsigned int payload_length)
{
    struct sk_buff *skb = NULL;
    if (tcp) {
        CHECK(ker_tcp_ipv4_create(&context, source_mac, destination_mac,
            source_ip, destination_ip, source_port, destination_port,
            (__be32)0x10203040, (__be32)0x50607080, (__be16)4096, 0x18,
            61, payload, payload_length, &skb) == 0);
    } else {
        CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac,
            source_ip, destination_ip, source_port, destination_port,
            63, payload, payload_length, &skb) == 0);
    }
    unsigned int start = ETH_HLEN + 20;
    unsigned int offset = tcp ? 16 : 6;
    unsigned int l4_length = skb->len - start;
    __wsum pseudo = csum_tcpudp_nofold(source_ip, destination_ip, l4_length,
        tcp ? IPPROTO_TCP : IPPROTO_UDP, 0);
    __sum16 seed = (__sum16)~csum_fold(pseudo);
    CHECK(seed != 0);
    memcpy(skb->data + start + offset, &seed, sizeof(seed));
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
    skb->csum_offset = (uint16_t)offset;
    return skb;
}

static int receive_packet(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling && received < 2);
    unsigned int index = received;
    CHECK(message->protocol == expected_protocol[index]);
    if (message->protocol == KER_TRANSPORT_UDP) {
        CHECK(message->packet.udp.source_port == source_port &&
            message->packet.udp.destination_port == destination_port);
        CHECK(message->packet.udp.payload_length == expected_payload_length[index]);
        CHECK(!memcmp(message->packet.udp.payload, expected_payload[index],
            expected_payload_length[index]));
    } else {
        CHECK(message->packet.tcp.source_port == source_port &&
            message->packet.tcp.destination_port == destination_port);
        CHECK(message->packet.tcp.payload_length == expected_payload_length[index]);
        CHECK(!memcmp(message->packet.tcp.payload, expected_payload[index],
            expected_payload_length[index]));
    }
    received++;
    return NET_RX_SUCCESS;
}

static int receive_ring(void *arg, unsigned int budget)
{
    CHECK(arg == &tx && budget == 1);
    struct rte_mbuf *chain = (void *)(uintptr_t)1;
    int result = ker_tx_ring_take(&ring, &chain);
    CHECK(result == 1 && chain != (void *)(uintptr_t)1);
    verify_transport_checksum(chain, expected_protocol[received] == KER_TRANSPORT_TCP);
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, 128, &skb) == 0);
    ker_packet_free(chain);
    struct ker_receive_result dispatched = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &dispatched) == 0 && !skb);
    CHECK(dispatched.handlers == 1 && dispatched.status == NET_RX_SUCCESS);
    return 1;
}

static void ring_boundaries(void)
{
    struct ker_tx_ring cap_one = {0}, duplicate = {.owner_lcore = 42};
    CHECK(ker_tx_ring_init(&cap_one, "ker_ring_exact_one", 1, SOCKET_ID_ANY) == 0);
    uint8_t first_bytes[] = {0x11, 0x22, 0x33};
    uint8_t second_bytes[] = {0x44, 0x55, 0x66};
    struct rte_mbuf *first = test_chain(first_bytes, sizeof(first_bytes));
    struct rte_mbuf *second = test_mbuf(second_bytes, sizeof(second_bytes));
    struct rte_mbuf *out = (void *)(uintptr_t)1;
    CHECK(ker_tx_ring_take(&cap_one, &out) == 0 && out == (void *)(uintptr_t)1);
    CHECK(ker_tx_ring_sink(first, &cap_one) == 0);
    CHECK(ker_tx_ring_init(&duplicate, "ker_ring_exact_one", 1, SOCKET_ID_ANY) == -EEXIST);
    CHECK(!duplicate.ring && duplicate.owner_lcore == 42);
    CHECK(ker_tx_ring_cleanup(&cap_one) == -EBUSY);
    CHECK(ker_packet_pool_cleanup(&pool) == -EBUSY);

    pthread_t producer;
    struct producer_call producer_call = {.ring = &cap_one, .packet = second};
    CHECK(pthread_create(&producer, NULL, foreign_producer, &producer_call) == 0);
    CHECK(pthread_join(producer, NULL) == 0 && producer_call.result == -EXDEV);
    CHECK(ker_tx_ring_sink(second, &cap_one) == -EAGAIN);
    CHECK(second->pkt_len == sizeof(second_bytes) &&
        !memcmp(rte_pktmbuf_mtod(second, const void *), second_bytes, sizeof(second_bytes)));
    struct consumer_call call = {.ring = &cap_one, .expected = first_bytes,
        .length = sizeof(first_bytes)};
    pthread_t consumer;
    CHECK(pthread_create(&consumer, NULL, pthread_consumer, &call) == 0);
    CHECK(pthread_join(consumer, NULL) == 0 && call.result == 1);
    CHECK(ker_tx_ring_take(&cap_one, &out) == 0 && out == (void *)(uintptr_t)1);
    CHECK(ker_tx_ring_sink(second, &cap_one) == 0);
    CHECK(ker_tx_ring_take(&cap_one, &out) == 1 && out == second);
    CHECK(!memcmp(rte_pktmbuf_mtod(out, const void *), second_bytes, sizeof(second_bytes)));
    ker_packet_free(out);
    CHECK(ker_tx_ring_cleanup(&cap_one) == 0);
    struct ker_tx_ring reused = {0};
    CHECK(ker_tx_ring_init(&reused, "ker_ring_exact_one", 1, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_ring_cleanup(&reused) == 0);

    struct ker_tx_ring cap_two = {0};
    CHECK(ker_tx_ring_init(&cap_two, "ker_ring_exact_two", 2, SOCKET_ID_ANY) == 0);
    first = test_mbuf(first_bytes, sizeof(first_bytes));
    second = test_mbuf(second_bytes, sizeof(second_bytes));
    struct rte_mbuf *third = test_mbuf(first_bytes, sizeof(first_bytes));
    CHECK(ker_tx_ring_sink(first, &cap_two) == 0 && ker_tx_ring_sink(second, &cap_two) == 0);
    CHECK(ker_tx_ring_sink(third, &cap_two) == -EAGAIN);
    CHECK(ker_tx_ring_take(&cap_two, &out) == 1 && out == first); ker_packet_free(out);
    CHECK(ker_tx_ring_take(&cap_two, &out) == 1 && out == second); ker_packet_free(out);
    CHECK(ker_tx_ring_take(&cap_two, &out) == 0 && out == second);
    ker_packet_free(third);
    CHECK(ker_tx_ring_cleanup(&cap_two) == 0);
}

static void worker_ring_retry(void)
{
    static const uint8_t udp_payload[] = {1, 3, 5, 7, 9};
    static const uint8_t tcp_payload[] = {2, 4, 6, 8, 10, 12, 14};
    memcpy(expected_payload[0], udp_payload, sizeof(udp_payload));
    memcpy(expected_payload[1], tcp_payload, sizeof(tcp_payload));
    expected_payload_length[0] = sizeof(udp_payload);
    expected_payload_length[1] = sizeof(tcp_payload);
    expected_protocol[0] = KER_TRANSPORT_UDP;
    expected_protocol[1] = KER_TRANSPORT_TCP;
    struct sk_buff *udp = NULL;
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port, 63,
        udp_payload, sizeof(udp_payload), &udp) == 0);
    struct sk_buff *tcp = partial_packet(true, tcp_payload, sizeof(tcp_payload));
    CHECK(ker_tx_export_init_chain_software_checksum(&tx, &context, 2,
        SIZE_MAX, 13, ker_tx_ring_sink, &ring) == 0);
    CHECK(ker_tx_export_enqueue(&tx, &udp) == 0 && !udp);
    CHECK(ker_tx_export_enqueue(&tx, &tcp) == 0 && !tcp);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 2, .rx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .rx = receive_ring, .arg = &tx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, 1, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && received == 1);
    CHECK(tx.last_completed == 1 && tx.last_error == -EAGAIN && tx.pending &&
        tx.packets == 1 && tx.bytes == tx.pending->truesize);
    CHECK(rte_ring_empty(ring.ring) && context.live == 1);
    CHECK(ker_worker_poll(&worker, 2, &progress) == 0);
    CHECK(progress.tx == 1 && progress.rx == 1 && received == 2);
    CHECK(!tx.pending && !tx.packets && !tx.bytes && context.live == 0);
    CHECK(rte_ring_empty(ring.ring));
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tx_ring_pool", RING_POOL_SIZE, 0,
        4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tx_ring_skb") == 0);
    struct ker_tx_ring invalid = {0};
    CHECK(ker_tx_ring_init(&invalid, "", 1, SOCKET_ID_ANY) == -EINVAL);
    CHECK(ker_tx_ring_init(&invalid, "invalid-zero", 0, SOCKET_ID_ANY) == -EINVAL);
    CHECK(ker_tx_ring_init(&invalid, "invalid-large", 65536, SOCKET_ID_ANY) == -EOVERFLOW);
    int bad_socket = ker_tx_ring_init(&invalid, "invalid-socket", 1, INT_MAX);
    CHECK(bad_socket < 0);
    CHECK(!invalid.ring && !invalid.owner_lcore);
    CHECK(ker_tx_ring_cleanup(&invalid) == -EINVAL);
    CHECK(ker_tx_ring_init(&ring, "ker_tx_ring_worker", 1, SOCKET_ID_ANY) == 0);
    ring_boundaries();
    CHECK(ker_eth_device_init(&device, &context, "ring0", 11, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device,
        receive_packet, &receiver) == 0);
    worker_ring_retry();
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_tx_ring_cleanup(&ring) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
