#include "check.h"
#include "eal.h"
#include "runtime/udp-create.h"
#include "runtime/ethernet.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <errno.h>

#define PAYLOAD_MAX 32
#define FRAME_MAX (ETH_HLEN + 20 + 8 + PAYLOAD_MAX)
#define UDP_PROTOCOL 17U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct rte_mbuf *pending;
static unsigned char expected_payload[PAYLOAD_MAX];
static unsigned int expected_length, delivered;
static const unsigned char source_mac[ETH_ALEN] = {2, 1, 2, 3, 4, 5};
static const unsigned char destination_mac[ETH_ALEN] = {2, 6, 7, 8, 9, 10};
static __be32 source_ip, destination_ip;
static __be16 source_port, destination_port;

static uint16_t oracle_sum(const unsigned char *p, unsigned int n)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < n; i += 2)
        sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

static uint16_t udp_oracle(const unsigned char *frame, unsigned int payload_length)
{
    const unsigned char *ip = frame + ETH_HLEN;
    const unsigned char *udp = ip + 20;
    unsigned int udp_length = 8 + payload_length;
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = UDP_PROTOCOL;
    pseudo[10] = (unsigned char)(udp_length >> 8); pseudo[11] = (unsigned char)udp_length;
    uint32_t sum = oracle_sum(pseudo, sizeof(pseudo)) + oracle_sum(udp, udp_length);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

static int receive_message(const struct ker_transport_message *message, void *arg)
{
    CHECK(arg == &receiver && worker.polling && !worker.timers.polling);
    CHECK(message->protocol == KER_TRANSPORT_UDP);
    CHECK(message->packet.udp.source_port == source_port &&
        message->packet.udp.destination_port == destination_port);
    CHECK(message->packet.udp.payload_length == expected_length);
    CHECK(!memcmp(message->packet.udp.payload, expected_payload, expected_length));
    ++delivered;
    return NET_RX_SUCCESS;
}

static int rx(void *arg, unsigned int budget)
{
    (void)arg;
    CHECK(budget == 1);
    if (!pending) return 0;
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

static void verify_packet(struct sk_buff *skb, const unsigned char *payload, unsigned int length)
{
    const unsigned char *frame = skb->data;
    CHECK(skb->len == ETH_HLEN + 28 + length);
    CHECK(skb_headroom(skb) == 128 && skb->mac_header == skb_headroom(skb));
    CHECK(skb->network_header == skb_headroom(skb) + ETH_HLEN);
    CHECK(skb->transport_header == skb_headroom(skb) + ETH_HLEN + 20);
    CHECK(!memcmp(frame, destination_mac, ETH_ALEN));
    CHECK(!memcmp(frame + 6, source_mac, ETH_ALEN));
    CHECK(frame[12] == 0x08 && frame[13] == 0x00);
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(ip[0] == 0x45 && ip[1] == 0 && ip[4] == 0 && ip[5] == 0);
    CHECK(ip[6] == 0 && ip[7] == 0 && ip[8] == 64 && ip[9] == UDP_PROTOCOL);
    CHECK(ip[2] == 0 && ip[3] == 28 + length);
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(oracle_sum(ip, 20) == 0xffff);
    const unsigned char *udp = ip + 20;
    CHECK(!memcmp(udp, &source_port, 2) && !memcmp(udp + 2, &destination_port, 2));
    CHECK(udp[4] == (unsigned char)((8 + length) >> 8) && udp[5] == (unsigned char)(8 + length));
    CHECK(udp_oracle(frame, length) == 0xffff);
    CHECK(!memcmp(udp + 8, payload, length));
}

static void one_packet(const unsigned char *payload, unsigned int length)
{
    memcpy(expected_payload, payload, length); expected_length = length;
    struct sk_buff *skb = NULL;
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, payload, length, &skb) == 0);
    CHECK(skb);
    verify_packet(skb, payload, length);
    struct rte_mbuf *exported = NULL;
    CHECK(ker_skb_to_mbuf(skb, &exported) == 0 && exported);
    CHECK(exported->pkt_len == skb->len && exported->ol_flags == 0);
    CHECK(!memcmp(rte_pktmbuf_mtod(exported, const void *), skb->data, skb->len));
    CHECK(ker_skb_free(skb) == 0); /* Exported copy outlives constructor skb. */

    pending = split_chain(exported);
    ker_packet_free(exported);
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
    CHECK(progress.rx == 1 && !pending && context.live == 0);
    CHECK(delivered > 0);
}

static void transactional_failures(void)
{
    unsigned char payload[4] = {1, 2, 3, 4};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 0, payload, sizeof(payload), &sentinel) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, NULL, 1, &sentinel) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, payload, 65508, &sentinel) == -EMSGSIZE);
    CHECK(sentinel == (void *)(uintptr_t)0x1234);
    unsigned char large[1900] = {0};
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, large, sizeof(large), &sentinel) == -ENOSPC);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);

    struct rte_mbuf *held[63];
    unsigned int n = 0;
    while (n < 63 && (held[n] = ker_packet_alloc(&pool))) ++n;
    CHECK(n == 63);
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, payload, sizeof(payload), &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    ker_packet_free(held[--n]);
    struct sk_buff *retry = NULL;
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, payload, sizeof(payload), &retry) == 0);
    CHECK(retry && context.live == 1 && ker_skb_free(retry) == 0);
    while (n) ker_packet_free(held[--n]);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 63);
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
    CHECK(ker_udp_ipv4_create(&context, source_mac, destination_mac, source_ip,
        destination_ip, source_port, destination_port, 64, payload, 2, &skb) == 0);
    CHECK(skb && skb->data[ETH_HLEN + 20 + 6] == 0xff && skb->data[ETH_HLEN + 20 + 7] == 0xff);
    CHECK(ker_skb_free(skb) == 0);
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
    CHECK(ker_eth_device_init(&device, &context, "udp-create0", 2, source_mac) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &runtime, &device, receive_message, &receiver) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = rx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);

    unsigned char odd[5] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    unsigned char even[4] = {0xab, 0xcd, 0xef, 0x01};
    one_packet(odd, sizeof(odd));
    one_packet(even, sizeof(even));
    one_packet(even, 0);
    checksum_zero_mangling();
    transactional_failures();

    CHECK(delivered == 3 && context.live == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("UDP packet construction, checksum and worker roundtrip passed");
    return 0;
}
