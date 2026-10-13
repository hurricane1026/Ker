/* Ker-specific integration inspired by F-Stack's segmented TX scenario.
 * Logical workers use separate pools/devices on one EAL thread. */
#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include "runtime/transport-receive.h"
#include <errno.h>
#include <string.h>

struct endpoint {
    struct ker_packet_pool pool;
    struct ker_skb_context skb;
    struct ker_eth_device device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_worker worker;
    struct ker_flow_context flow;
    unsigned handed, delivered, dropped;
    unsigned protocol;
    bool bad_checksum;
    bool allocation_drop;
    uint8_t frame[57];
    unsigned length;
};
static const unsigned char mac[6] = {2, 0, 0, 0, 0, 1};
static uint16_t sum16(const uint8_t *p, unsigned n, uint32_t sum)
{
    for (unsigned i = 0; i < n; i += 2)
        sum += ((unsigned)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}
static void put16(uint8_t *p, unsigned value) { p[0] = value >> 8; p[1] = value; }
static void frame(struct endpoint *e, unsigned protocol, unsigned corrupt)
{
    memset(e->frame, 0, sizeof(e->frame));
    e->protocol = protocol; e->bad_checksum = corrupt != 0;
    unsigned l4len = (protocol == 6 ? 20 : 8) + 3;
    e->length = 34 + l4len;
    uint8_t *p = e->frame, *ip = p + 14, *l4 = ip + 20;
    memcpy(p, mac, 6); memcpy(p + 6, mac, 6); p[12] = 8;
    ip[0] = 0x45; put16(ip + 2, 20 + l4len); ip[8] = 64; ip[9] = protocol;
    const uint8_t addresses[8] = {192, 0, 2, 1, 10, 0, 0, 1};
    memcpy(ip + 12, addresses, 8); put16(ip + 10, sum16(ip, 20, 0));
    put16(l4, 1234); put16(l4 + 2, 443);
    if (protocol == 6) { l4[12] = 0x50; l4[13] = 0x10; }
    else put16(l4 + 4, l4len);
    l4[l4len - 3] = 0xa1; l4[l4len - 2] = 0xb2; l4[l4len - 1] = 0xc3;
    uint8_t pseudo[12] = {192, 0, 2, 1, 10, 0, 0, 1, 0, 0, 0, 0};
    pseudo[9] = protocol; put16(pseudo + 10, l4len);
    uint16_t checksum = sum16(l4, l4len, (uint16_t)~sum16(pseudo, 12, 0));
    if (protocol == 17 && !checksum) checksum = 65535;
    put16(l4 + (protocol == 6 ? 16 : 6), checksum);
    if (corrupt == 1) ip[10] ^= 1;
    if (corrupt == 2) l4[l4len - 1] ^= 1;
}
static int message(const struct ker_transport_message *m, void *arg)
{
    struct endpoint *e = arg;
    CHECK(!e->bad_checksum && !e->allocation_drop);
    CHECK(m->protocol == e->protocol);
    CHECK(e->runtime.dispatching && e->flow.delivering);
    const uint8_t *payload;
    if (m->protocol == KER_TRANSPORT_UDP) {
        CHECK(m->packet.udp.source_port == rte_cpu_to_be_16(1234));
        CHECK(m->packet.udp.destination_port == rte_cpu_to_be_16(443));
        CHECK(m->packet.udp.payload_length == 3); payload = m->packet.udp.payload;
    } else {
        CHECK(m->packet.tcp.source_port == rte_cpu_to_be_16(1234));
        CHECK(m->packet.tcp.destination_port == rte_cpu_to_be_16(443));
        CHECK(m->packet.tcp.payload_length == 3); payload = m->packet.tcp.payload;
    }
    CHECK(payload[0] == 0xa1 && payload[1] == 0xb2 && payload[2] == 0xc3);
    ++e->delivered;
    return NET_RX_SUCCESS;
}
static void receive(void *arg, const struct ker_flow_key *key, struct rte_mbuf *packet)
{
    struct endpoint *e = arg;
    CHECK(key->domain == 7 && key->family == 4 && key->protocol == e->protocol);
    CHECK(key->local_port == 443 && key->remote_port == 1234);
    CHECK(packet->nb_segs == 7 && packet->pkt_len == e->length);
    uint8_t bytes[57];
    const void *data = rte_pktmbuf_read(packet, 0, packet->pkt_len, bytes);
    CHECK(data && memcmp(data, e->frame, e->length) == 0);
    ++e->handed;
    struct sk_buff *skb = NULL;
    int error = ker_eth_receive_copy_chain(&e->device, packet, 128, &skb);
    /* Successful handoff transfers the entire chain to this callback. Its
     * explicit policy is to consume/drop on copy allocation failure. */
    ker_packet_free(packet);
    if (e->allocation_drop) {
        CHECK(error == -ENOMEM && !skb); ++e->dropped; return;
    }
    CHECK(error == 0 && skb);
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&e->runtime, &e->device, &skb, &result) == 0);
    CHECK(!skb && result.handlers == 1);
    CHECK(result.status == (e->bad_checksum ? NET_RX_DROP : NET_RX_SUCCESS));
    CHECK(e->receiver.validation_error == (e->bad_checksum ? -EBADMSG : 0));
    if (e->bad_checksum) ++e->dropped;
}
static struct rte_mbuf *chain(struct ker_packet_pool *pool, const struct endpoint *e)
{
    /* EtherType, IPv4 address, and transport fields cross segment boundaries. */
    const unsigned lengths[7] = {13, 2, 8, 4, 8, 4, e->length - 39};
    struct rte_mbuf *head = NULL;
    unsigned offset = 0;
    for (unsigned i = 0; i < 7; ++i) {
        struct rte_mbuf *m = ker_packet_alloc(pool); CHECK(m);
        void *p = rte_pktmbuf_append(m, lengths[i]); CHECK(p);
        memcpy(p, e->frame + offset, lengths[i]); offset += lengths[i];
        if (!head) head = m;
        else CHECK(rte_pktmbuf_chain(head, m) == 0);
    }
    CHECK(offset == e->length);
    return head;
}
static void init(struct endpoint *e, unsigned id, struct ker_flow_fabric *fabric)
{
    const char *pool_name = id ? "flow_rx_pool1" : "flow_rx_pool0";
    const char *skb_name = id ? "flow_rx_skb1" : "flow_rx_skb0";
    CHECK(ker_packet_pool_init(&e->pool, pool_name, 127, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&e->skb, &e->pool, skb_name) == 0);
    CHECK(ker_eth_device_init(&e->device, &e->skb, id ? "flow1" : "flow0", id + 1, mac) == 0);
    CHECK(ker_receive_runtime_init(&e->runtime, &e->skb) == 0);
    CHECK(ker_transport_receiver_register(&e->receiver, &e->runtime, &e->device, message, e) == 0);
    struct ker_worker_config cfg = {.timer_budget=1, .handoff_budget=1};
    struct ker_worker_ops ops = {0};
    CHECK(ker_worker_init(&e->worker, &e->pool, &cfg, &ops) == 0);
    CHECK(ker_flow_attach(&e->flow, fabric, &e->worker, id, receive, e) == 0);
}
static void poll_one(struct endpoint *e)
{
    struct ker_worker_result result;
    CHECK(ker_worker_poll(&e->worker, 0, &result) == 0);
    CHECK(result.handoff == 1 && !e->skb.live);
}
static void cleanup(struct endpoint *e)
{
    CHECK(ker_flow_detach(&e->flow) == 0);
    CHECK(ker_worker_cleanup(&e->worker) == 0);
    CHECK(ker_transport_receiver_unregister(&e->receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&e->runtime) == 0);
    CHECK(ker_eth_device_cleanup(&e->device) == 0);
    CHECK(ker_skb_context_cleanup(&e->skb) == 0);
    CHECK(ker_packet_pool_cleanup(&e->pool) == 0);
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    for (unsigned owner = 0; owner < 2; ++owner) {
        uint16_t map[KER_FLOW_BUCKETS];
        for (unsigned b = 0; b < KER_FLOW_BUCKETS; ++b) map[b] = owner;
        struct ker_flow_fabric fabric = {0};
        struct ker_flow_config cfg = {.worker_count=2, .bucket_owner=map, .seed=1,
            .inbox_capacity=1, .name="flow_rx", .socket_id=SOCKET_ID_ANY};
        CHECK(ker_flow_fabric_init(&fabric, &cfg) == 0);
        struct endpoint endpoints[2] = {0};
        for (unsigned w = 0; w < 2; ++w) init(&endpoints[w], w, &fabric);
        struct endpoint *dest = &endpoints[owner], *src = &endpoints[1 - owner];
        for (unsigned protocol_index = 0; protocol_index < 2; ++protocol_index) {
            unsigned protocol = protocol_index ? 6 : 17;
            for (unsigned corrupt = 0; corrupt < 3; ++corrupt) {
                frame(dest, protocol, corrupt);
                for (unsigned remote = 0; remote < 2; ++remote) {
                    unsigned before = dest->handed;
                    struct rte_mbuf *m = chain(&src->pool, dest);
                    CHECK(ker_flow_submit(remote ? &src->flow : &dest->flow, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
                    CHECK(dest->handed == before + !remote);
                    if (remote) poll_one(dest);
                    CHECK(dest->handed == before + 1);
                    CHECK(src->handed == 0 && !dest->skb.live);
                }
            }
            frame(dest, protocol, 0);
            struct rte_mbuf *first = chain(&src->pool, dest), *retry = chain(&src->pool, dest);
            struct rte_mbuf *saved = retry;
            CHECK(ker_flow_submit(&src->flow, 7, KER_FLOW_INGRESS, &first) == 0 && !first);
            CHECK(ker_flow_submit(&src->flow, 7, KER_FLOW_INGRESS, &retry) == -ENOBUFS && retry == saved);
            CHECK(retry->nb_segs == 7);
            poll_one(dest);
            CHECK(ker_flow_submit(&src->flow, 7, KER_FLOW_INGRESS, &retry) == 0 && !retry);
            poll_one(dest);
            /* Exhaust only the owner's pool; the ingress producer can still
             * allocate and hand off a chain. Owner drops then recovers. */
            struct rte_mbuf *held[127]; unsigned count = 0;
            while (count < 127 && (held[count] = ker_packet_alloc(&dest->pool))) ++count;
            CHECK(count == 127);
            unsigned delivered = dest->delivered, dropped = dest->dropped;
            dest->allocation_drop = true;
            struct rte_mbuf *m = chain(&src->pool, dest);
            CHECK(ker_flow_submit(&src->flow, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
            poll_one(dest);
            CHECK(dest->dropped == dropped + 1 && dest->delivered == delivered);
            for (unsigned i = 0; i < count; ++i) ker_packet_free(held[i]);
            dest->allocation_drop = false;
            m = chain(&src->pool, dest);
            CHECK(ker_flow_submit(&src->flow, 7, KER_FLOW_INGRESS, &m) == 0 && !m);
            poll_one(dest); CHECK(dest->delivered == delivered + 1);
        }
        CHECK(dest->handed == 20 && dest->delivered == 10 && dest->dropped == 10);
        for (unsigned w = 0; w < 2; ++w) cleanup(&endpoints[w]);
        CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
    }
    CHECK(ker_memory_shutdown() == 0); CHECK(rte_eal_cleanup() == 0);
    puts("flow chain receive: owner protocol validation, full-inbox retry and explicit allocation-drop recovery passed");
    return 0;
}
