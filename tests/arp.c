#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/receive.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device, destination;
static const unsigned char mac[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 6, 7, 8, 9, 10};
static __be32 sip, tip;
static struct sk_buff *create(unsigned int operation)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_arp_create(&device, operation, sip, tip,
        operation == ARPOP_REPLY ? peer : NULL, NULL,
        operation == ARPOP_REPLY ? peer : NULL, &skb) == 0);
    return skb;
}
static void verify(const unsigned char *frame, unsigned int operation)
{
    unsigned char expected[42] = {0};
    if (operation == ARPOP_REQUEST) memset(expected, 0xff, 6);
    else memcpy(expected, peer, 6);
    memcpy(expected + 6, mac, 6);
    expected[12] = 8; expected[13] = 6; /* Ethernet ARP */
    expected[15] = 1; expected[16] = 8; expected[18] = 6; expected[19] = 4;
    expected[21] = (unsigned char)operation;
    memcpy(expected + 22, mac, 6); memcpy(expected + 28, &sip, 4);
    if (operation == ARPOP_REPLY) memcpy(expected + 32, peer, 6);
    memcpy(expected + 38, &tip, 4);
    CHECK(memcmp(frame, expected, sizeof(expected)) == 0);
}
static int consumed;
static int receiver(struct sk_buff *skb, struct ker_protocol_handler *handler,
                    struct net_device *orig, void *arg)
{
    (void)handler; (void)arg;
    CHECK(orig == destination.native && skb->pkt_type == PACKET_HOST && skb->protocol == rte_cpu_to_be_16(ETH_P_ARP));
    CHECK(skb->len == 28 && skb->network_header == skb_headroom(skb));
    verify(skb_mac_header(skb), ARPOP_REPLY);
    CHECK(ker_skb_free(skb) == 0); consumed++;
    return NET_RX_SUCCESS;
}
static void *wrong_worker(void *arg)
{
    (void)arg;
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_arp_device_setup(&device) == -EXDEV);
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, sip, tip, NULL, NULL, NULL, &skb) == -EXDEV);
    CHECK(skb == (void *)(uintptr_t)1);
    return NULL;
}
struct tx { struct sk_buff *pending; struct rte_mbuf *sent; };
static int tx_poll(void *arg, unsigned int budget)
{
    struct tx *tx = arg;
    CHECK(budget == 1);
    if (!tx->pending) return 0;
    int error = ker_skb_to_mbuf(tx->pending, &tx->sent);
    if (error) return error;
    CHECK(ker_skb_free(tx->pending) == 0); tx->pending = NULL;
    return 1;
}
int main(void)
{
    ker_test_eal_init(); sip = rte_cpu_to_be_32(0xc0000201); tip = rte_cpu_to_be_32(0xc0000202);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "arp_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "arp_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    struct sk_buff *output = (void *)(uintptr_t)1;
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, sip, tip, NULL, NULL, NULL, &output) == -ENOTSUP);
    CHECK(ker_arp_device_setup(&device) == 0 && ker_arp_device_setup(&device) == 0);
    CHECK(ker_arp_create(&device, 99, sip, tip, NULL, NULL, NULL, &output) == -EINVAL);
    CHECK(ker_arp_create(&device, ARPOP_REPLY, sip, tip, NULL, NULL, NULL, &output) == -EINVAL);
    CHECK(output == (void *)(uintptr_t)1);
    device.native->needed_headroom = 16;
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, sip, tip, NULL, NULL, NULL, &output) == -ENOTSUP);
    device.native->needed_headroom = 0;
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wrong_worker, NULL) == 0 && pthread_join(thread, NULL) == 0);
    ker_memory_fail_after(0);
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, sip, tip, NULL, NULL, NULL, &output) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(output == (void *)(uintptr_t)1 && context.live == 0);
    struct rte_mbuf *held[31];
    for (unsigned int i = 0; i < 31; ++i) CHECK((held[i] = ker_packet_alloc(&pool)) != NULL);
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, sip, tip, NULL, NULL, NULL, &output) == -ENOMEM);
    CHECK(output == (void *)(uintptr_t)1 && context.live == 0);
    for (unsigned int i = 0; i < 31; ++i) ker_packet_free(held[i]);
    for (unsigned int op = ARPOP_REQUEST; op <= ARPOP_REPLY; ++op) {
        struct sk_buff *skb = create(op);
        CHECK(skb->len == 42 && skb->dev == device.native && skb->protocol == rte_cpu_to_be_16(ETH_P_ARP));
        CHECK(skb->network_header == skb->mac_header + ETH_HLEN && skb->mac_len == ETH_HLEN);
        CHECK(arp_hdr(skb)->ar_hln == 6 && arp_hdr(skb)->ar_pln == 4);
        verify(skb->data, op);
        struct sk_buff *clone = NULL;
        CHECK(ker_skb_clone(skb, &clone) == 0 && ker_skb_free(skb) == 0);
        CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
        struct rte_mbuf *exported = NULL;
        CHECK(ker_skb_to_mbuf(clone, &exported) == 0 && exported->pkt_len == 42 && !exported->ol_flags);
        verify(rte_pktmbuf_mtod(exported, const unsigned char *), op);
        CHECK(ker_skb_free(clone) == 0); ker_packet_free(exported);
    }
    struct tx tx = {.pending = create(ARPOP_REPLY)};
    for (unsigned int i = 0; i < 30; ++i) CHECK((held[i] = ker_packet_alloc(&pool)) != NULL);
    struct rte_mbuf *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf(tx.pending, &sentinel) == -ENOMEM && sentinel == (void *)(uintptr_t)1);
    verify(tx.pending->data, ARPOP_REPLY);
    for (unsigned int i = 0; i < 30; ++i) ker_packet_free(held[i]);
    struct ker_worker worker = {0};
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1};
    struct ker_worker_ops ops = {.tx = tx_poll, .arg = &tx};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    struct ker_worker_result progress;
    CHECK(ker_worker_poll(&worker, 1, &progress) == 0 && progress.tx == 1 && tx.sent && !tx.pending);
    CHECK(ker_worker_cleanup(&worker) == 0);
    /* Software loopback of a genuine constructor result to the existing
     * classifier/dispatcher. Test consumer does not implement arp_rcv. */
    struct ker_receive_runtime runtime = {0}; struct ker_protocol_handler handler = {0};
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_eth_device_init(&destination, &context, "eth1", 2, peer) == 0);
    CHECK(ker_protocol_register(&runtime, &handler, &destination, rte_cpu_to_be_16(ETH_P_ARP), receiver, NULL) == 0);
    struct sk_buff *received = NULL;
    CHECK(ker_eth_receive(&destination, tx.sent, &received) == 0);
    struct ker_receive_result result;
    CHECK(ker_receive_dispatch(&runtime, &destination, &received, &result) == 0 && !received);
    CHECK(consumed == 1 && result.handlers == 1 && result.status == NET_RX_SUCCESS);
    CHECK(ker_protocol_unregister(&handler) == 0 && ker_receive_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&destination) == 0 && ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("ARP: original constructor bytes, header namespace, allocation/export failures and software TX loopback passed");
    return 0;
}
