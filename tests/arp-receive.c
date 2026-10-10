#include "check.h"
#include "eal.h"
#include "runtime/arp-receive.h"
#include "runtime/arp.h"
#include "runtime/memory.h"
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_receive_runtime runtime;
static struct ker_arp_receiver receiver;
static struct ker_protocol_handler observer;
static const unsigned char mac[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 6, 7, 8, 9, 10};
static __be32 local, remote;
static struct sk_buff *held, *reply;
static unsigned int messages;
static int callback_status = NET_RX_SUCCESS;
static bool make_reply;
static struct ker_arp_message last;
static int message(const struct ker_arp_message *m, void *arg)
{
    CHECK(arg == &receiver);
    CHECK(ker_arp_receiver_unregister(&receiver) == -EBUSY);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    last = *m; messages++;
    if (make_reply) {
        CHECK(m->target_local && m->operation == ARPOP_REQUEST && !reply);
        CHECK(ker_arp_create(&device, ARPOP_REPLY, m->target_ip, m->sender_ip,
            m->sender_mac, NULL, m->sender_mac, &reply) == 0);
    }
    return callback_status;
}
static int observe(struct sk_buff *skb, struct ker_protocol_handler *h, struct net_device *orig, void *arg)
{
    (void)h; (void)arg;
    CHECK(orig == device.native && !held);
    held = skb; /* Retain the callback-owned reference, do not add another. */
    return NET_RX_SUCCESS;
}
static struct sk_buff *packet(unsigned int payload)
{
    struct rte_mbuf *mbuf = ker_packet_alloc(&pool); CHECK(mbuf);
    unsigned char *p = (unsigned char *)rte_pktmbuf_append(mbuf, (uint16_t)(ETH_HLEN + payload)); CHECK(p);
    unsigned char bytes[42] = {0};
    memset(bytes, 0xff, 6); memcpy(bytes + 6, peer, 6); bytes[12] = 8; bytes[13] = 6;
    bytes[15] = 1; bytes[16] = 8; bytes[18] = 6; bytes[19] = 4; bytes[21] = ARPOP_REQUEST;
    memcpy(bytes + 22, peer, 6); memcpy(bytes + 28, &remote, 4); memcpy(bytes + 38, &local, 4);
    memset(p, 0xcc, ETH_HLEN + payload);
    memcpy(p, bytes, ETH_HLEN + (payload < 28 ? payload : 28));
    struct sk_buff *skb = NULL; CHECK(ker_eth_receive(&device, mbuf, &skb) == 0);
    memset(skb->cb, 0xa5, sizeof(skb->cb));
    return skb;
}
static int dispatch(struct sk_buff *skb, int error)
{
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == error && !skb);
    CHECK(result.handlers == (observer.registered ? 2U : 1U));
    return result.status;
}
static void *wrong_worker(void *arg)
{
    (void)arg;
    struct ker_arp_receiver other = {0};
    CHECK(ker_arp_receiver_register(&other, &runtime, &address, message, &receiver) == -EXDEV);
    CHECK(ker_arp_receiver_unregister(&receiver) == -EXDEV);
    return NULL;
}
int main(void)
{
    ker_test_eal_init(); local = rte_cpu_to_be_32(0xc0000201); remote = rte_cpu_to_be_32(0xc0000202);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "arp_rx_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "arp_rx_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    CHECK(ker_arp_device_setup(&device) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local, 24) == 0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, NULL, NULL) == -EINVAL);
    runtime.live = KER_RECEIVE_MAX_HANDLERS;
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == -ENOSPC);
    CHECK(refcount_read(&address.native->refcnt) == 1 && !receiver.handler.registered);
    runtime.live = 0;
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == -EALREADY);
    CHECK(refcount_read(&address.native->refcnt) == 2 && ker_ipv4_address_cleanup(&address) == -EBUSY);
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, wrong_worker, NULL) && !pthread_join(thread, NULL));
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && messages == 1);
    CHECK(last.sender_ip == remote && last.target_ip == local && last.target_local &&
        !memcmp(last.sender_mac, peer, 6) && last.operation == ARPOP_REQUEST);
    CHECK(dispatch(packet(46), 0) == NET_RX_SUCCESS && messages == 2); /* Ethernet padding */
    for (unsigned int len = 0; len < 28; ++len) CHECK(dispatch(packet(len), 0) == NET_RX_DROP);
    CHECK(messages == 2 && !context.live);
    /* Structural gate and private decoder reject each malformed field. */
    for (unsigned int field = 0; field < 10; ++field) {
        struct sk_buff *skb = packet(28); unsigned char *p = skb->data;
        switch (field) {
        case 0: p[4] = 5; break; /* hardware address length */
        case 1: p[5] = 16; break; /* protocol address length */
        case 2: p[1] = 99; break; /* hardware type */
        case 3: p[2] = 0x86; p[3] = 0xdd; break;
        case 4: p[7] = 99; break;
        case 5: p[8] = 1; break; /* multicast sender MAC */
        case 6: memset(p + 8, 0, 6); break;
        case 7: p[24] = 127; break; /* loopback target */
        case 8: p[14] = 224; break; /* multicast sender */
        case 9: p[7] = ARPOP_REPLY; memset(p + 14, 0, 4); break;
        }
        CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 2);
    }
    struct sk_buff *skb = packet(28); skb->data[1] = ARPHRD_IEEE802;
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 3);
    skb = packet(28); memset(skb->data + 14, 0, 4);
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 4 && !last.sender_ip); /* DAD */
    skb = packet(28); memcpy(skb->data + 24, &remote, 4);
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 5 && !last.target_local);
    skb = packet(28); skb->data[7] = ARPOP_REPLY;
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 6 && last.operation == ARPOP_REPLY);
    for (unsigned int mode = 0; mode < 3; ++mode) {
        skb = packet(28);
        if (!mode) device.native->flags |= ker_linux_IFF_NOARP;
        else skb->pkt_type = mode == 1 ? PACKET_OTHERHOST : PACKET_LOOPBACK;
        CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 6);
        device.native->flags &= ~ker_linux_IFF_NOARP;
    }
    /* Original share_check clones only the descriptor, preserving an earlier
     * observer's scratch/data and ownership on both success and OOM. */
    CHECK(ker_protocol_register(&runtime, &observer, NULL, rte_cpu_to_be_16(ETH_P_ARP), observe, NULL) == 0);
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && messages == 7 && held && context.live == 1);
    for (unsigned int i = 0; i < sizeof(held->cb); ++i) CHECK((unsigned char)held->cb[i] == 0xa5);
    CHECK(refcount_read(&held->users) == 1 && ker_skb_free(held) == 0); held = NULL;
    skb = packet(28); ker_memory_fail_after(0);
    CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 7 && held && refcount_read(&held->users) == 1);
    ker_memory_fail_after(-1); CHECK(ker_skb_free(held) == 0); held = NULL;
    skb = packet(28);
    struct sk_buff *occupied[6];
    for (unsigned int i = 0; i < 6; ++i) CHECK(ker_skb_alloc(&context, 0, 0, &occupied[i]) == 0);
    CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 7 && held && context.live == 7);
    CHECK(refcount_read(&held->users) == 1 && ker_skb_free(held) == 0); held = NULL;
    for (unsigned int i = 0; i < 6; ++i) CHECK(ker_skb_free(occupied[i]) == 0);
    CHECK(ker_protocol_unregister(&observer) == 0);
    callback_status = NET_RX_DROP;
    CHECK(dispatch(packet(28), 0) == NET_RX_DROP && !context.live);
    callback_status = -EIO;
    CHECK(dispatch(packet(28), -EPROTO) == NET_RX_DROP && !context.live);
    callback_status = NET_RX_SUCCESS; make_reply = true;
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && reply && context.live == 1);
    CHECK(!memcmp(reply->data, peer, 6) && !memcmp(reply->data + 6, mac, 6));
    CHECK(arp_hdr(reply)->ar_op == rte_cpu_to_be_16(ARPOP_REPLY));
    CHECK(!memcmp(reply->data + 28, &local, 4) && !memcmp(reply->data + 38, &remote, 4));
    CHECK(ker_skb_free(reply) == 0); reply = NULL;
    CHECK(ker_arp_receiver_unregister(&receiver) == 0 && refcount_read(&address.native->refcnt) == 1);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0 && ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("ARP receive: original gate, ownership, malformed frames, DAD, callback and reply construction passed");
    return 0;
}
