#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <pthread.h>
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char mac[6] = {2, 1, 2, 3, 4, 5};
static struct rte_mbuf *frame(const unsigned char dest[6], unsigned int protocol, unsigned int payload)
{
    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(packet, ETH_HLEN + payload);
    CHECK(bytes != NULL);
    memcpy(bytes, dest, 6);
    memcpy(bytes + 6, mac, 6);
    __be16 type = rte_cpu_to_be_16(protocol);
    memcpy(bytes + 12, &type, 2);
    memset(bytes + ETH_HLEN, 0x42, payload);
    return packet;
}
static void classify(const unsigned char dest[6], unsigned int wire, unsigned int expected,
                     unsigned int type, unsigned int payload, bool ipx)
{
    struct rte_mbuf *packet = frame(dest, wire, payload);
    if (ipx) memset(rte_pktmbuf_mtod(packet, unsigned char *) + ETH_HLEN, 0xff, 2);
    unsigned char *old_data = rte_pktmbuf_mtod(packet, unsigned char *);
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive(&device, packet, &skb) == 0);
    CHECK(skb->dev == device.native && skb->protocol == rte_cpu_to_be_16(expected));
    CHECK(skb->pkt_type == type && skb->len == payload && skb->mac_len == ETH_HLEN);
    CHECK(skb_mac_header(skb) == old_data && skb->data == old_data + ETH_HLEN);
    CHECK(skb->head + skb->network_header == skb->data);
    CHECK(eth_header_parse_protocol(skb) == rte_cpu_to_be_16(wire));
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(skb, &clone) == 0 && clone->dev == device.native);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(clone->dev->ifindex == 1);
    CHECK(ker_skb_free(clone) == 0);
}
static void failure_paths(void)
{
    struct rte_mbuf *packet = frame(mac, ETH_P_IP, 4);
    unsigned char before[18];
    memcpy(before, rte_pktmbuf_mtod(packet, void *), sizeof(before));
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    packet->data_len = packet->pkt_len = ETH_HLEN - 1;
    CHECK(ker_eth_receive(&device, packet, &result) == -EMSGSIZE);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && context.live == 0);
    packet->data_len = packet->pkt_len = sizeof(before);
    packet->data_off++;
    CHECK(ker_eth_receive(&device, packet, &result) == -EINVAL);
    packet->data_off--;
    packet->ol_flags = RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
    CHECK(ker_eth_receive(&device, packet, &result) == -ENOTSUP);
    packet->ol_flags = 0;
    struct sk_buff *held[7];
    for (size_t i = 0; i < 7; ++i) CHECK(ker_skb_alloc(&context, 16, 128, &held[i]) == 0);
    CHECK(ker_eth_receive(&device, packet, &result) == -ENOMEM);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && context.live == 7);
    CHECK(memcmp(before, rte_pktmbuf_mtod(packet, void *), sizeof(before)) == 0);
    CHECK(rte_mbuf_refcnt_read(packet) == 1);
    for (size_t i = 0; i < 7; ++i) CHECK(ker_skb_free(held[i]) == 0);
    ker_packet_free(packet);
}
static void *wrong_worker(void *arg)
{
    (void)arg;
    CHECK(rte_thread_register() == 0);
    CHECK(ker_eth_device_cleanup(&device) == -EXDEV);
    rte_thread_unregister();
    return NULL;
}
struct ingress { struct rte_mbuf *frames[2]; unsigned int next; unsigned int consumed; };
static int ingress_poll(void *arg, unsigned int budget)
{
    struct ingress *ingress = arg;
    unsigned int done = 0;
    while (done < budget && ingress->next < 2) {
        struct sk_buff *skb = NULL;
        CHECK(ker_eth_receive(&device, ingress->frames[ingress->next++], &skb) == 0);
        CHECK(skb->protocol == rte_cpu_to_be_16(ETH_P_ARP) || skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
        ++ingress->consumed;
        CHECK(ker_skb_free(skb) == 0);
        ++done;
    }
    return done;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_eth_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ker_eth_descriptors") == 0);
    ker_memory_fail_after(0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == -ENOMEM && !device.native);
    ker_memory_fail_after(-1);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    CHECK(device.native->reg_state == NETREG_UNINITIALIZED);
    CHECK(device.native->type == ARPHRD_ETHER && device.native->mtu == ETH_DATA_LEN);
    classify(mac, ETH_P_IP, ETH_P_IP, PACKET_HOST, 4, false);
    unsigned char broadcast[6] = {255, 255, 255, 255, 255, 255};
    unsigned char multicast[6] = {1, 0, 94, 0, 0, 1};
    unsigned char other[6] = {2, 7, 8, 9, 10, 11};
    classify(broadcast, ETH_P_ARP, ETH_P_ARP, PACKET_BROADCAST, 4, false);
    classify(multicast, ETH_P_IPV6, ETH_P_IPV6, PACKET_MULTICAST, 4, false);
    classify(other, 0x88b5, 0x88b5, PACKET_OTHERHOST, 4, false);
    classify(mac, 10, ETH_P_802_3, PACKET_HOST, 2, true);
    classify(mac, 10, ETH_P_802_2, PACKET_HOST, 1, false);
    classify(mac, 0, ETH_P_802_2, PACKET_HOST, 0, false);
    failure_paths();
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wrong_worker, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    struct ingress ingress = {.frames = {frame(mac, ETH_P_IP, 4), frame(broadcast, ETH_P_ARP, 4)}};
    struct ker_worker worker = {0};
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
    struct ker_worker_ops ops = {.rx = ingress_poll, .arg = &ingress};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    struct ker_worker_result result;
    CHECK(ker_worker_poll(&worker, 10, &result) == 0 && result.rx == 1);
    CHECK(ker_worker_poll(&worker, 10, &result) == 0 && result.rx == 1);
    CHECK(ingress.consumed == 2 && context.live == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Ethernet: original classifier/layout, device lifetime, failure ownership and worker ingress passed");
    return 0;
}
