#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static const unsigned char local_mac[ETH_ALEN] = {2, 0x11, 0x22, 0x33, 0x44, 0x55};
static const unsigned char peer_mac[ETH_ALEN] = {2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
static const unsigned char zero_mac[ETH_ALEN];
static const unsigned char broadcast_mac[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
static __be32 local_ip, peer_ip;

static __be32 ip(unsigned int host) { return rte_cpu_to_be_32(host); }

static void expected_wire(unsigned int operation, const unsigned char *destination,
    const unsigned char *target, unsigned char frame[42])
{
    memset(frame, 0, 42);
    memcpy(frame, destination, ETH_ALEN);
    memcpy(frame + 6, local_mac, ETH_ALEN);
    frame[12] = 0x08; frame[13] = 0x06;
    frame[14] = 0; frame[15] = 1;
    frame[16] = 0x08; frame[17] = 0;
    frame[18] = 6; frame[19] = 4;
    frame[20] = 0; frame[21] = (unsigned char)operation;
    memcpy(frame + 22, local_mac, ETH_ALEN);
    memcpy(frame + 28, &local_ip, sizeof(local_ip));
    memcpy(frame + 32, target, ETH_ALEN);
    memcpy(frame + 38, &peer_ip, sizeof(peer_ip));
}

static struct sk_buff *create(unsigned int operation, const unsigned char *destination,
    const unsigned char *target)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_arp_create_configured(&address, operation, peer_ip, destination,
        target, &skb) == 0);
    CHECK(skb && skb->len == 42 && skb->dev == device.native &&
        skb->protocol == rte_cpu_to_be_16(ETH_P_ARP) &&
        skb->mac_len == ETH_HLEN && skb->network_header == skb->mac_header + ETH_HLEN);
    unsigned char expected[42];
    expected_wire(operation, destination, target, expected);
    CHECK(memcmp(skb->data, expected, sizeof(expected)) == 0);
    return skb;
}

static void *foreign_create(void *unused)
{
    (void)unused;
    struct sk_buff *result = (void *)(uintptr_t)1;
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &result) == -EXDEV);
    CHECK(result == (void *)(uintptr_t)1);
    return NULL;
}

static void failure_boundaries(void)
{
    struct sk_buff *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_arp_create_configured(NULL, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -EINVAL);
    CHECK(ker_arp_create_configured(&address, 3, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -EINVAL);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        NULL, zero_mac, &sentinel) == -EINVAL);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, NULL, &sentinel) == -EINVAL);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, NULL) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)1 && context.live == 0);

    struct net_device *native = device.native;
    native->ip_ptr = NULL;
    CHECK(ker_arp_create_configured(&address, 99, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -EINVAL);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -ESHUTDOWN);
    native->ip_ptr = address.native;
    struct in_device *native_address = address.native;
    address.native = NULL;
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -ESHUTDOWN);
    address.native = native_address;
    native_address->dead = 1;
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -ESHUTDOWN);
    native_address->dead = 0;
    CHECK(sentinel == (void *)(uintptr_t)1 && context.live == 0);

    ker_memory_fail_after(0);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(sentinel == (void *)(uintptr_t)1 && context.live == 0);

    struct rte_mbuf *held[31];
    for (unsigned int i = 0; i < 31; ++i)
        CHECK((held[i] = ker_packet_alloc(&pool)) != NULL);
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        broadcast_mac, zero_mac, &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)1 && context.live == 0);
    for (unsigned int i = 0; i < 31; ++i)
        ker_packet_free(held[i]);

    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_create, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    struct sk_buff *retry = create(ARPOP_REQUEST, broadcast_mac, zero_mac);
    CHECK(ker_skb_free(retry) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "arp_cfg_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "arp_cfg_skb") == 0);
    local_ip = ip(0xc0000201); peer_ip = ip(0xc0000202);
    CHECK(ker_eth_device_init(&device, &context, "ethcfg0", 1, local_mac) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
    CHECK(ker_arp_device_setup(&device) == 0);

    /* Request accepts explicit broadcast/zero-THA tuple. */
    unsigned char caller_destination[ETH_ALEN], caller_target[ETH_ALEN];
    memcpy(caller_destination, broadcast_mac, ETH_ALEN);
    memcpy(caller_target, zero_mac, ETH_ALEN);
    struct sk_buff *request = NULL;
    CHECK(ker_arp_create_configured(&address, ARPOP_REQUEST, peer_ip,
        caller_destination, caller_target, &request) == 0);
    /* Tuple storage is borrowed only for the call; packet bytes are independent. */
    memset(caller_destination, 0x5a, ETH_ALEN);
    memset(caller_target, 0x6b, ETH_ALEN);
    unsigned char expected[42]; expected_wire(ARPOP_REQUEST, broadcast_mac, zero_mac, expected);
    CHECK(memcmp(request->data, expected, sizeof(expected)) == 0);

    /* Configured tuple is byte-identical to the existing raw adapter when
     * given its snapshotted source address and device MAC. */
    struct sk_buff *raw = NULL;
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, local_ip, peer_ip,
        broadcast_mac, local_mac, zero_mac, &raw) == 0);
    CHECK(raw->len == request->len && memcmp(raw->data, request->data, 42) == 0);
    CHECK(ker_skb_free(raw) == 0 && ker_skb_free(request) == 0);

    struct sk_buff *reply = create(ARPOP_REPLY, peer_mac, peer_mac);
    raw = NULL;
    CHECK(ker_arp_create(&device, ARPOP_REPLY, local_ip, peer_ip,
        peer_mac, local_mac, peer_mac, &raw) == 0);
    CHECK(raw->len == reply->len && memcmp(raw->data, reply->data, 42) == 0);
    CHECK(ker_skb_free(raw) == 0 && ker_skb_free(reply) == 0);
    failure_boundaries();

    CHECK(context.live == 0 && ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("Configured ARP: request/reply byte oracle, raw equivalence, ownership and failure rollback passed");
    return 0;
}
