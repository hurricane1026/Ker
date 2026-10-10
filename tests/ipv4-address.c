#include "check.h"
#include "eal.h"
#include "runtime/ipv4-address.h"
#include "runtime/arp.h"
#include "runtime/receive.h"
#include "runtime/napi.h"
#include "runtime/memory.h"
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static __be32 wire(unsigned int x) { return rte_cpu_to_be_32(x); }
static int unused_poll(struct ker_napi *n, unsigned int budget, void *arg)
{
    (void)n; (void)budget; (void)arg;
    CHECK(false); return 0;
}
static int unused_receive(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *orig, void *arg)
{
    (void)skb; (void)handler; (void)orig; (void)arg;
    CHECK(false); return 0;
}
static void *foreign(void *arg)
{
    (void)arg;
    CHECK(ker_ipv4_address_contains(&address, wire(0xc0000201)) == -EXDEV);
    CHECK(ker_ipv4_address_is_local(&address, wire(0xc0000201)) == -EXDEV);
    CHECK(ker_ipv4_address_cleanup(&address) == -EXDEV);
    return NULL;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "addr_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "addr_skb") == 0);
    const unsigned char mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    size_t allocations = ker_memory_live_allocations();
    CHECK(ker_ipv4_address_init(&address, &device, wire(0xc0000201), 33) == -EINVAL);
    for (size_t i = 0; i < 5; ++i) {
        const unsigned int bad[] = {0, 0x7f000001, 0xe0000001, 0xf0000001, 0xffffffff};
        CHECK(ker_ipv4_address_init(&address, &device, wire(bad[i]), 24) == -EINVAL);
    }
    ker_memory_fail_after(0);
    CHECK(ker_ipv4_address_init(&address, &device, wire(0xc0000201), 24) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(!address.native && !device.native->ip_ptr && ker_memory_live_allocations() == allocations);
    struct { unsigned int prefix, mask; int peer, other; } cases[] = {
        {0, 0, 1, 1}, {1, 0x80000000, 1, 1}, {8, 0xff000000, 1, 0},
        {24, 0xffffff00, 1, 0}, {31, 0xfffffffe, 0, 0}, {32, 0xffffffff, 0, 0}
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        CHECK(ker_ipv4_address_init(&address, &device, wire(0xc0000201), cases[i].prefix) == 0);
        struct in_ifaddr *ifa = address.native->ifa_list;
        CHECK(address.native->dev == device.native && device.native->ip_ptr == address.native);
        CHECK(ifa->ifa_dev == address.native && !ifa->ifa_next && ifa->ifa_local == wire(0xc0000201));
        CHECK(ifa->ifa_mask == wire(cases[i].mask) && ifa->ifa_prefixlen == cases[i].prefix);
        CHECK(ifa->ifa_broadcast == wire(0xc0000201 | ~cases[i].mask));
        CHECK(ifa->ifa_flags == IFA_F_PERMANENT && ifa->ifa_valid_lft == UINT32_MAX);
        CHECK(strcmp(ifa->ifa_label, "eth0") == 0);
        CHECK(ker_ipv4_address_contains(&address, wire(0xc0000201)) == 1);
        CHECK(ker_ipv4_address_contains(&address, wire(0xc0000202)) == cases[i].peer);
        CHECK(ker_ipv4_address_contains(&address, wire(0xc6336401)) == cases[i].other);
        CHECK(ker_ipv4_address_is_local(&address, wire(0xc0000201)) == 1);
        CHECK(ker_ipv4_address_is_local(&address, wire(0xc0000202)) == 0);
        CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
        CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
        CHECK(ker_ipv4_address_cleanup(&address) == 0 && !device.native->ip_ptr);
        CHECK(ker_memory_live_allocations() == allocations);
    }
    CHECK(ker_ipv4_address_init(&address, &device, wire(0xc0000200), 31) == 0);
    CHECK(ker_ipv4_address_contains(&address, wire(0xc0000201)) == 1);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, wire(0xc0000201), 24) == 0);
    struct ker_ipv4_address duplicate = {0};
    CHECK(ker_ipv4_address_init(&duplicate, &device, wire(0xc0000202), 24) == -EBUSY);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign, NULL) == 0 && pthread_join(thread, NULL) == 0);
    refcount_inc(&address.native->refcnt);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    CHECK(!refcount_dec_and_test(&address.native->refcnt));
    CHECK(ker_arp_device_setup(&device) == 0);
    struct sk_buff *request = NULL;
    CHECK(ker_arp_create(&device, ARPOP_REQUEST, address.native->ifa_list->ifa_local, wire(0xc0000202),
        NULL, NULL, NULL, &request) == 0);
    CHECK(memcmp(request->data + 28, &address.native->ifa_list->ifa_local, 4) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY && ker_eth_device_cleanup(&device) == -EBUSY);
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(request, &clone) == 0 && ker_skb_free(request) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    CHECK(ker_skb_free(clone) == 0);
    struct ker_napi_runtime nr = {0}; struct ker_napi n = {0};
    CHECK(ker_napi_runtime_init(&nr) == 0 && ker_napi_init(&n, &nr, &device, 4, unused_poll, NULL) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    CHECK(ker_napi_cleanup(&n) == 0 && ker_napi_runtime_cleanup(&nr) == 0);
    struct ker_receive_runtime rx = {0}; struct ker_protocol_handler h = {0};
    CHECK(ker_receive_runtime_init(&rx, &context) == 0);
    CHECK(ker_protocol_register(&rx, &h, &device, rte_cpu_to_be_16(ETH_P_ARP), unused_receive, NULL) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    CHECK(ker_protocol_unregister(&h) == 0 && ker_receive_runtime_cleanup(&rx) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0 && ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0 && ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("IPv4 address: original layouts/prefix helpers, rollback, pins, offline cleanup and ARP source passed");
    return 0;
}
