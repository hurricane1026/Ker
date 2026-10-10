#include "check.h"
#include "eal.h"
#include "runtime/receive.h"
#include "runtime/napi.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <linux/irqflags.h>
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_receive_runtime receiver;
static struct ker_eth_device device, other;
static struct ker_protocol_handler h1, h2, h3, collision, bound_other;
static struct sk_buff *retained;
static unsigned int calls[8], count;
struct action { unsigned int id; bool retain, clone, invalid; int status; };
static struct action x1 = {.id = 1}, x2 = {.id = 2}, x3 = {.id = 3};
static struct sk_buff *packet(struct ker_eth_device *dev, unsigned int protocol)
{
    struct rte_mbuf *mbuf = ker_packet_alloc(&pool);
    CHECK(mbuf != NULL);
    unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(mbuf, 18);
    CHECK(bytes != NULL);
    memcpy(bytes, dev->native->dev_addr, 6); memcpy(bytes + 6, dev->native->dev_addr, 6);
    __be16 type = rte_cpu_to_be_16(protocol); memcpy(bytes + 12, &type, 2);
    memset(bytes + 14, 0x42, 4);
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive(dev, mbuf, &skb) == 0);
    return skb;
}
static int consume(struct sk_buff *skb, struct ker_protocol_handler *handler,
                   struct net_device *original, void *arg)
{
    struct action *action = arg;
    CHECK(original == skb->dev && skb->skb_iif == original->ifindex);
    CHECK(skb->mac_len == ETH_HLEN && skb->network_header == skb_headroom(skb));
    CHECK(skb->transport_header == skb->network_header);
    CHECK(count < 8); calls[count++] = action->id;
    CHECK(ker_protocol_unregister(handler) == -EBUSY);
    CHECK(ker_receive_runtime_cleanup(&receiver) == -EBUSY);
    CHECK(ker_eth_device_cleanup(original == device.native ? &device : &other) == -EBUSY);
    CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
    struct ker_receive_result result = {.handlers = 99, .status = 99};
    struct sk_buff *nested = skb;
    CHECK(ker_receive_dispatch(&receiver, &device, &nested, &result) == -EBUSY && nested == skb);
    if (action->clone) {
        struct sk_buff *copy = NULL;
        CHECK(ker_skb_clone(skb, &copy) == 0);
        CHECK(ker_skb_make_writable(copy, 0, 0) == 0);
        copy->data[0] = 0x99;
        CHECK(skb->data[0] == 0x42);
        CHECK(ker_skb_free(copy) == 0);
    }
    if (action->retain) { CHECK(retained == NULL); retained = skb; }
    else {
        CHECK(ker_skb_free(skb) == 0);
        /* Also after freeing the final reference: dispatch itself pins dev. */
        CHECK(ker_eth_device_cleanup(original == device.native ? &device : &other) == -EBUSY);
    }
    return action->invalid ? -EIO : action->status;
}
static void *foreign(void *arg)
{
    (void)arg;
    struct ker_receive_result result;
    struct sk_buff *skb = NULL;
    CHECK(ker_protocol_unregister(&h1) == -EXDEV);
    CHECK(ker_receive_runtime_cleanup(&receiver) == -EXDEV);
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -EXDEV);
    return NULL;
}
static void run(struct ker_eth_device *dev, unsigned int protocol, unsigned int expected, int status, int error)
{
    struct sk_buff *skb = packet(dev, protocol);
    struct ker_receive_result result;
    count = 0;
    CHECK(ker_receive_dispatch(&receiver, dev, &skb, &result) == error && skb == NULL);
    CHECK(result.handlers == expected && result.status == status && count == expected);
}
struct ingress { unsigned int left; };
static int napi_driver(struct ker_napi *napi, unsigned int budget, void *arg)
{
    struct ingress *in = arg;
    unsigned int work = in->left < budget ? in->left : budget;
    for (unsigned int i = 0; i < work; ++i) run(&device, ETH_P_ARP, 1, NET_RX_SUCCESS, 0);
    in->left -= work;
    if (work < budget) CHECK(ker_napi_complete(napi, work) >= 0);
    return (int)work;
}
static int rx(void *arg, unsigned int budget)
{
    unsigned int work;
    int error = ker_napi_runtime_poll(arg, budget, &work);
    return error ? error : (int)work;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 15) == 0);
    CHECK(ker_packet_pool_init(&pool, "rx_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "rx_skb") == 0);
    const unsigned char mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    CHECK(ker_eth_device_init(&other, &context, "eth1", 2, mac) == 0);
    CHECK(ker_receive_runtime_init(&receiver, &context) == 0);
    CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
    CHECK(ker_protocol_register(&receiver, &h1, NULL, rte_cpu_to_be_16(ETH_P_ALL), consume, &x1) == -ENOTSUP);
    CHECK(ker_protocol_register(&receiver, &h1, NULL, rte_cpu_to_be_16(ETH_P_IP), consume, &x1) == 0);
    CHECK(ker_protocol_register(&receiver, &h2, NULL, rte_cpu_to_be_16(ETH_P_IP), consume, &x2) == 0);
    CHECK(ker_protocol_register(&receiver, &h3, &device, rte_cpu_to_be_16(ETH_P_IP), consume, &x3) == 0);
    CHECK(ker_protocol_register(&receiver, &collision, NULL, rte_cpu_to_be_16(ETH_P_IP + PTYPE_HASH_SIZE), consume, &x1) == 0);
    CHECK(ker_protocol_register(&receiver, &bound_other, &other, rte_cpu_to_be_16(ETH_P_IP), consume, &x3) == 0);
    CHECK(ker_eth_device_cleanup(&device) == -EBUSY);
    struct ker_receive_runtime second = {0};
    struct ker_protocol_handler rejected = {0};
    CHECK(ker_receive_runtime_init(&second, &context) == 0);
    CHECK(ker_protocol_register(&second, &rejected, &device, rte_cpu_to_be_16(ETH_P_IP), consume, &x1) == -EBUSY);
    CHECK(ker_receive_runtime_cleanup(&second) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign, NULL) == 0 && pthread_join(thread, NULL) == 0);
    x2.retain = true; x1.clone = true; x3.status = NET_RX_DROP;
    run(&device, ETH_P_IP, 3, NET_RX_DROP, 0);
    CHECK(calls[0] == 2 && calls[1] == 1 && calls[2] == 3);
    CHECK(retained && refcount_read(&retained->users) == 1 && context.live == 1);
    CHECK(retained->data[0] == 0x42);
    CHECK(ker_skb_free(retained) == 0); retained = NULL; x2.retain = false;
    run(&other, ETH_P_IP, 3, NET_RX_DROP, 0);
    CHECK(calls[2] == 3);
    run(&device, 0x88b5, 0, NET_RX_DROP, 0);
    x1.invalid = true; run(&device, ETH_P_IP, 3, NET_RX_DROP, -EPROTO); x1.invalid = false;
    struct sk_buff *skb = packet(&device, ETH_P_IP), *original = skb;
    struct ker_receive_result result = {.handlers = 99, .status = 99};
    skb->protocol = rte_cpu_to_be_16(ETH_P_8021Q);
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -ENOTSUP && skb == original && result.handlers == 99);
    skb->protocol = rte_cpu_to_be_16(ETH_P_IP);
    CHECK(ker_skb_get(skb) == 0);
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -EBUSY && skb == original);
    CHECK(ker_skb_free(skb) == 0);
    unsigned long irq;
    local_irq_save(irq);
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -EBUSY && skb == original);
    local_irq_restore(irq);
    skb_shinfo(skb)->flags = SKBFL_ZEROCOPY_ENABLE;
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -ENOTSUP && skb == original);
    skb_shinfo(skb)->flags = 0;
    skb->vlan_all = 1;
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -ENOTSUP && skb == original);
    skb->vlan_all = 0;
    skb->pfmemalloc = 1;
    CHECK(ker_receive_dispatch(&receiver, &device, &skb, &result) == -ENOTSUP && skb == original);
    skb->pfmemalloc = 0;
    CHECK(ker_skb_free(skb) == 0);
    CHECK(ker_protocol_unregister(&h1) == 0 && ker_protocol_unregister(&h2) == 0);
    CHECK(ker_protocol_unregister(&h3) == 0 && ker_protocol_unregister(&bound_other) == 0);
    CHECK(ker_protocol_unregister(&collision) == 0);
    CHECK(ker_protocol_register(&receiver, &h1, NULL, rte_cpu_to_be_16(ETH_P_ARP), consume, &x1) == 0);
    run(&device, ETH_P_ARP, 1, NET_RX_SUCCESS, 0);
    struct ker_protocol_handler many[KER_RECEIVE_MAX_HANDLERS] = {0};
    for (unsigned int i = 0; i < KER_RECEIVE_MAX_HANDLERS - 1; ++i)
        CHECK(ker_protocol_register(&receiver, &many[i], NULL, rte_cpu_to_be_16(ETH_P_ARP), consume, &x1) == 0);
    CHECK(ker_protocol_register(&receiver, &many[KER_RECEIVE_MAX_HANDLERS - 1], NULL,
        rte_cpu_to_be_16(ETH_P_ARP), consume, &x1) == -ENOSPC);
    for (unsigned int i = 0; i < KER_RECEIVE_MAX_HANDLERS - 1; ++i)
        CHECK(ker_protocol_unregister(&many[i]) == 0);
    struct ker_napi_runtime nr = {0}; struct ker_napi napi = {0}; struct ingress ingress = {.left = 3};
    CHECK(ker_napi_runtime_init(&nr) == 0 && ker_napi_init(&napi, &nr, &device, 4, napi_driver, &ingress) == 0);
    CHECK(ker_napi_enable(&napi) == 0 && ker_napi_schedule(&napi) == 1);
    struct ker_worker worker = {0};
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 2};
    struct ker_worker_ops ops = {.rx = rx, .arg = &nr};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    struct ker_worker_result progress;
    CHECK(ker_worker_poll(&worker, 1, &progress) == 0 && progress.rx == 2);
    CHECK(ker_worker_poll(&worker, 2, &progress) == 0 && progress.rx == 1 && ingress.left == 0);
    CHECK(ker_worker_cleanup(&worker) == 0 && ker_napi_disable(&napi) == 0 && ker_napi_cleanup(&napi) == 0);
    CHECK(ker_napi_runtime_cleanup(&nr) == 0);
    CHECK(ker_protocol_unregister(&h1) == 0);
    CHECK(ker_receive_runtime_cleanup(&receiver) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_eth_device_cleanup(&other) == 0);
    CHECK(context.live == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("receive: original matching/delivery, references, device binding, validation and NAPI ingress passed");
    return 0;
}
