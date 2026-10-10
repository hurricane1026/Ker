#include "check.h"
#include "eal.h"
#include "runtime/napi.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <pthread.h>
#include <linux/irqflags.h>
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_napi_runtime runtime;
static struct ker_napi a, b;
struct driver {
    unsigned int left, calls, last_budget, delivered;
    bool missed, no_complete, excessive, fail, wire;
};
static struct driver da, db;
static int poll_driver(struct ker_napi *napi, unsigned int budget, void *arg)
{
    struct driver *d = arg;
    d->calls++; d->last_budget = budget;
    unsigned int untouched = 42;
    CHECK(ker_napi_runtime_poll(&runtime, 1, &untouched) == -EBUSY && untouched == 42);
    CHECK(ker_napi_disable(napi) == -EBUSY && ker_napi_cleanup(napi) == -EBUSY);
    CHECK(ker_napi_runtime_cleanup(&runtime) == -EBUSY);
    CHECK(ker_napi_complete(napi, budget) == -EINVAL);
    if (d->fail) return -EIO;
    if (d->excessive) return (int)budget + 1;
    unsigned int count = d->left < budget ? d->left : budget;
    d->left -= count;
    if (d->wire) {
        for (unsigned int i = 0; i < count; ++i) {
            struct rte_mbuf *packet = ker_packet_alloc(&pool);
            CHECK(packet != NULL);
            unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(packet, 18);
            CHECK(bytes != NULL);
            memcpy(bytes, device.native->dev_addr, 6);
            memcpy(bytes + 6, device.native->dev_addr, 6);
            __be16 protocol = rte_cpu_to_be_16(ETH_P_IP);
            memcpy(bytes + 12, &protocol, 2); memset(bytes + 14, 0, 4);
            struct sk_buff *skb = NULL;
            CHECK(ker_eth_receive(&device, packet, &skb) == 0);
            CHECK(skb->protocol == protocol && skb->len == 4 && skb->dev == device.native);
            CHECK(ker_skb_free(skb) == 0); d->delivered++;
        }
    }
    if (d->missed) {
        CHECK(ker_napi_schedule(napi) == 0);
        d->missed = false;
    }
    if (count < budget && !d->no_complete) {
        CHECK(ker_napi_complete(napi, count) >= 0);
        CHECK(ker_napi_complete(napi, count) == -EPERM);
    }
    return (int)count;
}
static void *foreign(void *arg)
{
    (void)arg;
    unsigned int done = 42;
    unsigned long irq;
    local_irq_save(irq);
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == -EXDEV && done == 42);
    local_irq_restore(irq);
    CHECK(ker_napi_schedule(&a) == -EXDEV);
    CHECK(ker_napi_enable(&a) == -EXDEV);
    CHECK(ker_napi_disable(&a) == -EXDEV);
    CHECK(ker_napi_cleanup(&a) == -EXDEV);
    CHECK(ker_napi_runtime_cleanup(&runtime) == -EXDEV);
    CHECK(ker_napi_runtime_poll(&runtime, 1, &done) == -EXDEV && done == 42);
    return NULL;
}
static int rx_poll(void *arg, unsigned int budget)
{
    unsigned int done;
    int error = ker_napi_runtime_poll(arg, budget, &done);
    return error ? error : (int)done;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "napi_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "napi_skb") == 0);
    const unsigned char mac[6] = {2, 1, 2, 3, 4, 5};
    CHECK(ker_eth_device_init(&device, &context, "ker0", 1, mac) == 0);
    CHECK(ker_napi_runtime_init(&runtime) == 0);
    CHECK(ker_napi_init(&a, &runtime, &device, 0, poll_driver, &da) == -EINVAL);
    CHECK(ker_napi_init(&a, &runtime, &device, 4, poll_driver, &da) == 0);
    CHECK(ker_napi_init(&b, &runtime, &device, 4, poll_driver, &db) == 0);
    CHECK(device.napi_live == 2 && ker_eth_device_cleanup(&device) == -EBUSY);
    CHECK(ker_napi_schedule(&a) == -ESHUTDOWN);
    CHECK(!napi_schedule_prep(&a.native)); /* exact Linux DISABLE test */
    CHECK(ker_napi_enable(&a) == 0 && ker_napi_enable(&b) == 0);
    CHECK(ker_napi_complete(&a, 0) == -EPERM);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    unsigned int done = 42;
    unsigned long irq;
    local_irq_save(irq);
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == -EBUSY && done == 42);
    local_irq_restore(irq);
    CHECK(ker_napi_schedule(&a) == 1 && ker_napi_schedule(&a) == 0);
    CHECK(a.native.state & NAPIF_STATE_MISSED);
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == 0 && done == 0);
    CHECK(napi_is_scheduled(&a.native) && !(a.native.state & NAPIF_STATE_MISSED));
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == 0 && done == 0);
    CHECK(!napi_is_scheduled(&a.native) && a.native.list_owner == -1);
    da.left = db.left = 5;
    CHECK(ker_napi_schedule(&a) == 1 && ker_napi_schedule(&b) == 1);
    unsigned int bcalls = db.calls;
    CHECK(ker_napi_runtime_poll(&runtime, 2, &done) == 0 && done == 2 && da.last_budget == 2);
    CHECK(db.calls == bcalls);
    CHECK(ker_napi_runtime_poll(&runtime, 2, &done) == 0 && done == 2 && db.calls == bcalls + 1);
    CHECK(ker_napi_runtime_poll(&runtime, 8, &done) == 0 && done == 6);
    CHECK(!napi_is_scheduled(&a.native) && !napi_is_scheduled(&b.native));
    da.missed = true;
    CHECK(ker_napi_schedule(&a) == 1);
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == 0 && done == 0 && napi_is_scheduled(&a.native));
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == 0 && !napi_is_scheduled(&a.native));
    da.no_complete = true;
    CHECK(ker_napi_schedule(&a) == 1);
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == -EPROTO && done == 0);
    da.no_complete = false; da.excessive = true;
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == -EPROTO && done == 0);
    da.excessive = false; da.fail = true;
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == -EIO && done == 0);
    da.fail = false;
    CHECK(ker_napi_runtime_poll(&runtime, 4, &done) == 0 && !napi_is_scheduled(&a.native));
    a.native.gro_flush_timeout = 1;
    CHECK(ker_napi_schedule(&a) == -ENOTSUP);
    a.native.gro_flush_timeout = 0;
    a.native.state |= NAPIF_STATE_IN_BUSY_POLL;
    CHECK(ker_napi_schedule(&a) == -ENOTSUP);
    a.native.state &= ~NAPIF_STATE_IN_BUSY_POLL;
    da.left = 3; da.wire = true;
    CHECK(ker_napi_schedule(&a) == 1);
    unsigned int calls = da.calls;
    CHECK(ker_napi_runtime_poll(&runtime, 0, &done) == 0 && done == 0 && da.calls == calls);
    struct ker_worker worker = {0};
    struct ker_worker_config wc = {.timer_budget = 1, .rx_budget = 2, .packet_low = 1, .packet_high = 2};
    struct ker_worker_ops ops = {.rx = rx_poll, .arg = &runtime};
    CHECK(ker_worker_init(&worker, &pool, &wc, &ops) == 0);
    struct rte_mbuf *held[30];
    for (unsigned int i = 0; i < 30; ++i) CHECK((held[i] = ker_packet_alloc(&pool)) != NULL);
    struct ker_worker_result result;
    CHECK(ker_worker_poll(&worker, 1, &result) == 0 && result.rx == 0 && da.calls == calls);
    for (unsigned int i = 0; i < 30; ++i) ker_packet_free(held[i]);
    CHECK(ker_worker_poll(&worker, 2, &result) == 0 && result.rx == 2 && da.delivered == 2);
    CHECK(ker_worker_poll(&worker, 3, &result) == 0 && result.rx == 1 && da.delivered == 3);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_napi_cleanup(&a) == -EBUSY);
    CHECK(ker_napi_schedule(&a) == 1);
    CHECK(ker_napi_disable(&a) == 0 && list_empty(&a.native.poll_list));
    CHECK(ker_napi_disable(&b) == 0);
    CHECK(ker_napi_cleanup(&a) == 0 && ker_napi_cleanup(&b) == 0);
    CHECK(ker_napi_runtime_cleanup(&runtime) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
