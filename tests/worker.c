#include "check.h"
#include "eal.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

struct fixture {
    struct ker_worker worker;
    struct ker_packet_pool pool;
    struct rte_mbuf *held[31];
    unsigned int held_count;
    unsigned int tx_calls;
    unsigned int rx_calls;
    unsigned int timer_calls;
    unsigned int service_calls;
    void *service_free;
    unsigned int last_rx_budget;
    bool release;
    bool tx_fail;
    bool rx_overrun;
};
static int service_poll(void *arg, unsigned int budget)
{
    struct fixture *f = arg;
    CHECK(budget == 1);
    ++f->service_calls;
    if (f->service_free) {
        kfree(f->service_free);
        f->service_free = NULL;
        return 1;
    }
    return 0;
}
static int tx_poll(void *arg, unsigned int budget)
{
    struct fixture *f = arg;
    ++f->tx_calls;
    if (f->tx_fail)
        return -EIO;
    unsigned int count = 0;
    while (f->release && f->held_count && count < budget) {
        ker_packet_free(f->held[--f->held_count]);
        ++count;
    }
    return (int)count;
}
static int rx_poll(void *arg, unsigned int budget)
{
    struct fixture *f = arg;
    ++f->rx_calls;
    f->last_rx_budget = budget;
    if (f->rx_overrun)
        return (int)budget + 1;
    unsigned int count = 0;
    while (count < budget) {
        struct rte_mbuf *packet = ker_packet_alloc(&f->pool);
        if (!packet)
            break;
        CHECK(f->held_count < 31);
        f->held[f->held_count++] = packet;
        ++count;
    }
    return (int)count;
}
static void timer_tick(struct ker_timer *timer, void *arg)
{
    (void)timer;
    struct fixture *f = arg;
    ++f->timer_calls;
    struct ker_worker_result untouched = {.rx = 123};
    CHECK(ker_worker_poll(&f->worker, 10, &untouched) == -EBUSY);
    CHECK(untouched.rx == 123);
    CHECK(ker_worker_cleanup(&f->worker) == -EBUSY);
}
static void *wrong_worker(void *arg)
{
    struct fixture *f = arg;
    CHECK(rte_thread_register() == 0);
    struct ker_worker_result untouched = {.rx = 123};
    CHECK(ker_worker_poll(&f->worker, 10, &untouched) == -EXDEV && untouched.rx == 123);
    CHECK(ker_worker_cleanup(&f->worker) == -EXDEV);
    rte_thread_unregister();
    return NULL;
}
struct foreign_cache {
    struct ker_packet_pool *pool;
    pthread_barrier_t barrier;
    unsigned int cached;
};
static void cache_barrier(struct foreign_cache *f)
{
    int error = pthread_barrier_wait(&f->barrier);
    CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *cache_holder(void *arg)
{
    struct foreign_cache *f = arg;
    CHECK(rte_thread_register() == 0);
    struct rte_mbuf *packet = rte_pktmbuf_alloc(f->pool->mbufs);
    CHECK(packet != NULL);
    rte_pktmbuf_free(packet);
    struct rte_mempool_cache *cache = rte_mempool_default_cache(f->pool->mbufs, rte_lcore_id());
    CHECK(cache != NULL && cache->len != 0);
    f->cached = cache->len;
    cache_barrier(f);
    cache_barrier(f);
    rte_mempool_cache_flush(cache, f->pool->mbufs);
    rte_thread_unregister();
    return NULL;
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_memory_budget_config limit = {2 * RTE_CACHE_LINE_SIZE, RTE_CACHE_LINE_SIZE, 0};
    CHECK(ker_memory_budget_configure(KER_MEMORY_CONTROL, &limit) == 0);
    struct fixture f = {0};
    /* Enable cache: local availability must include cached free descriptors. */
    CHECK(ker_packet_pool_init(&f.pool, "ker_worker_packets", 31, 2, 1024, SOCKET_ID_ANY) == 0);
    /* Native allocation, cloning and final backing release are visible without
     * any ker-owned packet reference counter or allocator bookkeeping. */
    struct rte_mbuf *native = rte_pktmbuf_alloc(f.pool.mbufs);
    CHECK(native != NULL);
    struct rte_mbuf *clone = rte_pktmbuf_clone(native, f.pool.mbufs);
    CHECK(clone != NULL);
    unsigned int available;
    CHECK(ker_packet_pool_available(&f.pool, &available) == 0 && available == 29);
    rte_pktmbuf_free(native);
    CHECK(ker_packet_pool_available(&f.pool, &available) == 0 && available == 29);
    rte_pktmbuf_free(clone);
    CHECK(ker_packet_pool_available(&f.pool, &available) == 0 && available == 31);
    struct foreign_cache foreign = {.pool = &f.pool};
    CHECK(pthread_barrier_init(&foreign.barrier, NULL, 2) == 0);
    pthread_t holder;
    CHECK(pthread_create(&holder, NULL, cache_holder, &foreign) == 0);
    cache_barrier(&foreign);
    CHECK(ker_packet_pool_available(&f.pool, &available) == 0 && available == 31 - foreign.cached);
    cache_barrier(&foreign);
    CHECK(pthread_join(holder, NULL) == 0);
    CHECK(pthread_barrier_destroy(&foreign.barrier) == 0);
    CHECK(ker_packet_pool_available(&f.pool, &available) == 0 && available == 31);
    struct ker_worker_config config = {.timer_budget = 1, .service_budget = 1, .tx_budget = 2, .rx_budget = 8,
        .packet_low = 3, .packet_high = 7, .rx_margin = 3};
    struct ker_worker_ops ops = {.service = service_poll, .tx = tx_poll, .rx = rx_poll, .arg = &f};
    CHECK(ker_worker_init(&f.worker, &f.pool, &config, &ops) == 0);
    CHECK(ker_worker_init(&f.worker, &f.pool, &config, &ops) == -EALREADY);
    struct ker_timer timer;
    ker_timer_init(&timer, timer_tick, &f);
    CHECK(ker_timer_arm(&f.worker.timers, &timer, 10) == 0);
    struct ker_worker_result result;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.timers == 1 && result.tx == 0 && result.rx == 8);
    CHECK(result.packet_available == 31 && f.held_count == 8);
    CHECK(ker_packet_pool_cleanup(&f.pool) == -EBUSY);
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0 && result.rx == 8);
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0 && result.rx == 8);
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.packet_available == 7 && result.rx_budget == 4 && result.rx == 4);
    CHECK(f.held_count == 28);
    CHECK(ker_timer_arm(&f.worker.timers, &timer, 10) == 0);
    unsigned int rx_calls = f.rx_calls;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.timers == 1 && result.rx == 0 && f.rx_calls == rx_calls);
    CHECK(result.pressure & KER_WORKER_PACKET_PRESSURE);
    CHECK(f.service_calls == f.tx_calls);
    /* TX progresses under pressure; hysteresis requires the high free count. */
    f.release = true;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.tx == 2 && result.packet_available == 5 && result.rx == 0);
    CHECK(result.pressure & KER_WORKER_PACKET_PRESSURE);
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.tx == 2 && result.packet_available == 7 && result.rx == 4);
    CHECK(!result.pressure);
    /* Control-memory pressure also stops RX, but timers and TX still run. */
    void *control = kmalloc(1, GFP_KERNEL);
    CHECK(control != NULL);
    CHECK(ker_timer_arm(&f.worker.timers, &timer, 10) == 0);
    rx_calls = f.rx_calls;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.timers == 1 && result.tx == 2 && f.rx_calls == rx_calls);
    CHECK(result.pressure & (1U << KER_MEMORY_CONTROL));
    /* Queued application work can release retained state and resume ingress
     * in this same turn; it is not gated behind RX admission. */
    f.service_free = control;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0);
    CHECK(result.service == 1 && result.rx > 0 && !result.pressure);
    while (f.held_count) ker_packet_free(f.held[--f.held_count]);
    CHECK(ker_worker_poll(&f.worker, 10, &result) == 0 && result.rx == 8);
    f.tx_fail = true;
    CHECK(ker_timer_arm(&f.worker.timers, &timer, 10) == 0);
    rx_calls = f.rx_calls;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == -EIO);
    CHECK(result.timers == 1 && f.rx_calls == rx_calls);
    f.tx_fail = false;
    f.rx_overrun = true;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == -EPROTO);
    f.rx_overrun = false;
    unsigned long flags;
    local_irq_save(flags);
    result.rx = 123;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == -EBUSY && result.rx == 123);
    local_irq_restore(flags);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wrong_worker, &f) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    while (f.held_count) ker_packet_free(f.held[--f.held_count]);
    CHECK(ker_packet_pool_cleanup(&f.pool) == 0);
    result.rx = 123;
    CHECK(ker_worker_poll(&f.worker, 10, &result) == -ESHUTDOWN && result.rx == 123);
    unsigned int fired = f.timer_calls;
    CHECK(ker_timer_arm(&f.worker.timers, &timer, 20) == 0);
    CHECK(ker_worker_cleanup(&f.worker) == 0);
    CHECK(timer.owner == NULL && f.timer_calls == fired);
    CHECK(ker_worker_cleanup(&f.worker) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Worker: RX admission, native pool headroom, timer/TX progress and recovery passed");
    return 0;
}
