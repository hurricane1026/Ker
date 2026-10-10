#include "runtime/worker.h"
#include "runtime/memory.h"
#include <linux/irqflags.h>
#include <rte_lcore.h>
#include <limits.h>
#include <errno.h>

static int memory_active(void)
{
    struct ker_memory_budget_stats stats;
    return ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats);
}
int ker_worker_init(struct ker_worker *worker, struct ker_packet_pool *packets,
    const struct ker_worker_config *config, const struct ker_worker_ops *ops)
{
    if (!worker || !packets || !packets->mbufs || !config || !ops ||
        !config->timer_budget || config->timer_budget > INT_MAX ||
        config->service_budget > INT_MAX || (config->service_budget && !ops->service) ||
        config->rx_budget > INT_MAX || config->tx_budget > INT_MAX ||
        (config->rx_budget && !ops->rx) || (config->tx_budget && !ops->tx) ||
        config->packet_high > packets->mbufs->size || config->rx_margin > packets->mbufs->size ||
        (!config->packet_high && config->packet_low) ||
        (config->packet_high && config->packet_low >= config->packet_high))
        return -EINVAL;
    if (worker->initialized)
        return -EALREADY;
    if (memory_active() || ker_local_irq_disabled())
        return -EPERM;
    *worker = (struct ker_worker){.packets = packets, .backing_pool = packets->mbufs,
        .config = *config, .ops = *ops, .lcore = rte_lcore_id(), .initialized = true};
    ker_runtime_init(&worker->timers);
    return 0;
}
int ker_worker_cleanup(struct ker_worker *worker)
{
    if (!worker)
        return -EINVAL;
    if (!worker->initialized)
        return 0;
    if (rte_lcore_id() != worker->lcore)
        return -EXDEV;
    if (worker->polling)
        return -EBUSY;
    int error = ker_runtime_cleanup(&worker->timers);
    if (!error)
        worker->initialized = false;
    return error;
}
static int assess_rx(struct ker_worker *worker, struct ker_worker_result *result)
{
    if (worker->packets->mbufs != worker->backing_pool)
        return -ESHUTDOWN;
    for (unsigned int domain = 0; domain < KER_MEMORY_DOMAIN_COUNT; ++domain) {
        struct ker_memory_budget_stats stats;
        int error = ker_memory_budget_stats(domain, &stats);
        if (error)
            return error;
        if (stats.pressure)
            result->pressure |= 1U << domain;
    }
    int error = ker_packet_pool_available(worker->packets, &result->packet_available);
    if (error)
        return error;
    if (worker->config.packet_high) {
        if (result->packet_available <= worker->config.packet_low)
            worker->packet_pressure = true;
        else if (result->packet_available >= worker->config.packet_high)
            worker->packet_pressure = false;
    }
    if (worker->packet_pressure)
        result->pressure |= KER_WORKER_PACKET_PRESSURE;
    if (!result->pressure && result->packet_available > worker->config.rx_margin) {
        unsigned int allowed = result->packet_available - worker->config.rx_margin;
        result->rx_budget = allowed < worker->config.rx_budget ? allowed : worker->config.rx_budget;
    }
    return 0;
}
static int io_poll(ker_worker_io callback, void *arg, unsigned int budget)
{
    if (!budget)
        return 0;
    int count = callback(arg, budget);
    return count >= 0 && (unsigned int)count > budget ? -EPROTO : count;
}
int ker_worker_poll(struct ker_worker *worker, int64_t now_ns, struct ker_worker_result *result)
{
    if (!worker || !worker->initialized || !result || now_ns < 0 || now_ns < worker->timers.now_ns)
        return -EINVAL;
    if (rte_lcore_id() != worker->lcore)
        return -EXDEV;
    if (worker->polling || ker_local_irq_disabled())
        return -EBUSY;
    if (memory_active() || worker->packets->mbufs != worker->backing_pool)
        return -ESHUTDOWN;
    struct ker_worker_result progress = {0};
    worker->polling = true;
    int count = ker_runtime_poll(&worker->timers, now_ns, worker->config.timer_budget);
    int error = count < 0 ? count : 0;
    if (!error) {
        progress.timers = (unsigned int)count;
        count = io_poll(worker->ops.service, worker->ops.arg, worker->config.service_budget);
        error = count < 0 ? count : 0;
        if (!error)
            progress.service = (unsigned int)count;
    }
    if (!error) {
        count = io_poll(worker->ops.tx, worker->ops.arg, worker->config.tx_budget);
        error = count < 0 ? count : 0;
        if (!error)
            progress.tx = (unsigned int)count;
    }
    if (!error)
        error = assess_rx(worker, &progress);
    if (!error) {
        count = io_poll(worker->ops.rx, worker->ops.arg, progress.rx_budget);
        error = count < 0 ? count : 0;
        if (!error)
            progress.rx = (unsigned int)count;
    }
    worker->polling = false;
    *result = progress;
    return error;
}
