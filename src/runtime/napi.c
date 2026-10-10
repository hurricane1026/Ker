#include "runtime/napi.h"
#include "runtime/memory.h"
#include <linux/container_of.h>
#include <linux/irqflags.h>
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>

static int driver_poll(struct napi_struct *native, int budget)
{
    struct ker_napi *napi = container_of(native, struct ker_napi, native);
    return napi->poll(napi, (unsigned int)budget, napi->arg);
}
static int runtime_valid(struct ker_napi_runtime *runtime)
{
    if (!runtime || !runtime->initialized) return -EINVAL;
    if (rte_lcore_id() != runtime->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    return 0;
}
static int napi_valid(struct ker_napi *napi)
{
    if (!napi || !napi->initialized) return -EINVAL;
    int error = runtime_valid(napi->runtime);
    if (error) return error;
    struct napi_struct *n = &napi->native;
    if (n->weight <= 0 || n->poll != driver_poll) return -EINVAL;
    if (n->dev != napi->device->native || !n->dev) return -ESHUTDOWN;
    unsigned long allowed = NAPIF_STATE_SCHED | NAPIF_STATE_MISSED |
        NAPIF_STATE_DISABLE | NAPIF_STATE_NO_BUSY_POLL;
    if ((n->state & ~allowed) || n->thread || n->config || n->skb || n->gro_flush_timeout ||
        n->irq_suspend_timeout || n->defer_hard_irqs || n->defer_hard_irqs_count ||
        n->gro.bitmask || n->gro.rx_count || !list_empty(&n->gro.rx_list)) return -ENOTSUP;
    for (unsigned int i = 0; i < GRO_HASH_BUCKETS; ++i)
        if (n->gro.hash[i].count || !list_empty(&n->gro.hash[i].list)) return -ENOTSUP;
    return 0;
}
int ker_napi_runtime_init(struct ker_napi_runtime *runtime)
{
    if (!runtime) return -EINVAL;
    if (runtime->initialized) return -EALREADY;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -EPERM;
    *runtime = (struct ker_napi_runtime){.lcore = rte_lcore_id(), .initialized = true};
    INIT_LIST_HEAD(&runtime->scheduled);
    return 0;
}
int ker_napi_runtime_cleanup(struct ker_napi_runtime *runtime)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (runtime->polling || runtime->live || !list_empty(&runtime->scheduled)) return -EBUSY;
    *runtime = (struct ker_napi_runtime){0};
    return 0;
}
int ker_napi_init(struct ker_napi *napi, struct ker_napi_runtime *runtime,
    struct ker_eth_device *device, unsigned int weight, ker_napi_poll_fn poll, void *arg)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (!napi || !device || !device->native || !poll || !weight || weight > INT_MAX) return -EINVAL;
    if (runtime->polling) return -EBUSY;
    if (device->lcore != runtime->lcore) return -EXDEV;
    if (napi->initialized) return -EALREADY;
    if (runtime->live == UINT_MAX || device->napi_live == UINT_MAX) return -EOVERFLOW;
    *napi = (struct ker_napi){.runtime = runtime, .device = device, .poll = poll,
        .arg = arg, .initialized = true};
    struct napi_struct *n = &napi->native;
    n->state = NAPIF_STATE_DISABLE | NAPIF_STATE_NO_BUSY_POLL;
    n->weight = (int)weight; n->poll = driver_poll; n->dev = device->native; n->list_owner = -1; n->irq = -1;
    INIT_LIST_HEAD(&n->poll_list); INIT_LIST_HEAD(&n->dev_list); INIT_LIST_HEAD(&n->gro.rx_list);
    for (unsigned int i = 0; i < GRO_HASH_BUCKETS; ++i) INIT_LIST_HEAD(&n->gro.hash[i].list);
    runtime->live++; device->napi_live++;
    return 0;
}
int ker_napi_enable(struct ker_napi *napi)
{
    int error = napi_valid(napi);
    if (error) return error;
    if (napi->runtime->polling) return -EBUSY;
    if (napi->enabled) return -EALREADY;
    napi->native.state = NAPIF_STATE_NO_BUSY_POLL;
    napi->enabled = true;
    return 0;
}
int ker_napi_disable(struct ker_napi *napi)
{
    int error = napi_valid(napi);
    if (error) return error;
    if (napi->runtime->polling) return -EBUSY;
    if (!list_empty(&napi->native.poll_list)) list_del_init(&napi->native.poll_list);
    napi->native.state = NAPIF_STATE_DISABLE | NAPIF_STATE_NO_BUSY_POLL;
    napi->native.list_owner = -1; napi->enabled = false;
    return 0;
}
int ker_napi_cleanup(struct ker_napi *napi)
{
    int error = napi_valid(napi);
    if (error) return error;
    if (napi->enabled || napi->runtime->polling) return -EBUSY;
    napi->runtime->live--; napi->device->napi_live--;
    *napi = (struct ker_napi){0};
    return 0;
}
/* Called by the original completion when a MISSED schedule needs another pass.
 * Raw Linux entry points are private: only guarded ker_napi_* calls are valid. */
void __napi_schedule(struct napi_struct *native)
{
    struct ker_napi *napi = container_of(native, struct ker_napi, native);
    BUG_ON(!napi->initialized || rte_lcore_id() != napi->runtime->lcore ||
           !napi->enabled || !napi_is_scheduled(native) || !list_empty(&native->poll_list));
    native->list_owner = (int)napi->runtime->lcore;
    list_add_tail(&native->poll_list, &napi->runtime->scheduled);
}
int ker_napi_schedule(struct ker_napi *napi)
{
    int error = napi_valid(napi);
    if (error) return error;
    if (!napi->enabled) return -ESHUTDOWN;
    return napi_schedule(&napi->native) ? 1 : 0;
}
int ker_napi_complete(struct ker_napi *napi, unsigned int work_done)
{
    int error = napi_valid(napi);
    if (error) return error;
    if (!napi->polling || napi->completed || !napi_is_scheduled(&napi->native)) return -EPERM;
    if (work_done >= napi->active_budget) return -EINVAL;
    napi->completed = true;
    return napi_complete_done(&napi->native, (int)work_done) ? 1 : 0;
}
int ker_napi_runtime_poll(struct ker_napi_runtime *runtime, unsigned int budget,
    unsigned int *work_done)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (!work_done || budget > INT_MAX) return -EINVAL;
    if (runtime->polling || ker_local_irq_disabled()) return -EBUSY;
    *work_done = 0;
    if (!budget) return 0;
    struct list_head ready;
    INIT_LIST_HEAD(&ready);
    /* Snapshot this round; new schedules and repolls go to scheduled. */
    if (!list_empty(&runtime->scheduled)) {
        ready.next = runtime->scheduled.next; ready.prev = runtime->scheduled.prev;
        ready.next->prev = &ready; ready.prev->next = &ready;
        INIT_LIST_HEAD(&runtime->scheduled);
    }
    runtime->polling = true;
    while (!list_empty(&ready) && *work_done < budget) {
        struct napi_struct *n = container_of(ready.next, struct napi_struct, poll_list);
        struct ker_napi *napi = container_of(n, struct ker_napi, native);
        error = napi_valid(napi);
        if (error) break;
        list_del_init(&n->poll_list);
        unsigned int remaining = budget - *work_done;
        unsigned int allowed = (unsigned int)n->weight < remaining ? (unsigned int)n->weight : remaining;
        napi->active_budget = allowed; napi->polling = true; napi->completed = false;
        int count = n->poll(n, (int)allowed);
        napi->polling = false; napi->active_budget = 0; napi->completed = false;
        error = count < 0 ? count : (unsigned int)count > allowed ? -EPROTO : 0;
        if (!error) {
            *work_done += (unsigned int)count;
            if ((unsigned int)count < allowed && napi_is_scheduled(n) && list_empty(&n->poll_list))
                error = -EPROTO; /* short work without completion */
            else if ((unsigned int)count == allowed && !napi_is_scheduled(n))
                error = -EPROTO; /* full work must keep scheduling ownership */
        }
        if (napi_is_scheduled(n) && list_empty(&n->poll_list)) __napi_schedule(n);
        if (error) break;
    }
    /* Unvisited old work goes first next time, before new work/repolls. */
    if (!list_empty(&ready)) {
        struct list_head *first = ready.next, *last = ready.prev, *next = runtime->scheduled.next;
        runtime->scheduled.next = first; first->prev = &runtime->scheduled;
        last->next = next; next->prev = last;
    }
    runtime->polling = false;
    return error;
}
