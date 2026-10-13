#include "runtime/flow-ring.h"
#include "runtime/worker.h"
#include <errno.h>
#include <limits.h>
#include <linux/irqflags.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <string.h>

static int ready(struct ker_flow_ring *adapter)
{
    if (!adapter || !adapter->ring || !adapter->ring->ring || !adapter->context ||
        !adapter->context->attached) return -EINVAL;
    if (rte_lcore_id() != adapter->owner_lcore) return -EXDEV;
    if (adapter->polling || adapter->context->delivering || ker_local_irq_disabled()) return -EBUSY;
    return 0;
}

int ker_flow_ring_init(struct ker_flow_ring *adapter, struct ker_tx_ring *ring,
    struct ker_flow_context *context, uint64_t domain, enum ker_flow_direction direction)
{
    if (!adapter || !ring || !ring->ring || !context || !context->attached ||
        (direction != KER_FLOW_INGRESS && direction != KER_FLOW_EGRESS)) return -EINVAL;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    if (context->worker->polling || context->delivering || ker_local_irq_disabled()) return -EBUSY;
    if (adapter->ring || adapter->context || adapter->pending || adapter->polling) return -EALREADY;
    if (ring->consumers) return -EBUSY;
    if (context->flow_ring_live == UINT_MAX) return -EOVERFLOW;
    ring->consumers++;
    context->flow_ring_live++;
    *adapter = (struct ker_flow_ring){.ring = ring, .context = context,
        .domain = domain, .direction = direction, .owner_lcore = context->lcore};
    return 0;
}

int ker_flow_ring_poll(void *arg, unsigned int budget)
{
    struct ker_flow_ring *adapter = arg;
    int error = ready(adapter);
    if (error) return error;
    if (budget > INT_MAX) return -EOVERFLOW;
    if (!budget) return 0;
    adapter->polling = true;
    adapter->last_completed = adapter->last_dropped = 0;
    adapter->last_error = 0;
    unsigned int completed = 0;
    while (completed < budget) {
        if (!adapter->pending) {
            void *object = NULL;
            error = rte_ring_sc_dequeue(adapter->ring->ring, &object);
            if (error == -ENOENT) break;
            if (error) { adapter->last_error = error; break; }
            if (!object) { adapter->last_error = -EIO; break; }
            adapter->pending = object;
        }
        struct rte_mbuf *packet = adapter->pending;
        error = ker_flow_submit(adapter->context, adapter->domain, adapter->direction, &packet);
        if (error == -ENOBUFS) { adapter->last_error = error; break; }
        if (error) {
            if (error == -EINVAL || error == -EMSGSIZE || error == -ENOTSUP || error == -EOVERFLOW) {
                rte_pktmbuf_free(adapter->pending);
                adapter->pending = NULL;
                adapter->last_dropped++;
                completed++;
                adapter->last_error = error;
                continue;
            }
            adapter->last_error = error;
            break;
        }
        adapter->pending = NULL;
        completed++;
    }
    adapter->last_completed = completed;
    adapter->polling = false;
    return completed ? (int)completed : adapter->last_error;
}

int ker_flow_ring_cancel(struct ker_flow_ring *adapter, struct rte_mbuf **out)
{
    int error = ready(adapter);
    if (error) return error;
    if (!out) return -EINVAL;
    if (!adapter->pending) return 0;
    *out = adapter->pending;
    adapter->pending = NULL;
    return 1;
}

int ker_flow_ring_cleanup(struct ker_flow_ring *adapter)
{
    if (!adapter || !adapter->ring || !adapter->context) return -EINVAL;
    if (rte_lcore_id() != adapter->owner_lcore) return -EXDEV;
    if (adapter->polling || adapter->context->delivering || adapter->context->worker->polling ||
        ker_local_irq_disabled()) return -EBUSY;
    if (adapter->pending) return -EBUSY;
    if (!adapter->ring->consumers || !adapter->context->flow_ring_live) return -EIO;
    adapter->ring->consumers--;
    adapter->context->flow_ring_live--;
    *adapter = (struct ker_flow_ring){0};
    return 0;
}
