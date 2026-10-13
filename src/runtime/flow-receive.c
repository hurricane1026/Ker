#include "runtime/flow-receive.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/irqflags.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <string.h>

static void receive_enqueue(void *arg, const struct ker_flow_key *key,
    struct rte_mbuf *packet)
{
    (void)key;
    struct ker_flow_receive *receive = arg;
    int error = ker_tx_ring_sink(packet, &receive->queue);
    if (!error) return;
    receive->last_enqueue_error = error;
    receive->overflow_dropped++;
    rte_pktmbuf_free(packet);
}

int ker_flow_receive_init(struct ker_flow_receive *receive,
    struct ker_flow_fabric *fabric, struct ker_worker *worker,
    unsigned int worker_id, struct ker_eth_device *device,
    struct ker_receive_runtime *runtime,
    const struct ker_flow_receive_config *config)
{
    if (!receive || !fabric || !worker || !device || !runtime || !config ||
        !config->name || !config->capacity || !device->context ||
        !runtime->context || !runtime->initialized || !worker->initialized ||
        !worker->packets || !worker->backing_pool ||
        worker->packets != runtime->context->packets ||
        worker->backing_pool != runtime->context->packets->mbufs ||
        device->context != runtime->context)
        return -EINVAL;
    if (worker->lcore == LCORE_ID_ANY || device->lcore != worker->lcore ||
        runtime->lcore != worker->lcore || runtime->context->lcore != worker->lcore ||
        rte_lcore_id() != worker->lcore) return -EXDEV;
    if (receive->initialized || receive->queue.ring || receive->rx.ring ||
        receive->context.attached) return -EALREADY;
    if (worker->polling || runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;

    int error = ker_tx_ring_init(&receive->queue, config->name,
        config->capacity, config->socket_id);
    if (error) return error;
    error = ker_rx_ring_init(&receive->rx, &receive->queue, device, runtime,
        config->headroom);
    if (error) goto fail_queue;
    error = ker_flow_attach(&receive->context, fabric, worker, worker_id,
        receive_enqueue, receive);
    if (error) goto fail_rx;
    receive->context.receive_owned = true;
    receive->owner_lcore = worker->lcore;
    receive->initialized = true;
    return 0;

fail_rx:
    (void)ker_rx_ring_cleanup(&receive->rx);
fail_queue:
    (void)ker_tx_ring_cleanup(&receive->queue);
    return error;
}

struct ker_flow_context *ker_flow_receive_context(struct ker_flow_receive *receive)
{
    return receive && receive->initialized ? &receive->context : NULL;
}

int ker_flow_receive_poll(void *arg, unsigned int budget)
{
    struct ker_flow_receive *receive = arg;
    if (!receive || !receive->initialized) return -EINVAL;
    return ker_rx_ring_poll(&receive->rx, budget);
}

int ker_flow_receive_cancel(struct ker_flow_receive *receive,
    struct rte_mbuf **out)
{
    if (!receive || !receive->initialized) return -EINVAL;
    if (rte_lcore_id() != receive->owner_lcore) return -EXDEV;
    if (receive->context.worker->polling || receive->context.delivering ||
        receive->rx.polling || receive->rx.runtime->dispatching ||
        ker_local_irq_disabled()) return -EBUSY;
    return ker_rx_ring_cancel(&receive->rx, out);
}

int ker_flow_receive_cleanup(struct ker_flow_receive *receive)
{
    if (!receive || !receive->initialized) return -EINVAL;
    if (rte_lcore_id() != receive->owner_lcore) return -EXDEV;
    if (receive->context.worker->polling || receive->context.delivering ||
        receive->rx.polling || receive->rx.runtime->dispatching ||
        ker_local_irq_disabled()) return -EBUSY;
    if (receive->context.flow_ring_live || receive->rx.pending ||
        !rte_ring_empty(receive->context.inbox) ||
        !rte_ring_empty(receive->queue.ring)) return -EBUSY;

    receive->context.receive_owned = false;
    int error = ker_flow_detach(&receive->context);
    if (error) {
        receive->context.receive_owned = true;
        return error;
    }
    error = ker_rx_ring_cleanup(&receive->rx);
    if (error) return error;
    error = ker_tx_ring_cleanup(&receive->queue);
    if (error) return error;
    *receive = (struct ker_flow_receive){0};
    return 0;
}
