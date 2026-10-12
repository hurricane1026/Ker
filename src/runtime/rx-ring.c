#include "runtime/rx-ring.h"
#include "runtime/buffer.h"
#include "runtime/memory.h"
#include <errno.h>
#include <limits.h>
#include <linux/irqflags.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <string.h>

static int valid(struct ker_rx_ring *rx)
{
    if (!rx || !rx->ring || !rx->ring->ring || !rx->device || !rx->device->native ||
        !rx->runtime || !rx->runtime->initialized)
        return -EINVAL;
    if (rte_lcore_id() != rx->owner_lcore) return -EXDEV;
    if (rx->polling || rx->runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;
    return 0;
}

int ker_rx_ring_init(struct ker_rx_ring *rx, struct ker_tx_ring *ring,
    struct ker_eth_device *device, struct ker_receive_runtime *runtime,
    unsigned int headroom)
{
    if (!rx || !ring || !device || !runtime || !ring->ring || !device->native ||
        !device->context || !runtime->initialized || !runtime->context ||
        !runtime->context->descriptors || !runtime->context->packets ||
        !runtime->context->packets->mbufs || (headroom & 1))
        return -EINVAL;
    if (runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;
    uint32_t room = rte_pktmbuf_data_room_size(runtime->context->packets->mbufs);
    uint32_t backing = RTE_ALIGN_FLOOR(room, SMP_CACHE_BYTES);
    size_t shared_info = ker_skb_shared_info_size();
    if (headroom > UINT16_MAX || backing <= shared_info ||
        (uint64_t)headroom + ETH_HLEN > backing - shared_info)
        return -ENOSPC;
    if (rx->ring || rx->device || rx->runtime || rx->pending) return -EALREADY;
    unsigned int lcore = rte_lcore_id();
    if (lcore == LCORE_ID_ANY || ring->owner_lcore == LCORE_ID_ANY || device->lcore != lcore ||
        runtime->lcore != lcore || device->context->lcore != lcore ||
        runtime->context != device->context)
        return -EXDEV;
    if ((device->receive_runtime && device->receive_runtime != runtime) ||
        (device->rx_ring_runtime && device->rx_ring_runtime != runtime)) return -EBUSY;
    if (ring->consumers || device->rx_ring_live || runtime->rx_ring_live) return -EBUSY;
    if (device->rx_ring_live == UINT_MAX || runtime->rx_ring_live == UINT_MAX)
        return -EOVERFLOW;
    device->rx_ring_runtime = runtime;
    ring->consumers++;
    device->rx_ring_live++;
    runtime->rx_ring_live++;
    *rx = (struct ker_rx_ring){.ring = ring, .device = device, .runtime = runtime,
        .owner_lcore = lcore, .headroom = headroom};
    return 0;
}

int ker_rx_ring_poll(void *arg, unsigned int budget)
{
    struct ker_rx_ring *rx = arg;
    int error = valid(rx);
    if (error) return error;
    if (budget > INT_MAX) return -EOVERFLOW;
    if (!budget) return 0;
    rx->polling = true;
    rx->last_completed = 0;
    rx->last_dropped = 0;
    rx->last_error = 0;
    unsigned int completed = 0;
    while (completed < budget) {
        if (!rx->pending) {
            void *object = NULL;
            error = rte_ring_sc_dequeue(rx->ring->ring, &object);
            if (error == -ENOENT) break;
            if (error) { rx->last_error = error; break; }
            if (!object) { rx->last_error = -EIO; break; }
            rx->pending = object;
        }

        struct sk_buff *skb = NULL;
        error = ker_eth_receive_copy_chain(rx->device, rx->pending,
            rx->headroom, &skb);
        if (error == -ENOMEM) {
            rx->last_error = error;
            break;
        }
        if (error) {
            ker_packet_free(rx->pending);
            rx->pending = NULL;
            rx->last_error = error;
            rx->last_dropped++;
            completed++;
            continue;
        }

        ker_packet_free(rx->pending);
        rx->pending = NULL;
        struct ker_receive_result result = {0};
        error = ker_receive_dispatch(rx->runtime, rx->device, &skb, &result);
        if (skb) BUG_ON(ker_skb_free(skb));
        if (error) rx->last_error = error;
        if (error || result.status == NET_RX_DROP) rx->last_dropped++;
        completed++;
    }
    rx->last_completed = completed;
    rx->polling = false;
    return completed ? (int)completed : rx->last_error;
}

int ker_rx_ring_cancel(struct ker_rx_ring *rx, struct rte_mbuf **out)
{
    int error = valid(rx);
    if (error) return error;
    if (!out) return -EINVAL;
    if (!rx->pending) return 0;
    *out = rx->pending;
    rx->pending = NULL;
    return 1;
}

int ker_rx_ring_cleanup(struct ker_rx_ring *rx)
{
    if (!rx || !rx->ring || !rx->device || !rx->runtime) return -EINVAL;
    if (rte_lcore_id() != rx->owner_lcore) return -EXDEV;
    if (rx->polling || rx->runtime->dispatching) return -EBUSY;
    if (rx->pending) return -EBUSY;
    BUG_ON(!rx->ring->consumers || !rx->device->rx_ring_live ||
           !rx->runtime->rx_ring_live || rx->device->rx_ring_runtime != rx->runtime);
    rx->device->rx_ring_runtime = NULL;
    rx->ring->consumers--;
    rx->device->rx_ring_live--;
    rx->runtime->rx_ring_live--;
    *rx = (struct ker_rx_ring){0};
    return 0;
}
