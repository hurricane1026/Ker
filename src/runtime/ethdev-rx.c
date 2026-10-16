#include "runtime/ethdev-rx.h"
#include "runtime/buffer.h"
#include "runtime/memory.h"
#include <errno.h>
#include <limits.h>
#include <linux/irqflags.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <string.h>

static int valid(struct ker_ethdev_rx *rx)
{
    if (!rx || !rx->initialized || !rx->device || !rx->runtime)
        return -EINVAL;
    if (rte_lcore_id() != rx->owner_lcore) return -EXDEV;
    if (rx->polling || rx->runtime->dispatching || ker_local_irq_disabled())
        return -EBUSY;
    return 0;
}

int ker_ethdev_rx_init_profile(struct ker_ethdev_rx *rx, struct ker_eth_device *device,
    struct ker_receive_runtime *runtime, uint16_t port_id, uint16_t queue_id,
    unsigned int headroom, enum ker_ethdev_rx_copy_profile copy_profile)
{
    if (copy_profile != KER_ETHDEV_RX_COPY_UNIQUE &&
        copy_profile != KER_ETHDEV_RX_COPY_IMMUTABLE_BORROWED &&
        copy_profile != KER_ETHDEV_RX_COPY_IMMUTABLE_EXTERNAL)
        return -EINVAL;
    if (!rx || !device || !runtime || !device->native || !device->context ||
        !runtime->initialized || !runtime->context || !runtime->context->descriptors ||
        !runtime->context->packets || !runtime->context->packets->mbufs ||
        runtime->context != device->context || (headroom & 1))
        return -EINVAL;
    if (rx->device || rx->runtime || rx->pending || rx->initialized || rx->polling ||
        rx->port_id || rx->queue_id || rx->owner_lcore || rx->headroom ||
        rx->last_completed || rx->last_dropped || rx->last_error ||
        rx->copy_profile)
        return -EALREADY;
    if (runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;
    unsigned int lcore = rte_lcore_id();
    if (lcore == LCORE_ID_ANY || device->lcore != lcore ||
        runtime->lcore != lcore || device->context->lcore != lcore)
        return -EXDEV;
    uint32_t room = rte_pktmbuf_data_room_size(runtime->context->packets->mbufs);
    uint32_t backing = RTE_ALIGN_FLOOR(room, SMP_CACHE_BYTES);
    size_t shared_info = ker_skb_shared_info_size();
    if (headroom > UINT16_MAX || backing <= shared_info ||
        (uint64_t)headroom + ETH_HLEN > backing - shared_info)
        return -ENOSPC;
    if ((device->receive_runtime && device->receive_runtime != runtime) ||
        device->rx_ring_runtime || device->rx_ring_live || runtime->rx_ring_live)
        return -EBUSY;
    if (device->rx_ring_live == UINT_MAX || runtime->rx_ring_live == UINT_MAX)
        return -EOVERFLOW;
    if (!rte_eth_dev_is_valid_port(port_id)) return -ENODEV;
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    int error = rte_eth_dev_info_get(port_id, &info);
    if (error) return error < 0 ? error : -error;
    if (queue_id >= info.nb_rx_queues || queue_id >= info.max_rx_queues)
        return -EINVAL;

    device->rx_ring_runtime = runtime;
    device->rx_ring_live++;
    runtime->rx_ring_live++;
    *rx = (struct ker_ethdev_rx){.device = device, .runtime = runtime,
        .port_id = port_id, .queue_id = queue_id, .owner_lcore = lcore,
        .headroom = headroom, .initialized = true, .copy_profile = copy_profile};
    return 0;
}

int ker_ethdev_rx_init(struct ker_ethdev_rx *rx, struct ker_eth_device *device,
    struct ker_receive_runtime *runtime, uint16_t port_id, uint16_t queue_id,
    unsigned int headroom)
{
    return ker_ethdev_rx_init_profile(rx, device, runtime, port_id, queue_id,
        headroom, KER_ETHDEV_RX_COPY_UNIQUE);
}

int ker_ethdev_rx_poll(void *arg, unsigned int budget)
{
    struct ker_ethdev_rx *rx = arg;
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
            struct rte_mbuf *packet = NULL;
            uint16_t count = rte_eth_rx_burst(rx->port_id, rx->queue_id, &packet, 1);
            if (!count) break;
            if (count != 1 || !packet) {
                rx->last_error = -EIO;
                break;
            }
            rx->pending = packet;
        }

        struct sk_buff *skb = NULL;
        if (rx->copy_profile == KER_ETHDEV_RX_COPY_IMMUTABLE_EXTERNAL)
            error = ker_eth_receive_copy_chain_external(rx->device, rx->pending,
                rx->headroom, &skb);
        else if (rx->copy_profile == KER_ETHDEV_RX_COPY_IMMUTABLE_BORROWED)
            error = ker_eth_receive_copy_chain_borrowed(rx->device, rx->pending,
                rx->headroom, &skb);
        else
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

int ker_ethdev_rx_cancel(struct ker_ethdev_rx *rx, struct rte_mbuf **out)
{
    int error = valid(rx);
    if (error) return error;
    if (!out) return -EINVAL;
    if (!rx->pending) return 0;
    *out = rx->pending;
    rx->pending = NULL;
    return 1;
}

int ker_ethdev_rx_cleanup(struct ker_ethdev_rx *rx)
{
    if (!rx || !rx->initialized || !rx->device || !rx->runtime) return -EINVAL;
    if (rte_lcore_id() != rx->owner_lcore) return -EXDEV;
    if (rx->polling || rx->runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;
    if (rx->pending) return -EBUSY;
    BUG_ON(!rx->device->rx_ring_live || !rx->runtime->rx_ring_live ||
        rx->device->rx_ring_runtime != rx->runtime);
    rx->device->rx_ring_runtime = NULL;
    rx->device->rx_ring_live--;
    rx->runtime->rx_ring_live--;
    *rx = (struct ker_ethdev_rx){0};
    return 0;
}
