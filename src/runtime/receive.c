#include "runtime/receive.h"
#include "runtime/memory.h"
#include <rte_lcore.h>
#include <linux/irqflags.h>
#include <errno.h>
#include <limits.h>

static int runtime_valid(struct ker_receive_runtime *runtime)
{
    if (!runtime || !runtime->initialized) return -EINVAL;
    if (rte_lcore_id() != runtime->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (!runtime->context->descriptors || ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats))
        return -ESHUTDOWN;
    return 0;
}
int ker_receive_runtime_init(struct ker_receive_runtime *runtime, struct ker_skb_context *context)
{
    if (!runtime || !context || !context->descriptors) return -EINVAL;
    if (runtime->initialized) return -EALREADY;
    if (context->lcore != rte_lcore_id() || rte_lcore_id() == LCORE_ID_ANY) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -EPERM;
    if (context->receive_live == UINT_MAX) return -EOVERFLOW;
    *runtime = (struct ker_receive_runtime){.context = context, .lcore = rte_lcore_id(), .initialized = true};
    for (unsigned int i = 0; i < PTYPE_HASH_SIZE; ++i) INIT_LIST_HEAD(&runtime->protocols[i]);
    context->receive_live++;
    return 0;
}
int ker_receive_runtime_cleanup(struct ker_receive_runtime *runtime)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (runtime->dispatching || runtime->live || runtime->rx_ring_live) return -EBUSY;
    runtime->context->receive_live--;
    *runtime = (struct ker_receive_runtime){0};
    return 0;
}
static int deliver(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *native, struct net_device *original)
{
    struct ker_protocol_handler *handler = container_of(native, struct ker_protocol_handler, native);
    struct ker_receive_runtime *runtime = handler->runtime;
    BUG_ON(!runtime->dispatching || dev != skb->dev);
    runtime->delivered++;
    int status = handler->receive(skb, handler, original, handler->arg);
    /* The reference is owned by the callback even when it reports drop/error. */
    if (status != NET_RX_SUCCESS && status != NET_RX_DROP) {
        runtime->callback_error = -EPROTO;
        return NET_RX_DROP;
    }
    return status;
}
int ker_protocol_register(struct ker_receive_runtime *runtime, struct ker_protocol_handler *handler,
    struct ker_eth_device *device, __be16 type, ker_protocol_fn receive, void *arg)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (!handler || !receive) return -EINVAL;
    if (runtime->dispatching) return -EBUSY;
    if (handler->registered) return -EALREADY;
    if (rte_be_to_cpu_16(type) < ETH_P_802_3_MIN ||
        type == rte_cpu_to_be_16(ETH_P_8021Q) || type == rte_cpu_to_be_16(ETH_P_8021AD)) return -ENOTSUP;
    if (device && (!device->native || device->context != runtime->context)) return -EINVAL;
    if (device && device->lcore != runtime->lcore) return -EXDEV;
    if (runtime->live >= KER_RECEIVE_MAX_HANDLERS) return -ENOSPC;
    if (device && ((device->receive_runtime && device->receive_runtime != runtime) ||
        (device->rx_ring_runtime && device->rx_ring_runtime != runtime))) return -EBUSY;
    if (device && device->protocol_live == UINT_MAX) return -EOVERFLOW;
    *handler = (struct ker_protocol_handler){.runtime = runtime, .device = device,
        .receive = receive, .arg = arg, .registered = true};
    handler->native.type = type; handler->native.dev = device ? device->native : NULL;
    handler->native.func = deliver;
    if (device && !device->receive_runtime) {
        device->receive_runtime = runtime;
        INIT_LIST_HEAD(&device->native->ptype_specific);
    }
    struct list_head *head = device ? &device->native->ptype_specific :
        &runtime->protocols[rte_be_to_cpu_16(type) & PTYPE_HASH_MASK];
    /* Match original dev_add_pack head insertion without pretending global RCU. */
    handler->native.list.next = head->next; handler->native.list.prev = head;
    head->next->prev = &handler->native.list; head->next = &handler->native.list;
    runtime->live++;
    if (device) { device->protocol_live++; device->protocol_handlers++; }
    return 0;
}
int ker_protocol_unregister(struct ker_protocol_handler *handler)
{
    if (!handler || !handler->registered) return -EINVAL;
    int error = runtime_valid(handler->runtime);
    if (error) return error;
    if (handler->runtime->dispatching) return -EBUSY;
    list_del_init(&handler->native.list);
    handler->runtime->live--;
    if (handler->device) {
        handler->device->protocol_live--;
        if (!--handler->device->protocol_handlers) handler->device->receive_runtime = NULL;
    }
    *handler = (struct ker_protocol_handler){0};
    return 0;
}
/* Non-linear user buffers are unsupported. Original orphan helper avoids
 * calling this for the supported no-zcopy path; an unexpected copy fails. */
int skb_copy_ubufs(struct sk_buff *skb, gfp_t flags)
{
    (void)skb; (void)flags;
    return -ENOTSUP;
}
int ker_receive_dispatch(struct ker_receive_runtime *runtime, struct ker_eth_device *device,
    struct sk_buff **packet, struct ker_receive_result *result)
{
    int error = runtime_valid(runtime);
    if (error) return error;
    if (!device || !device->native || !packet || !*packet || !result) return -EINVAL;
    if (runtime->dispatching || ker_local_irq_disabled()) return -EBUSY;
    if (device->lcore != runtime->lcore) return -EXDEV;
    if (device->context != runtime->context ||
        (device->receive_runtime && device->receive_runtime != runtime) ||
        (device->rx_ring_runtime && device->rx_ring_runtime != runtime)) return -EINVAL;
    struct sk_buff *skb = *packet;
    error = ker_skb_validate(skb, runtime->context);
    if (error) return error;
    if (skb_shared(skb)) return -EBUSY;
    if (skb->dev != device->native || !skb_mac_header_was_set(skb) ||
        skb->mac_header > skb->network_header || skb->network_header != skb_headroom(skb) ||
        skb->network_header - skb->mac_header != ETH_HLEN) return -EINVAL;
    if (skb->pfmemalloc || skb_vlan_tag_present(skb) || device->native->rx_handler || device->native->xdp_prog ||
        rte_be_to_cpu_16(skb->protocol) < ETH_P_802_3_MIN ||
        skb->protocol == rte_cpu_to_be_16(ETH_P_8021Q) ||
        skb->protocol == rte_cpu_to_be_16(ETH_P_8021AD)) return -ENOTSUP;
    if (device->protocol_live == UINT_MAX) return -EOVERFLOW;
    /* No fallible validation follows ownership transfer. Device pin survives
     * even a final callback that frees the last skb and attempts cleanup. */
    device->protocol_live++;
    runtime->dispatching = true; runtime->delivered = 0; runtime->callback_error = 0;
    *packet = NULL;
    skb_reset_network_header(skb);
    if (!skb_transport_header_was_set(skb)) skb_reset_transport_header(skb);
    skb_reset_mac_len(skb); skb->skb_iif = device->native->ifindex;
    struct packet_type *last = NULL;
    struct list_head *head = &runtime->protocols[rte_be_to_cpu_16(skb->protocol) & PTYPE_HASH_MASK];
    ker_linux_deliver_ptype_list(skb, &last, device->native, skb->protocol, head);
    if (device->receive_runtime == runtime)
        ker_linux_deliver_ptype_list(skb, &last, device->native, skb->protocol,
                                    &device->native->ptype_specific);
    int status;
    if (last) status = last->func(skb, skb->dev, last, device->native);
    else {
        status = NET_RX_DROP;
        BUG_ON(ker_skb_free(skb));
    }
    *result = (struct ker_receive_result){.handlers = runtime->delivered, .status = status};
    runtime->dispatching = false; device->protocol_live--;
    return runtime->callback_error;
}
