#include "runtime/ethernet.h"
#include <linux/slab.h>
#include <rte_lcore.h>
#include <errno.h>

_Static_assert(offsetof(struct net_device, dev_addr_shadow) % 2 == 0, "MAC alignment");
_Static_assert(offsetof(struct net_device, broadcast) % 2 == 0, "broadcast alignment");
int ker_eth_device_init(struct ker_eth_device *device, struct ker_skb_context *context,
    const char *name, int ifindex, const unsigned char mac[6])
{
    if (!device || !context || !name || !*name || !mac || ifindex <= 0 ||
        strlen(name) >= IFNAMSIZ || (mac[0] & 1) ||
        !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]))
        return -EINVAL;
    if (device->native)
        return -EALREADY;
    if (!context->descriptors || rte_lcore_id() == LCORE_ID_ANY || context->lcore != rte_lcore_id())
        return -EXDEV;
    struct net_device *native = kzalloc(sizeof(*native), GFP_KERNEL);
    if (!native)
        return -ENOMEM;
    memcpy(native->name, name, strlen(name) + 1);
    memcpy(native->dev_addr_shadow, mac, ETH_ALEN);
    memcpy(native->perm_addr, mac, ETH_ALEN);
    native->dev_addr = native->dev_addr_shadow;
    memset(native->broadcast, 0xff, ETH_ALEN);
    native->addr_len = ETH_ALEN;
    native->hard_header_len = ETH_HLEN;
    native->min_header_len = ETH_HLEN;
    native->type = ARPHRD_ETHER;
    native->mtu = ETH_DATA_LEN;
    native->ifindex = ifindex;
    native->reg_state = NETREG_UNINITIALIZED;
    refcount_set(&native->dev_refcnt, 1);
    mutex_init(&native->lock);
    mutex_init(&native->dev.mutex);
    *device = (struct ker_eth_device){.native = native, .context = context, .lcore = rte_lcore_id()};
    return 0;
}
int ker_eth_device_cleanup(struct ker_eth_device *device)
{
    if (!device)
        return -EINVAL;
    if (!device->native)
        return 0;
    if (rte_lcore_id() != device->lcore)
        return -EXDEV;
    if (device->context->live || device->napi_live || device->protocol_live ||
        device->rx_ring_live || device->rx_ring_runtime || device->native->ip_ptr)
        return -EBUSY;
    mutex_destroy(&device->native->dev.mutex);
    mutex_destroy(&device->native->lock);
    kfree(device->native);
    *device = (struct ker_eth_device){0};
    return 0;
}
int ker_eth_receive(struct ker_eth_device *device, struct rte_mbuf *packet,
    struct sk_buff **result)
{
    if (!device || !device->native || !packet || !result)
        return -EINVAL;
    if (rte_lcore_id() != device->lcore)
        return -EXDEV;
    if (packet->data_len < ETH_HLEN)
        return -EMSGSIZE;
    /* The disabled unaligned-access Linux helpers use u16 loads. */
    if ((uintptr_t)rte_pktmbuf_mtod(packet, void *) % 2)
        return -EINVAL;
    struct sk_buff *skb;
    int error = ker_skb_from_mbuf(device->context, packet, &skb);
    if (error)
        return error;
    skb->protocol = eth_type_trans(skb, device->native);
    skb->mac_len = ETH_HLEN;
    skb_reset_network_header(skb);
    *result = skb;
    return 0;
}
enum eth_copy_profile { ETH_COPY_UNIQUE, ETH_COPY_BORROWED, ETH_COPY_EXTERNAL };
static int receive_copy_chain_profile(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result,
    enum eth_copy_profile profile)
{
    if (!device || !device->native || !device->context || !chain || !result)
        return -EINVAL;
    if (rte_lcore_id() != device->lcore)
        return -EXDEV;
    if (device->context->lcore != device->lcore)
        return -EXDEV;
    if (device->native->type != ARPHRD_ETHER || device->native->addr_len != ETH_ALEN ||
        !device->native->dev_addr)
        return -ENOTSUP;
    if (chain->pkt_len < ETH_HLEN)
        return -EMSGSIZE;
    if (headroom & 1)
        return -EINVAL;
    struct sk_buff *skb = NULL;
    int error;
    if (profile == ETH_COPY_EXTERNAL)
        error = ker_skb_copy_from_mbuf_chain_external(device->context, chain,
            headroom, &skb);
    else if (profile == ETH_COPY_BORROWED)
        error = ker_skb_copy_from_mbuf_chain_borrowed(device->context, chain,
            headroom, &skb);
    else
        error = ker_skb_copy_from_mbuf_chain(device->context, chain, headroom, &skb);
    if (error)
        return error;
    /* The destination pool provides aligned buffers; retain this guard before
     * calling Linux's classifier, whose native u16 loads require alignment. */
    if ((uintptr_t)skb->data & 1) {
        ker_skb_free(skb);
        return -EINVAL;
    }
    skb->protocol = eth_type_trans(skb, device->native);
    skb->mac_len = ETH_HLEN;
    skb_reset_network_header(skb);
    *result = skb;
    return 0;
}
int ker_eth_receive_copy_chain(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result)
{
    return receive_copy_chain_profile(device, chain, headroom, result, ETH_COPY_UNIQUE);
}
int ker_eth_receive_copy_chain_borrowed(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result)
{
    return receive_copy_chain_profile(device, chain, headroom, result,
        ETH_COPY_BORROWED);
}
int ker_eth_receive_copy_chain_external(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result)
{
    return receive_copy_chain_profile(device, chain, headroom, result,
        ETH_COPY_EXTERNAL);
}
