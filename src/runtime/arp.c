#include "runtime/arp.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include <rte_lcore.h>
#include <errno.h>

static const struct header_ops headers = {
    .create = eth_header, .parse_protocol = eth_header_parse_protocol
};
/* Only the synchronous original constructor runs while this allocation scope
 * is active. Header ops are fixed above; no application callbacks can reenter. */
static _Thread_local struct ker_skb_context *allocation_context;
static _Thread_local int allocation_error;
static int valid(struct ker_eth_device *device)
{
    if (!device || !device->native || !device->context || !device->context->descriptors) return -EINVAL;
    if (rte_lcore_id() != device->lcore || device->context->lcore != device->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    struct net_device *n = device->native;
    if (n->type != ARPHRD_ETHER || n->addr_len != ETH_ALEN || n->hard_header_len != ETH_HLEN ||
        n->needed_headroom || n->needed_tailroom ||
        n->flags & (ker_linux_IFF_LOOPBACK | ker_linux_IFF_NOARP)) return -ENOTSUP;
    return 0;
}
int ker_arp_device_setup(struct ker_eth_device *device)
{
    int error = valid(device);
    if (error) return error;
    if (device->native->header_ops && device->native->header_ops != &headers) return -EBUSY;
    device->native->header_ops = &headers;
    return 0;
}
struct sk_buff *alloc_skb(unsigned int size, gfp_t flags)
{
    BUG_ON(!allocation_context || flags != GFP_ATOMIC);
    struct sk_buff *skb = NULL;
    allocation_error = ker_skb_alloc(allocation_context, size, 0, &skb);
    return allocation_error ? NULL : skb;
}
void kfree_skb(struct sk_buff *skb)
{
    BUG_ON(!allocation_context || ker_skb_free(skb));
}
int ker_arp_create(struct ker_eth_device *device, unsigned int operation,
    __be32 source_ip, __be32 target_ip, const unsigned char *destination_mac,
    const unsigned char *source_mac, const unsigned char *target_mac,
    struct sk_buff **result)
{
    int error = valid(device);
    if (error) return error;
    if (!result || (operation != ARPOP_REQUEST && operation != ARPOP_REPLY)) return -EINVAL;
    if (operation == ARPOP_REPLY && (!destination_mac || !target_mac)) return -EINVAL;
    if (device->native->header_ops != &headers) return -ENOTSUP;
    if (allocation_context) return -EBUSY;
    allocation_context = device->context; allocation_error = 0;
    struct sk_buff *skb = arp_create((int)operation, ETH_P_ARP, target_ip, device->native,
        source_ip, destination_mac, source_mac, target_mac);
    error = allocation_error;
    allocation_context = NULL;
    if (!skb) return error ? error : -ENOMEM;
    /* Original arp_create resets network header before pushing Ethernet;
     * initialize MAC geometry for later copy/export or software loopback. */
    skb_reset_mac_header(skb); skb->mac_len = ETH_HLEN;
    *result = skb;
    return 0;
}
int ker_arp_create_configured(struct ker_ipv4_address *address,
    unsigned int operation, __be32 target_ip,
    const unsigned char destination_mac[ETH_ALEN],
    const unsigned char target_mac[ETH_ALEN], struct sk_buff **result)
{
    if (!address || !result || !destination_mac || !target_mac ||
        (operation != ARPOP_REQUEST && operation != ARPOP_REPLY))
        return -EINVAL;

    struct ker_eth_device *device = address->device;
    if (!device || !device->native || !device->context ||
        !device->context->descriptors)
        return -ESHUTDOWN;
    if (rte_lcore_id() != device->lcore || device->context->lcore != device->lcore)
        return -EXDEV;

    struct net_device *native = device->native;
    struct in_device *native_address = address->native;
    if (!native_address)
        return -ESHUTDOWN;
    if (native->type != ARPHRD_ETHER || native->addr_len != ETH_ALEN ||
        !native->dev_addr)
        return -ENOTSUP;
    struct in_ifaddr *ifa = native_address->ifa_list;
    if (native_address->dead || native->ip_ptr != native_address ||
        native_address->dev != native ||
        !ifa || ifa->ifa_next || ifa->ifa_dev != native_address ||
        !(ifa->ifa_flags & IFA_F_PERMANENT) || !ifa->ifa_local)
        return -ESHUTDOWN;

    /* Copy every value that the raw constructor will consume before entering
     * its allocator. Callers retain no mutable tuple authority afterward. */
    struct ker_skb_context *context_snapshot = device->context;
    struct ker_eth_device device_snapshot = {
        .native = native,
        .context = context_snapshot,
        .lcore = device->lcore
    };
    __be32 source_ip = ifa->ifa_local;
    unsigned char source_mac[ETH_ALEN];
    unsigned char destination_snapshot[ETH_ALEN];
    unsigned char target_snapshot[ETH_ALEN];
    memcpy(source_mac, native->dev_addr, ETH_ALEN);
    memcpy(destination_snapshot, destination_mac, ETH_ALEN);
    memcpy(target_snapshot, target_mac, ETH_ALEN);
    return ker_arp_create(&device_snapshot, operation, source_ip, target_ip,
        destination_snapshot, source_mac, target_snapshot, result);
}
int ker_arp_capture_begin(struct ker_eth_device *device)
{
    int error = valid(device);
    if (error) return error;
    if (device->native->header_ops != &headers) return -ENOTSUP;
    if (allocation_context) return -EBUSY;
    allocation_context = device->context; allocation_error = 0;
    return 0;
}
int ker_arp_capture_end(void)
{
    if (!allocation_context) return -EPERM;
    int error = allocation_error;
    allocation_context = NULL; allocation_error = 0;
    return error;
}
