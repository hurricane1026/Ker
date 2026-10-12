#ifndef KER_RUNTIME_CONFIGURED_PACKET_H
#define KER_RUNTIME_CONFIGURED_PACKET_H
#include "runtime/ipv4-address.h"
#include <errno.h>
#include <rte_lcore.h>
#include <string.h>

/* Private, worker-local snapshot shared by explicit-address constructors. */
struct ker_configured_packet_source {
    struct ker_skb_context *context;
    __be32 source_ip;
    unsigned char source_mac[ETH_ALEN];
    unsigned char destination_mac[ETH_ALEN];
};

static inline int ker_configured_packet_source_snapshot(
    struct ker_ipv4_address *address,
    const unsigned char destination_mac[ETH_ALEN],
    struct ker_configured_packet_source *snapshot)
{
    if (!address || !address->native || !address->device || !destination_mac || !snapshot)
        return -EINVAL;
    struct ker_eth_device *device = address->device;
    if (!device->native || !device->context || !device->context->descriptors)
        return -ESHUTDOWN;
    if (rte_lcore_id() != device->lcore || device->context->lcore != device->lcore)
        return -EXDEV;

    struct in_device *native_address = address->native;
    struct net_device *native_device = device->native;
    if (native_address->dead || native_address->dev != native_device ||
        rcu_dereference_raw(native_device->ip_ptr) != native_address)
        return -ESHUTDOWN;
    if (native_device->type != ARPHRD_ETHER || native_device->addr_len != ETH_ALEN ||
        !native_device->dev_addr)
        return -ENOTSUP;

    struct in_ifaddr *ifa = native_address->ifa_list;
    if (!ifa || ifa->ifa_next || ifa->ifa_dev != native_address ||
        !(ifa->ifa_flags & IFA_F_PERMANENT) || !ifa->ifa_local ||
        ifa->ifa_address != ifa->ifa_local)
        return -ENOTSUP;

    struct ker_configured_packet_source value = {
        .context = device->context,
        .source_ip = ifa->ifa_local
    };
    memcpy(value.source_mac, native_device->dev_addr, ETH_ALEN);
    memcpy(value.destination_mac, destination_mac, ETH_ALEN);
    *snapshot = value;
    return 0;
}
#endif
