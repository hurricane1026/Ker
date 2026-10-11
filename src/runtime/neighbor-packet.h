#ifndef KER_RUNTIME_NEIGHBOR_PACKET_H
#define KER_RUNTIME_NEIGHBOR_PACKET_H
#include "runtime/neighbor.h"
#include <rte_lcore.h>
#include <errno.h>

struct ker_neighbor_packet_source {
    struct ker_skb_context *context;
    __be32 source_ip;
    unsigned char source_mac[ETH_ALEN];
    unsigned char destination_mac[ETH_ALEN];
};

/* Snapshot the validated owner-local source path and a permanent destination
 * mapping, dropping its acquired reference before returning to an allocator. */
static inline int ker_neighbor_packet_source_snapshot(struct ker_neighbor_table *table,
    __be32 destination_ip, struct ker_neighbor_packet_source *snapshot)
{
    if (!table || !table->native || !table->address || !snapshot)
        return -EINVAL;
    if (rte_lcore_id() != table->lcore)
        return -EXDEV;

    struct ker_ipv4_address *address = table->address;
    struct ker_eth_device *device = address->device;
    if (!address->native || !device || !device->native || !device->context)
        return -ESHUTDOWN;
    if (rte_lcore_id() != device->lcore || device->lcore != device->context->lcore)
        return -EXDEV;
    struct net_device *native_device = device->native;
    struct in_device *native_address = address->native;
    struct in_ifaddr *ifa = native_address->ifa_list;
    if (native_device->type != ARPHRD_ETHER || native_device->addr_len != ETH_ALEN || !native_device->dev_addr)
        return -ENOTSUP;
    if (!ifa || !ifa->ifa_local || ifa->ifa_dev != native_address || native_address->dev != native_device ||
        rcu_dereference_raw(native_device->ip_ptr) != native_address ||
        native_address->arp_parms != &table->native->parms || table->native->parms.dev != native_device)
        return -ESHUTDOWN;

    struct neighbour *entry = NULL;
    int error = ker_neighbor_lookup(table, destination_ip, &entry);
    if (error)
        return error;
    struct ker_neighbor_packet_source copy = {0};
    error = ker_neighbor_mac(table, entry, copy.destination_mac);
    copy.context = device->context;
    copy.source_ip = ifa->ifa_local;
    memcpy(copy.source_mac, native_device->dev_addr, ETH_ALEN);
    BUG_ON(ker_neighbor_release(table, entry));
    if (error)
        return error;
    *snapshot = copy;
    return 0;
}
#endif
