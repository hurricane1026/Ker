#include "runtime/udp-neighbor-create.h"
#include <rte_lcore.h>
#include <errno.h>

int ker_udp_ipv4_create_neighbor(struct ker_neighbor_table *table, __be32 destination_ip,
    __be16 source_port, __be16 destination_port, uint8_t ttl, const void *payload,
    unsigned int payload_length, struct sk_buff **result)
{
    if (!table || !table->native || !table->address || !result || !ttl ||
        (!payload && payload_length))
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
    unsigned char destination_mac[ETH_ALEN];
    error = ker_neighbor_mac(table, entry, destination_mac);
    __be32 source_ip = ifa->ifa_local;
    unsigned char source_mac[ETH_ALEN];
    memcpy(source_mac, native_device->dev_addr, ETH_ALEN);
    struct ker_skb_context *context = device->context;
    BUG_ON(ker_neighbor_release(table, entry));
    if (error)
        return error;

    /* The neighbor reference is released before the constructor allocates. */
    return ker_udp_ipv4_create(context, source_mac, destination_mac,
        source_ip, destination_ip, source_port, destination_port,
        ttl, payload, payload_length, result);
}
