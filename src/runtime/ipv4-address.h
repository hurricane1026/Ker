#ifndef KER_RUNTIME_IPV4_ADDRESS_H
#define KER_RUNTIME_IPV4_ADDRESS_H
#include "ker/linux_ipv4_address.h"
#include "runtime/ethernet.h"
/* One static address on a private Ethernet device, owner worker only. Stable
 * zero-initialized wrapper and device storage; setup/cleanup are offline,
 * before NAPI/protocol registrations and with no live skb in this context.
 * No inetdev_init/RCU/netlink/sysctl/FIB/IGMP/neighbour services are implied. */
struct ker_ipv4_address {
    struct in_device *native;
    struct ker_eth_device *device;
};
/* Wire-order local address, prefix 0..32. Zero, loopback, multicast, reserved
 * class-E and limited broadcast are refused on this Ethernet-only boundary.
 * Does not install routes or reject subnet endpoint addresses. */
int ker_ipv4_address_init(struct ker_ipv4_address *address, struct ker_eth_device *device,
    __be32 local, unsigned int prefix);
int ker_ipv4_address_cleanup(struct ker_ipv4_address *address);
/* 1/0 or negative errno. This is the exact original prefix predicate, not FIB
 * route classification. /0 matches every address; /31 and /32 remain literal. */
int ker_ipv4_address_contains(struct ker_ipv4_address *address, __be32 candidate);
int ker_ipv4_address_is_local(struct ker_ipv4_address *address, __be32 candidate);
#endif
