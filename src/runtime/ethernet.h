#ifndef KER_RUNTIME_ETHERNET_H
#define KER_RUNTIME_ETHERNET_H
#include "ker/linux_ethernet.h"
#include "runtime/skb.h"
/* Unregistered, single-worker Ethernet device view. Complete original layout,
 * not Linux register_netdevice or a simulated NAPI/protocol implementation.
 * Initialize to {0}; context and device storage must remain stable. */
struct ker_eth_device {
    struct net_device *native;
    struct ker_skb_context *context;
    unsigned int lcore;
    unsigned int napi_live; /* attached NAPI contexts pin this device */
};
int ker_eth_device_init(struct ker_eth_device *device, struct ker_skb_context *context,
    const char *name, int ifindex, const unsigned char mac[6]);
/* Conservatively refuses cleanup while ANY skb in its context is live,
 * including clones, and while a NAPI context is attached. */
int ker_eth_device_cleanup(struct ker_eth_device *device);
/* Adopts mbuf only on success. Short or odd-aligned L2 headers are rejected
 * before mutation. Returns a classified skb owned by the caller; no dispatch. */
int ker_eth_receive(struct ker_eth_device *device, struct rte_mbuf *packet,
    struct sk_buff **result);
#endif
