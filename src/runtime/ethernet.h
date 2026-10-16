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
    void *receive_runtime; /* single receiver for bound protocol lists */
    unsigned int protocol_handlers;
    unsigned int protocol_live; /* registrations and dispatch pin */
    unsigned int rx_ring_live; /* attached bounded ring consumers */
    struct ker_receive_runtime *rx_ring_runtime; /* exclusive binding while RX ring attached */
    unsigned int napi_live; /* attached NAPI contexts pin this device */
};
int ker_eth_device_init(struct ker_eth_device *device, struct ker_skb_context *context,
    const char *name, int ifindex, const unsigned char mac[6]);
/* Conservatively refuses cleanup while ANY skb in its context is live,
 * including clones, and while NAPI/protocol contexts or dispatch pin the device. */
int ker_eth_device_cleanup(struct ker_eth_device *device);
/* Adopts mbuf only on success. Short or odd-aligned L2 headers are rejected
 * before mutation. Returns a classified skb owned by the caller; no dispatch. */
int ker_eth_receive(struct ker_eth_device *device, struct rte_mbuf *packet,
    struct sk_buff **result);
/* Copies a uniquely-owned, direct multi-segment frame into a linear skb,
 * then uses the original Linux Ethernet classifier. The input chain remains
 * caller-owned on success and failure. Headroom must be even-aligned. */
int ker_eth_receive_copy_chain(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result);
/* Explicit immutable borrowed-input variant; leaves the entire source chain
 * reference untouched while producing a classified skb copy. */
int ker_eth_receive_copy_chain_borrowed(struct ker_eth_device *device,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result);
#endif
