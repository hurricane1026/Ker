#ifndef KER_RUNTIME_ARP_RECEIVE_H
#define KER_RUNTIME_ARP_RECEIVE_H
#include "ker/linux_arp_receive.h"
#include "runtime/receive.h"
#include "runtime/ipv4-address.h"
/* Copied values, not borrowed packet pointers. No automatic neighbor learning
 * or reply. sender_ip==0 denotes a valid address-detection request. */
struct ker_arp_message {
    __be32 sender_ip, target_ip;
    unsigned char sender_mac[6], target_mac[6];
    unsigned int operation;
    bool target_local;
};
/* Message is borrowed for the call; callback owns no skb. May construct a
 * reply with ker_arp_create and retain it in its own bounded TX queue. Return
 * NET_RX_SUCCESS or NET_RX_DROP. Packet is released on every callback result. */
typedef int (*ker_arp_message_fn)(const struct ker_arp_message *, void *);
struct ker_arp_receiver {
    struct ker_protocol_handler handler;
    struct ker_ipv4_address *address;
    ker_arp_message_fn receive;
    void *arg;
};
/* Stable zero-initialized storage; one owner worker. Pins address and device
 * through handler registration; unregister before address/device cleanup. */
int ker_arp_receiver_register(struct ker_arp_receiver *, struct ker_receive_runtime *,
    struct ker_ipv4_address *, ker_arp_message_fn, void *);
int ker_arp_receiver_unregister(struct ker_arp_receiver *);
#endif
