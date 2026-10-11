#include "runtime/arp-receive.h"
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>
/* Scoped only around the synchronous raw arp_rcv gate. Reentrant dispatch
 * cannot replace the scope. Event callbacks never receive skb ownership. */
_Static_assert(sizeof(struct neighbour_cb) <= sizeof(((struct sk_buff *)0)->cb), "neighbor scratch fits skb");
static _Thread_local struct ker_arp_receiver *active;
static _Thread_local const struct ker_arp_message *active_message;
static _Thread_local struct ker_arp_message active_message_copy;
static _Thread_local unsigned int active_packet_type;
int ker_arp_rx_feedback_scope(struct ker_arp_receiver *receiver, const struct ker_arp_message *message)
{
    if (!receiver || !message) return -EINVAL;
    if (receiver->handler.runtime && rte_lcore_id() != receiver->handler.runtime->lcore) return -EXDEV;
    if (active != receiver || active_message != message) return -EPERM;
    if (!receiver->handler.runtime) return -EPERM;
    if (active_packet_type != PACKET_HOST) return -ENOTSUP;
    if (message->sender_ip != active_message_copy.sender_ip || message->target_ip != active_message_copy.target_ip ||
        message->operation != active_message_copy.operation || message->target_local != active_message_copy.target_local ||
        memcmp(message->sender_mac, active_message_copy.sender_mac, ETH_ALEN) ||
        memcmp(message->target_mac, active_message_copy.target_mac, ETH_ALEN)) return -ESTALE;
    return 0;
}
struct sk_buff *ker_arp_rx_clone(struct sk_buff *skb, gfp_t flags)
{
    BUG_ON(!active || flags != GFP_ATOMIC);
    struct sk_buff *clone = NULL;
    return ker_skb_clone(skb, &clone) ? NULL : clone;
}
void ker_arp_rx_free(struct sk_buff *skb) { BUG_ON(ker_skb_free(skb)); }
void ker_arp_rx_free_reason(struct sk_buff *skb, enum skb_drop_reason reason)
{
    BUG_ON(reason == SKB_NOT_DROPPED_YET);
    ker_arp_rx_free(skb);
}
void *ker_arp_rx_pull_tail(struct sk_buff *skb, int delta)
{
    (void)skb; (void)delta;
    /* All admitted bridge skbs are linear. Reaching a fragment operation
     * would mean validation or ownership has been violated. */
    BUG();
    return NULL;
}
static bool unicast_ip(__be32 ip)
{
    unsigned int h = rte_be_to_cpu_32(ip);
    return h && (h >> 24) != 127 && (h & 0xf0000000U) < 0xe0000000U;
}
int ker_arp_rx_process(struct sk_buff *skb, struct net_device *dev)
{
    BUG_ON(!active || dev != active->address->device->native);
    const struct arphdr *arp = arp_hdr(skb);
    struct ker_arp_message message = {0};
    int status = NET_RX_DROP;
    if ((arp->ar_hrd != rte_cpu_to_be_16(ARPHRD_ETHER) &&
         arp->ar_hrd != rte_cpu_to_be_16(ARPHRD_IEEE802)) ||
        arp->ar_pro != rte_cpu_to_be_16(ETH_P_IP)) goto done;
    message.operation = rte_be_to_cpu_16(arp->ar_op);
    if (message.operation != ARPOP_REQUEST && message.operation != ARPOP_REPLY) goto done;
    const unsigned char *p = (const unsigned char *)(arp + 1);
    memcpy(message.sender_mac, p, 6); memcpy(&message.sender_ip, p + 6, 4);
    memcpy(message.target_mac, p + 10, 6); memcpy(&message.target_ip, p + 16, 4);
    if (!unicast_ip(message.target_ip) || (message.sender_ip && !unicast_ip(message.sender_ip)) ||
        (!message.sender_ip && message.operation != ARPOP_REQUEST) ||
        (message.sender_mac[0] & 1) || !(message.sender_mac[0] | message.sender_mac[1] |
        message.sender_mac[2] | message.sender_mac[3] | message.sender_mac[4] | message.sender_mac[5])) goto done;
    int local = ker_ipv4_address_is_local(active->address, message.target_ip);
    if (local < 0) goto done;
    message.target_local = local;
    /* Native neighbour scratch was reset by original arp_rcv. This private
     * decoder does not execute arp_process, routing or a netfilter hook. */
    active_message = &message; active_message_copy = message; active_packet_type = skb->pkt_type;
    status = active->receive(&message, active->arg);
    active_message = NULL; active_message_copy = (struct ker_arp_message){0}; active_packet_type = 0;
done:
    ker_arp_rx_free(skb);
    return status;
}
static int receive(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    struct ker_arp_receiver *receiver = arg;
    struct ker_eth_device *dev = receiver->address->device;
    if (active || ker_skb_validate(skb, dev->context) || skb->dev != dev->native ||
        skb->network_header != skb_headroom(skb) || dev->native->type != ARPHRD_ETHER ||
        dev->native->addr_len != ETH_ALEN || dev->native->hard_header_len != ETH_HLEN ||
        ker_ipv4_address_is_local(receiver->address, receiver->address->native->ifa_list->ifa_local) != 1) {
        ker_arp_rx_free(skb);
        return NET_RX_DROP;
    }
    active = receiver;
    int status = ker_linux_arp_receive(skb, dev->native, &handler->native, original);
    active = NULL;
    return status;
}
int ker_arp_receiver_register(struct ker_arp_receiver *receiver, struct ker_receive_runtime *runtime,
    struct ker_ipv4_address *address, ker_arp_message_fn callback, void *arg)
{
    if (!receiver || !runtime || !address || !address->native || !callback) return -EINVAL;
    if (receiver->handler.registered) return -EALREADY;
    int error = ker_ipv4_address_is_local(address, address->native->ifa_list->ifa_local);
    if (error < 0) return error;
    if (address->device->native->addr_len != ETH_ALEN || address->device->native->hard_header_len != ETH_HLEN) return -ENOTSUP;
    if (refcount_read(&address->native->refcnt) >= INT_MAX) return -EOVERFLOW;
    error = ker_protocol_register(runtime, &receiver->handler, address->device,
        rte_cpu_to_be_16(ETH_P_ARP), receive, receiver);
    if (error) return error;
    refcount_inc(&address->native->refcnt);
    receiver->address = address; receiver->receive = callback; receiver->arg = arg;
    return 0;
}
int ker_arp_receiver_unregister(struct ker_arp_receiver *receiver)
{
    if (!receiver || !receiver->handler.registered) return -EINVAL;
    int error = ker_protocol_unregister(&receiver->handler);
    if (error) return error;
    BUG_ON(refcount_dec_and_test(&receiver->address->native->refcnt));
    *receiver = (struct ker_arp_receiver){0};
    return 0;
}
