#include "runtime/transport-receive.h"
#include "runtime/memory.h"
#include <errno.h>

static int transport_receive(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    (void)original;
    struct ker_transport_receiver *receiver = arg;
    struct ker_skb_context *context = handler->runtime->context;
    struct ker_transport_message message = {0};
    int error = -EINVAL;

    if (handler != &receiver->handler || !receiver->receive || !handler->device ||
        skb->dev != handler->device->native)
        goto reject;

    struct ker_ipv4_packet_view ip;
    error = ker_ipv4_packet_view_init(context, skb, &ip);
    if (error)
        goto reject;

    message.ipv4 = ip;
    switch (ip.header[9]) {
    case KER_TRANSPORT_ICMP_ECHO:
        message.protocol = KER_TRANSPORT_ICMP_ECHO;
        error = ker_icmp_echo_packet_view_init(context, skb, &message.packet.icmp_echo);
        break;
    case KER_TRANSPORT_UDP:
        message.protocol = KER_TRANSPORT_UDP;
        error = ker_udp_packet_view_init(context, skb, &message.packet.udp);
        break;
    case KER_TRANSPORT_TCP:
        message.protocol = KER_TRANSPORT_TCP;
        error = ker_tcp_packet_view_init(context, skb, &message.packet.tcp);
        break;
    default:
        error = -EPROTONOSUPPORT;
        break;
    }
    if (error)
        goto reject;

    if (receiver->echo_service && message.protocol == KER_TRANSPORT_ICMP_ECHO &&
        message.packet.icmp_echo.type == 8) {
        if (!receiver->echo_service_receive) {
            error = -EOPNOTSUPP;
            goto reject;
        }
        error = receiver->echo_service_receive(receiver->echo_service, skb, &message);
        receiver->validation_error = error;
        BUG_ON(ker_skb_free(skb));
        return error ? NET_RX_DROP : NET_RX_SUCCESS;
    }

    receiver->validation_error = 0;
    int status = receiver->receive(&message, receiver->arg);
    /* The protocol dispatcher converts invalid callback statuses to -EPROTO.
     * This adapter has already consumed its skb reference below. */
    BUG_ON(ker_skb_free(skb));
    return status;

reject:
    receiver->validation_error = error;
    BUG_ON(ker_skb_free(skb));
    return NET_RX_DROP;
}

int ker_transport_receiver_register(struct ker_transport_receiver *receiver,
    struct ker_receive_runtime *runtime, struct ker_eth_device *device,
    ker_transport_receive_fn callback, void *arg)
{
    if (!receiver || !runtime || !device || !callback)
        return -EINVAL;
    if (receiver->handler.registered)
        return -EALREADY;
    int error = ker_protocol_register(runtime, &receiver->handler, device,
        rte_cpu_to_be_16(ETH_P_IP), transport_receive, receiver);
    if (error)
        return error;
    receiver->receive = callback;
    receiver->arg = arg;
    receiver->validation_error = 0;
    return 0;
}

int ker_transport_receiver_unregister(struct ker_transport_receiver *receiver)
{
    if (!receiver || !receiver->handler.registered)
        return -EINVAL;
    if (receiver->echo_service)
        return -EBUSY;
    int error = ker_protocol_unregister(&receiver->handler);
    if (error)
        return error;
    *receiver = (struct ker_transport_receiver){0};
    return 0;
}
