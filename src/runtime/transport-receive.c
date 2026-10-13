#include "runtime/transport-receive.h"
#include "runtime/memory.h"
#include <errno.h>

static int transport_receive(struct sk_buff *skb,
                             struct ker_protocol_handler *handler,
                             struct net_device *original, void *arg) {
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
        if (!receiver->icmpv4_service && !receiver->generic_icmpv4_enabled &&
            ip.packet_length > ip.header_length &&
            ip.header[ip.header_length] != 0 && ip.header[ip.header_length] != 8) {
            error = -ENOTSUP;
            break;
        }
    message.protocol = KER_TRANSPORT_ICMP_ECHO;
    error = ker_icmpv4_packet_view_init(context, skb, &message.icmpv4);
    if (!error && (message.icmpv4.type == 0 || message.icmpv4.type == 8))
      error = ker_icmp_echo_packet_view_init(context, skb,
                                             &message.packet.icmp_echo);
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

  if (message.protocol == KER_TRANSPORT_UDP &&
      receiver->udp_endpoint_table) {
    if (!receiver->udp_endpoint_receive) {
      error = -EOPNOTSUPP;
      goto reject;
    }
    int handled = receiver->udp_endpoint_receive(
        receiver->udp_endpoint_table, skb, &message);
    if (handled < 0) {
      error = handled;
      receiver->validation_error = error;
      BUG_ON(ker_skb_free(skb));
      return handled == -EPROTO ? -EPROTO : NET_RX_DROP;
    }
    if (handled == 1 || handled == 2) {
      receiver->validation_error = 0;
      BUG_ON(ker_skb_free(skb));
      return handled == 1 ? NET_RX_SUCCESS : NET_RX_DROP;
    }
    if (handled != 0) {
      receiver->validation_error = -EPROTO;
      BUG_ON(ker_skb_free(skb));
      return NET_RX_DROP;
    }
  }

  if (receiver->icmpv4_service && message.protocol == KER_TRANSPORT_ICMP_ECHO) {
    if (!receiver->icmpv4_service_receive) {
      error = -EOPNOTSUPP;
      goto reject;
    }
    int handled = receiver->icmpv4_service_receive(receiver->icmpv4_service,
                                                   skb, &message);
    if (handled < 0) {
      error = handled;
      receiver->validation_error = error;
      BUG_ON(ker_skb_free(skb));
      return NET_RX_DROP;
    }
    if (handled > 0) {
      receiver->validation_error = 0;
      BUG_ON(ker_skb_free(skb));
      return NET_RX_SUCCESS;
    }
  } else if (message.protocol == KER_TRANSPORT_ICMP_ECHO &&
             message.icmpv4.type != 0 && message.icmpv4.type != 8 &&
             !receiver->generic_icmpv4_enabled) {
    error = -EOPNOTSUPP;
    goto reject;
  }

  if (receiver->echo_service && message.protocol == KER_TRANSPORT_ICMP_ECHO &&
      message.packet.icmp_echo.type == 8) {
    if (!receiver->echo_service_receive) {
      error = -EOPNOTSUPP;
      goto reject;
    }
    error =
        receiver->echo_service_receive(receiver->echo_service, skb, &message);
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
                                    struct ker_receive_runtime *runtime,
                                    struct ker_eth_device *device,
                                    ker_transport_receive_fn callback,
                                    void *arg) {
  if (!receiver || !runtime || !device || !callback)
    return -EINVAL;
  if (receiver->handler.registered)
    return -EALREADY;
  int error = ker_protocol_register(runtime, &receiver->handler, device,
                                    rte_cpu_to_be_16(ETH_P_IP),
                                    transport_receive, receiver);
  if (error)
    return error;
  receiver->receive = callback;
  receiver->arg = arg;
  receiver->validation_error = 0;
  return 0;
}

int ker_transport_receiver_unregister(struct ker_transport_receiver *receiver) {
  if (!receiver || !receiver->handler.registered)
    return -EINVAL;
  if (receiver->echo_service || receiver->icmpv4_service ||
      receiver->udp_endpoint_table)
    return -EBUSY;
  int error = ker_protocol_unregister(&receiver->handler);
  if (error)
    return error;
  *receiver = (struct ker_transport_receiver){0};
  return 0;
}

int ker_transport_receiver_enable_generic_icmpv4(
    struct ker_transport_receiver *receiver) {
  if (!receiver || !receiver->handler.registered || !receiver->receive)
    return -EINVAL;
  if (receiver->handler.runtime->dispatching || receiver->icmpv4_service ||
      receiver->echo_service)
    return -EBUSY;
  if (rte_lcore_id() != receiver->handler.runtime->lcore)
    return -EXDEV;
  receiver->generic_icmpv4_enabled = true;
  return 0;
}
