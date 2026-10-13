#ifndef KER_RUNTIME_TRANSPORT_RECEIVE_H
#define KER_RUNTIME_TRANSPORT_RECEIVE_H
#include "runtime/icmp-echo-packet-view.h"
#include "runtime/icmpv4-packet-view.h"
#include "runtime/receive.h"
#include "runtime/tcp-packet-view.h"
#include "runtime/udp-packet-view.h"
struct ker_icmp_echo_service;
struct ker_icmpv4_service;

enum ker_transport_protocol {
  KER_TRANSPORT_ICMP_ECHO = 1,
  KER_TRANSPORT_UDP = 17,
  KER_TRANSPORT_TCP = 6
};
struct ker_transport_message {
  enum ker_transport_protocol protocol;
  struct ker_ipv4_packet_view ipv4;
  union {
    struct ker_udp_packet_view udp;
    struct ker_tcp_packet_view tcp;
    struct ker_icmp_echo_packet_view icmp_echo;
  } packet;
  /* Generic ICMPv4 view is valid for every admitted ICMP type. The legacy
   * packet.icmp_echo member remains populated for echo packets. */
  struct ker_icmpv4_packet_view icmpv4;
};
/* Message and packet pointers are borrowed only for this synchronous call.
 * Callback must not retain, mutate, or free the message/views or skb and must
 * not use any view after return. The callback never owns an skb reference and
 * may return only NET_RX_SUCCESS or NET_RX_DROP. */
typedef int (*ker_transport_receive_fn)(const struct ker_transport_message *,
                                        void *);
typedef int (*ker_transport_service_receive_fn)(
    void *, struct sk_buff *, const struct ker_transport_message *);
/* Private service-hook result: negative drops, zero passes to the application,
 * positive marks the message handled and suppresses application delivery. */
struct ker_transport_receiver {
  struct ker_protocol_handler handler;
  ker_transport_receive_fn receive;
  void *arg;
  int validation_error; /* Last worker-local decode/admission error, or 0. */
  struct ker_icmp_echo_service *echo_service;
  ker_transport_service_receive_fn echo_service_receive;
  struct ker_icmpv4_service *icmpv4_service;
  ker_transport_service_receive_fn icmpv4_service_receive;
  bool generic_icmpv4_enabled;
};
/* Stable zero-initialized storage; pins device while registered. IPv4
 * UDP/TCP and legacy echo are delivered by default. Generic ICMPv4 requires
 * explicit opt-in or a bound control service. A descriptor shared by protocol
 * fanout fails closed via the existing unique-owner view checks. No sockets,
 * FIB routing, fragment reassembly, or TCP state machine are implied. */
int ker_transport_receiver_register(struct ker_transport_receiver *,
                                    struct ker_receive_runtime *,
                                    struct ker_eth_device *,
                                    ker_transport_receive_fn, void *);
int ker_transport_receiver_unregister(struct ker_transport_receiver *);
/* Explicitly opt the application callback into generic, non-echo ICMPv4
 * views. The default receiver behavior remains limited to legacy echo. */
int ker_transport_receiver_enable_generic_icmpv4(
    struct ker_transport_receiver *);
#endif
