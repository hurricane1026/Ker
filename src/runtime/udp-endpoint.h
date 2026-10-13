#ifndef KER_RUNTIME_UDP_ENDPOINT_H
#define KER_RUNTIME_UDP_ENDPOINT_H
#include "runtime/icmpv4-service.h"

/* The message and skb-backed pointers are borrowed and read-only for this
 * synchronous callback; do not retain them. Return NET_RX_SUCCESS or
 * NET_RX_DROP. Any other status is rejected as -EPROTO. */
typedef int (*ker_udp_endpoint_receive_fn)(const struct ker_transport_message *,
                                           void *);
struct ker_udp_endpoint {
  __be16 port;
  ker_udp_endpoint_receive_fn receive;
  void *arg;
};
/* Caller owns and zero-initializes the table, entry array and entries. Do not
 * edit entry storage while enabled; keep it stable through disable. Ports are
 * nonzero wire-order UDP destination ports. Disable requires an empty table.
 * This is a bounded datagram callback adapter, not a socket API. */
struct ker_udp_endpoint_table {
  struct ker_transport_receiver *receiver;
  struct ker_icmpv4_service *icmpv4;
  struct ker_udp_endpoint *entries;
  size_t capacity, count;
  bool busy;
};
int ker_udp_endpoint_table_enable(struct ker_udp_endpoint_table *,
                                  struct ker_transport_receiver *,
                                  struct ker_icmpv4_service *,
                                  struct ker_udp_endpoint *, size_t);
int ker_udp_endpoint_table_disable(struct ker_udp_endpoint_table *);
int ker_udp_endpoint_bind(struct ker_udp_endpoint_table *, __be16,
                          ker_udp_endpoint_receive_fn, void *);
int ker_udp_endpoint_unbind(struct ker_udp_endpoint_table *, __be16);
/* Only complete local-unicast IPv4 UDP with IHL 20, TTL > 0, no options,
 * reserved/MF/offset bits clear, valid IP/UDP checksums and DF permitted are
 * eligible. The already enabled ICMPv4 service handles closed-port errors;
 * this does not create sockets or connected/wildcard endpoints. */
#endif
