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
  __be32 peer_address;
  __be16 peer_port;
  uint64_t generation;
  uint64_t incarnation;
  bool connected;
};
struct ker_udp_endpoint_table;
struct ker_udp_endpoint_handle {
  const struct ker_udp_endpoint_table *table;
  size_t slot;
  uint64_t generation;
};
/* Caller owns and zero-initializes the table, entry array and entries. Do not
 * edit entry storage while enabled; keep it stable through disable. Retain the
 * table object to preserve handle generations across re-enable. Zeroing or
 * reusing its storage starts a new object lifetime and invalidates old handles.
 * Ports are nonzero wire-order UDP destination ports. Disable requires an
 * empty table.
 * This is a bounded datagram callback adapter, not a socket API. */
struct ker_udp_endpoint_table {
  struct ker_transport_receiver *receiver;
  struct ker_icmpv4_service *icmpv4;
  struct ker_udp_endpoint *entries;
  size_t capacity, count;
  uint64_t next_generation;
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
int ker_udp_endpoint_bind_ex(struct ker_udp_endpoint_table *, __be16,
                             ker_udp_endpoint_receive_fn, void *,
                             struct ker_udp_endpoint_handle *);
int ker_udp_endpoint_connect(struct ker_udp_endpoint_table *,
                             struct ker_udp_endpoint_handle, __be32, __be16);
int ker_udp_endpoint_disconnect(struct ker_udp_endpoint_table *,
                                struct ker_udp_endpoint_handle);
int ker_udp_endpoint_close(struct ker_udp_endpoint_table *,
                           struct ker_udp_endpoint_handle);
/* Only complete local-unicast IPv4 UDP with IHL 20, TTL > 0, no options,
 * reserved/MF/offset bits clear, valid IP/UDP checksums and DF permitted are
 * eligible. The already enabled ICMPv4 service handles closed-port errors.
 * Connected endpoints filter the complete source address and UDP source port;
 * a peer mismatch follows the closed-port ICMP safety path. Handles are table-
 * and generation-scoped. */
#endif
