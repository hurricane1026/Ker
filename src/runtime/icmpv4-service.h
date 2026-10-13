#ifndef KER_RUNTIME_ICMPV4_SERVICE_H
#define KER_RUNTIME_ICMPV4_SERVICE_H
#include "runtime/neighbor-timer.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"

struct ker_icmpv4_control_event {
  uint8_t type, code;
  __be32 source, destination;
  uint16_t next_hop_mtu;
  uint8_t pointer;
  __be32 gateway;
  struct ker_icmpv4_packet_view message;
  struct ker_icmpv4_quoted_ipv4_view quote;
  bool has_quote;
};
typedef void (*ker_icmpv4_control_event_fn)(
    const struct ker_icmpv4_control_event *, void *);
typedef uint64_t (*ker_icmpv4_monotonic_ms_fn)(void *);
/* UTC callback returns zero on success or a negative errno; positive statuses
 * are rejected as invalid callback results. */
typedef int (*ker_icmpv4_utc_ms_fn)(void *, uint32_t *);

struct ker_icmpv4_service_config {
  uint8_t ttl;
  bool echo_enabled, timestamp_enabled, probe_enabled;
  unsigned int burst;
  uint64_t refill_ms;
  ker_icmpv4_monotonic_ms_fn monotonic_ms;
  ker_icmpv4_utc_ms_fn utc_ms;
  void *clock_arg;
  ker_icmpv4_control_event_fn event;
  void *event_arg;
};
struct ker_icmpv4_service {
  struct ker_transport_receiver *receiver;
  struct ker_neighbor_monitor *monitor;
  struct ker_icmpv4_service_config config;
  uint64_t tokens, last_refill_ms, last_now_ms;
  bool clock_started;
  bool busy;
  uint64_t received, replies_submitted, errors_submitted;
  uint64_t events_delivered, suppressed, malformed, unsupported, dropped;
  int last_error;
};

/* Worker-local opt-in control service. Binds one receiver and its existing
 * explicit-peer resolver; controls do not install routes or PMTU state. */
int ker_icmpv4_service_enable(struct ker_icmpv4_service *,
                              struct ker_transport_receiver *,
                              struct ker_neighbor_monitor *,
                              const struct ker_icmpv4_service_config *);
int ker_icmpv4_service_disable(struct ker_icmpv4_service *);
/* Borrowed offending skb is never consumed. Only a bounded quote is copied. */
int ker_icmpv4_service_emit_error(struct ker_icmpv4_service *, struct sk_buff *,
                                  uint8_t type, uint8_t code,
                                  uint32_t information);
#endif
