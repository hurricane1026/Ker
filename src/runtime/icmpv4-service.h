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
/* Return 1 when consumed, 0 to continue legacy handling, a negative errno on
 * failure. Positive values other than 1 are rejected as -EPROTO. */
typedef int (*ker_icmpv4_control_observer_fn)(
    const struct ker_icmpv4_control_event *, void *);
typedef uint64_t (*ker_icmpv4_monotonic_ms_fn)(void *);
/* UTC callback returns zero on success or a negative errno; positive statuses
 * are rejected as invalid callback results. */
typedef int (*ker_icmpv4_utc_ms_fn)(void *, uint32_t *);

struct ker_icmpv4_service_config {
  uint8_t ttl;
  bool echo_enabled, timestamp_enabled, probe_enabled;
  /* Copied with the rest of the config; bit N selects IPv4 protocol N. */
  uint8_t unavailable_protocols[32];
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
  ker_icmpv4_control_observer_fn control_observer;
  void *control_observer_arg;
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
/* One worker-local observer may inspect fully validated error quotations
 * before the service applies its configured-peer filter. Attach/detach are
 * owner-only and blocked during receive dispatch. The observer pins service
 * lifetime until detached. */
int ker_icmpv4_service_control_observer_attach(
    struct ker_icmpv4_service *, ker_icmpv4_control_observer_fn, void *);
int ker_icmpv4_service_control_observer_detach(
    struct ker_icmpv4_service *, ker_icmpv4_control_observer_fn, void *);
/* Borrowed offending skb is never consumed. Only a bounded quote is copied. */
int ker_icmpv4_service_emit_error(struct ker_icmpv4_service *, struct sk_buff *,
                                  uint8_t type, uint8_t code,
                                  uint32_t information);
#endif
