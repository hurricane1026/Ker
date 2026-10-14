#ifndef KER_RUNTIME_UDP_ERROR_H
#define KER_RUNTIME_UDP_ERROR_H
#include "runtime/icmpv4-pmtu.h"
#include "runtime/tx-export.h"
#include "runtime/udp-endpoint.h"

typedef uint64_t (*ker_udp_error_clock_fn)(void *);

enum ker_udp_error_record_state {
  KER_UDP_ERROR_FREE,
  KER_UDP_ERROR_RESERVED,
  KER_UDP_ERROR_SENT,
  KER_UDP_ERROR_TOMBSTONE
};

struct ker_udp_error_event {
  int error;
  int pmtu_status;
  uint8_t type, code;
  uint16_t next_hop_mtu;
  __be32 local_address, peer_address, reporter_address;
  __be16 local_port, peer_port;
  uint64_t sequence, incarnation;
};

struct ker_udp_error_queue {
  struct ker_udp_error_queue *next;
  struct ker_udp_endpoint_handle endpoint;
  struct ker_udp_error_event *events;
  size_t capacity, head, count;
  uint64_t dropped;
  bool attached, busy;
};

struct ker_udp_error_record {
  enum ker_udp_error_record_state state;
  struct ker_udp_endpoint_handle endpoint;
  struct ker_neighbor_monitor *monitor;
  uint64_t token, sequence, incarnation, expires_ms;
  struct sk_buff *skb;
  __be32 local_address, peer_address;
  __be16 local_port, peer_port, identification, frag_off;
  uint16_t ip_length;
  __be16 udp_length, udp_checksum;
  bool accepted_pending;
};

struct ker_udp_error_tracker;
struct ker_udp_error_peer {
  struct ker_udp_error_tracker *tracker;
  struct ker_neighbor_monitor *monitor;
  struct ker_icmpv4_pmtu pmtu;
  struct ker_tx_export_observer tx_observer;
  bool busy;
};

struct ker_udp_error_token {
  struct ker_udp_error_tracker *tracker;
  size_t slot;
  uint64_t token;
  __be16 identification;
};

struct ker_udp_error_tracker {
  struct ker_icmpv4_service *service;
  struct ker_udp_endpoint_table *endpoints;
  struct ker_udp_error_record *records;
  struct ker_udp_error_peer *peers;
  size_t record_capacity, peer_capacity, peer_count;
  unsigned int io_refs;
  struct ker_udp_error_queue *queue_head;
  size_t queue_capacity, queue_count;
  ker_udp_error_clock_fn clock;
  void *clock_arg;
  uint64_t lifetime_ms, last_now_ms, next_token, next_sequence;
  uint16_t next_identification;
  bool clock_started, busy, attached;
};

/* Storage remains caller-owned until cleanup. RESERVED entries are never
 * expired or reused; SENT evidence and consumed-ID tombstones expire after
 * lifetime_ms. */
int ker_udp_error_tracker_init(
    struct ker_udp_error_tracker *, struct ker_icmpv4_service *,
    struct ker_udp_endpoint_table *, struct ker_udp_error_record *, size_t,
    struct ker_udp_error_peer *, size_t, size_t queue_capacity,
    ker_udp_error_clock_fn, void *, uint64_t lifetime_ms);
int ker_udp_error_tracker_cleanup(struct ker_udp_error_tracker *);
int ker_udp_error_peer_register(struct ker_udp_error_tracker *,
                                struct ker_neighbor_monitor *);
int ker_udp_error_peer_unregister(struct ker_udp_error_tracker *,
                                  struct ker_neighbor_monitor *);

int ker_udp_error_queue_attach(struct ker_udp_error_tracker *,
                               struct ker_udp_endpoint_handle,
                               struct ker_udp_error_queue *,
                               struct ker_udp_error_event *, size_t);
/* Returns -EBUSY while this endpoint has an outstanding RESERVED send. */
int ker_udp_error_queue_detach(struct ker_udp_error_tracker *,
                               struct ker_udp_endpoint_handle);
/* Return 1 for an error, 0 when empty, or a negative errno. */
int ker_udp_error_recv(struct ker_udp_error_tracker *,
                       struct ker_udp_endpoint_handle,
                       struct ker_udp_error_event *);

/* Reserve an IPv4 ID before packet construction, then publish the exact UDP
 * quote from the constructed skb before neighbor output. Immediate failures
 * must cancel the reservation. */
int ker_udp_error_reserve(struct ker_udp_error_tracker *,
                          struct ker_udp_endpoint_handle,
                          struct ker_neighbor_monitor *, __be32 local_address,
                          __be16 local_port, __be32 peer_address,
                          __be16 peer_port, size_t payload_length,
                          struct ker_udp_error_token *);
int ker_udp_error_publish(struct ker_udp_error_tracker *,
                          struct ker_udp_error_token, struct sk_buff *);
int ker_udp_error_cancel(struct ker_udp_error_tracker *,
                         struct ker_udp_error_token);

/* Reclaim reservations only after all registered peer ARP queues and TX
 * exporters are empty. This is the explicit recovery path for native queue
 * drops that do not reach the TX observer. */
int ker_udp_error_resync(struct ker_udp_error_tracker *);

#endif
