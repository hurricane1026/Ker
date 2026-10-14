#include "runtime/udp-error.h"
#include "runtime/ethernet.h"
#include "runtime/ipv4-address.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/irqflags.h>
#include <net/checksum.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <string.h>

#define UDP_ERROR_QUOTE_LENGTH 28U
#define UDP_ERROR_ID_SPACE 65536U

static struct ker_udp_endpoint *current_endpoint(
    struct ker_udp_error_tracker *, struct ker_udp_endpoint_handle);
static void tombstone(struct ker_udp_error_record *);

static void pin_peer_callbacks(struct ker_udp_error_tracker *tracker) {
  for (size_t i = 0; i < tracker->peer_capacity; ++i) {
    struct ker_udp_error_peer *peer = &tracker->peers[i];
    if (peer->tracker != tracker || !peer->monitor)
      continue;
    if (!peer->callback_pins) {
      peer->callback_pmtu_busy = peer->pmtu.busy;
      peer->callback_observer_busy = peer->tx_observer.busy;
      peer->pmtu.busy = true;
      peer->tx_observer.busy = true;
    }
    ++peer->callback_pins;
  }
}

static void unpin_peer_callbacks(struct ker_udp_error_tracker *tracker) {
  for (size_t i = 0; i < tracker->peer_capacity; ++i) {
    struct ker_udp_error_peer *peer = &tracker->peers[i];
    if (peer->tracker != tracker || !peer->monitor || !peer->callback_pins)
      continue;
    if (!--peer->callback_pins) {
      peer->pmtu.busy = peer->callback_pmtu_busy;
      peer->tx_observer.busy = peer->callback_observer_busy;
    }
  }
}

static void flush_accepted(struct ker_udp_error_tracker *tracker,
                           uint64_t now) {
  bool valid = now <= UINT64_MAX - tracker->lifetime_ms &&
               (!tracker->clock_started || now >= tracker->last_now_ms);
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    struct ker_udp_error_record *record = &tracker->records[i];
    if (!record->accepted_pending)
      continue;
    struct ker_udp_endpoint *endpoint =
        current_endpoint(tracker, record->endpoint);
    if (!valid) {
      uint64_t base = tracker->clock_started && now < tracker->last_now_ms
                          ? tracker->last_now_ms : now;
      tombstone(record);
      record->expires_ms = base <= UINT64_MAX - tracker->lifetime_ms
                               ? base + tracker->lifetime_ms : UINT64_MAX;
      continue;
    }
    if (!endpoint || endpoint->incarnation != record->incarnation) {
      tombstone(record);
      record->expires_ms = now + tracker->lifetime_ms;
      continue;
    }
    record->state = KER_UDP_ERROR_SENT;
    record->skb = NULL;
    record->skb_identity = 0;
    record->accepted_pending = false;
    record->expires_ms = now + tracker->lifetime_ms;
  }
  if (valid) {
    tracker->clock_started = true;
    tracker->last_now_ms = now;
  }
}

static uint64_t error_clock(void *arg) {
  struct ker_udp_error_tracker *tracker = arg;
  bool tracker_was_busy = tracker->busy;
  bool service_was_busy = tracker->service->busy;
  bool endpoints_were_busy = tracker->endpoints->busy;
  tracker->busy = true;
  tracker->service->busy = true;
  tracker->endpoints->busy = true;
  pin_peer_callbacks(tracker);
  uint64_t value = tracker->clock(tracker->clock_arg);
  flush_accepted(tracker, value);
  unpin_peer_callbacks(tracker);
  tracker->busy = tracker_was_busy;
  tracker->service->busy = service_was_busy;
  tracker->endpoints->busy = endpoints_were_busy;
  return value;
}

static int tracker_check(const struct ker_udp_error_tracker *tracker) {
  if (!tracker || !tracker->service || !tracker->endpoints ||
      !tracker->service->receiver || !tracker->service->receiver->handler.runtime)
    return -EINVAL;
  if (rte_lcore_id() != tracker->service->receiver->handler.runtime->lcore)
    return -EXDEV;
  if (tracker->busy || tracker->service->busy ||
      tracker->service->receiver->handler.runtime->dispatching ||
      tracker->endpoints->busy || ker_local_irq_disabled())
    return -EBUSY;
  return 0;
}

static int read_now(struct ker_udp_error_tracker *tracker, uint64_t *now) {
  if (tracker->busy)
    return -EBUSY;
  bool service_was_busy = tracker->service->busy;
  bool endpoints_were_busy = tracker->endpoints->busy;
  tracker->busy = true;
  tracker->service->busy = true;
  tracker->endpoints->busy = true;
  pin_peer_callbacks(tracker);
  uint64_t value = tracker->clock(tracker->clock_arg);
  flush_accepted(tracker, value);
  unpin_peer_callbacks(tracker);
  tracker->busy = false;
  tracker->service->busy = service_was_busy;
  tracker->endpoints->busy = endpoints_were_busy;
  if (tracker->clock_started && value < tracker->last_now_ms)
    return -ERANGE;
  tracker->clock_started = true;
  tracker->last_now_ms = value;
  *now = value;
  return 0;
}

static struct ker_udp_error_peer *find_peer(
    const struct ker_udp_error_tracker *tracker,
    const struct ker_neighbor_monitor *monitor) {
  for (size_t i = 0; i < tracker->peer_capacity; ++i)
    if (tracker->peers[i].monitor == monitor)
      return &tracker->peers[i];
  return NULL;
}

static struct ker_udp_error_record *record_for_token(
    struct ker_udp_error_tracker *tracker, struct ker_udp_error_token token) {
  if (token.tracker != tracker || token.slot >= tracker->record_capacity ||
      !token.token)
    return NULL;
  struct ker_udp_error_record *record = &tracker->records[token.slot];
  return record->state == KER_UDP_ERROR_RESERVED &&
                 record->token == token.token &&
                 record->identification == token.identification
             ? record
             : NULL;
}

static void tombstone(struct ker_udp_error_record *record) {
  *record = (struct ker_udp_error_record){
      .state = KER_UDP_ERROR_TOMBSTONE,
      .identification = record->identification,
      .expires_ms = record->expires_ms};
}

static struct ker_udp_endpoint *current_endpoint(
    struct ker_udp_error_tracker *tracker,
    struct ker_udp_endpoint_handle handle) {
  struct ker_udp_endpoint_table *table = tracker->endpoints;
  if (!table->receiver || handle.table != table ||
      handle.slot >= table->capacity || !handle.generation)
    return NULL;
  struct ker_udp_endpoint *endpoint = &table->entries[handle.slot];
  if (!endpoint->receive || endpoint->generation != handle.generation)
    return NULL;
  return endpoint;
}

static void expire_sent(struct ker_udp_error_tracker *tracker, uint64_t now) {
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    struct ker_udp_error_record *record = &tracker->records[i];
    if ((record->state == KER_UDP_ERROR_SENT ||
         record->state == KER_UDP_ERROR_TOMBSTONE) &&
        now >= record->expires_ms)
      *record = (struct ker_udp_error_record){0};
  }
}

static struct ker_udp_error_queue *find_queue(
    struct ker_udp_error_tracker *tracker,
    struct ker_udp_endpoint_handle handle) {
  for (struct ker_udp_error_queue *queue = tracker->queue_head; queue;
       queue = queue->next)
    if (queue->attached && queue->endpoint.table == handle.table &&
        queue->endpoint.slot == handle.slot &&
        queue->endpoint.generation == handle.generation)
      return queue;
  return NULL;
}

static bool record_matches_quote(
    const struct ker_udp_error_record *record,
    const struct ker_icmpv4_quoted_ipv4_view *quote) {
  if (!record || !quote || !quote->flow_available || quote->protocol != 17 ||
      quote->header_length != 20 || quote->transport_length < 8 ||
      quote->total_length != record->ip_length)
    return false;
  const unsigned char *ip = quote->header;
  const unsigned char *udp = quote->transport;
  __be16 fragment;
  memcpy(&fragment, ip + 6, sizeof(fragment));
  if (fragment != htons(0x4000U) || ip_fast_csum(ip, 5) != 0)
    return false;
  __be32 local, peer;
  memcpy(&local, ip + 12, sizeof(local));
  memcpy(&peer, ip + 16, sizeof(peer));
  return local == record->local_address && peer == record->peer_address &&
         !memcmp(ip + 4, &record->identification, sizeof(record->identification)) &&
         !memcmp(udp, &record->local_port, sizeof(record->local_port)) &&
         !memcmp(udp + 2, &record->peer_port, sizeof(record->peer_port)) &&
         !memcmp(udp + 4, &record->udp_length, sizeof(record->udp_length)) &&
         !memcmp(udp + 6, &record->udp_checksum, sizeof(record->udp_checksum));
}

static int pmtu_confirm(void *arg, __be32 local, __be32 peer,
                        const struct ker_icmpv4_quoted_ipv4_view *quote) {
  struct ker_udp_error_peer *peer_state = arg;
  struct ker_udp_error_tracker *tracker = peer_state->tracker;
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    const struct ker_udp_error_record *record = &tracker->records[i];
    if (record->state != KER_UDP_ERROR_SENT ||
        record->monitor != peer_state->monitor ||
        record->local_address != local || record->peer_address != peer ||
        !record_matches_quote(record, quote))
      continue;
    struct ker_udp_endpoint *endpoint =
        current_endpoint(tracker, record->endpoint);
    return endpoint && endpoint->incarnation == record->incarnation;
  }
  return 0;
}

static int observe_control(const struct ker_icmpv4_control_event *event,
                           void *arg) {
  struct ker_udp_error_tracker *tracker = arg;
  if (!event || !event->has_quote)
    return 0;
  if (event->type == 5)
    return 0; /* Redirects never install a route or alter a peer. */

  int error_number;
  if (event->type == 3) {
    switch (event->code) {
    case 0: case 6: case 11: error_number = ENETUNREACH; break;
    case 1: case 5: case 7: case 8: case 12: error_number = EHOSTUNREACH; break;
    case 2: error_number = EPROTONOSUPPORT; break;
    case 3: error_number = ECONNREFUSED; break;
    case 4: error_number = EMSGSIZE; break;
    case 9: case 10: case 13: case 14: case 15: error_number = EACCES; break;
    default: return 0;
    }
  } else if (event->type == 11)
    error_number = ETIMEDOUT;
  else if (event->type == 12)
    error_number = EPROTO;
  else
    return 0;

  int error = read_now(tracker, &(uint64_t){0});
  if (error)
    return error;
  expire_sent(tracker, tracker->last_now_ms);
  tracker->busy = true;
  struct ker_udp_error_record *matched = NULL;
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    struct ker_udp_error_record *record = &tracker->records[i];
    if (record->state != KER_UDP_ERROR_SENT ||
        !record_matches_quote(record, &event->quote))
      continue;
    struct ker_udp_endpoint *endpoint =
        current_endpoint(tracker, record->endpoint);
    if (!endpoint || endpoint->incarnation != record->incarnation) {
      tombstone(record);
      continue;
    }
    matched = record;
    break;
  }
  if (!matched) {
    tracker->busy = false;
    return 0;
  }
  struct ker_udp_error_peer *peer = find_peer(tracker, matched->monitor);
  if (!peer) {
    tracker->busy = false;
    return 0;
  }
  uint32_t current_mtu = 0;
  int pmtu_status = 0;
  if (event->type == 3 && event->code == 4) {
    pmtu_status = ker_icmpv4_pmtu_apply(&peer->pmtu, &event->message,
                                        &event->quote);
    if (pmtu_status >= 0) {
      int mtu_status = ker_icmpv4_pmtu_current_mtu(&peer->pmtu, &current_mtu);
      if (mtu_status)
        pmtu_status = mtu_status;
    }
  }
  struct ker_udp_error_queue *queue =
      find_queue(tracker, matched->endpoint);
  if (queue) {
    queue->busy = true;
    if (queue->count == queue->capacity) {
      if (queue->dropped != UINT64_MAX)
        ++queue->dropped;
    } else {
      size_t remaining = queue->capacity - queue->head;
      size_t tail = queue->count >= remaining
                        ? queue->count - remaining
                        : queue->head + queue->count;
      queue->events[tail] = (struct ker_udp_error_event){
          .error = error_number,
          .pmtu_status = pmtu_status,
          .type = event->type,
          .code = event->code,
          .next_hop_mtu = current_mtu ? (uint16_t)current_mtu
                                      : event->next_hop_mtu,
          .local_address = matched->local_address,
          .peer_address = matched->peer_address,
          .reporter_address = event->source,
          .local_port = matched->local_port,
          .peer_port = matched->peer_port,
          .sequence = matched->sequence,
          .incarnation = matched->incarnation};
      ++queue->count;
    }
    queue->busy = false;
  }
  tombstone(matched);
  tracker->busy = false;
  return 1;
}

static int tx_prepare(const struct rte_mbuf *packet,
                      struct ker_tx_export_observer_note *note, void *arg) {
  (void)arg;
  if (!packet || !note)
    return -EINVAL;
  note->length = 0;
  if (rte_pktmbuf_pkt_len(packet) < ETH_HLEN + UDP_ERROR_QUOTE_LENGTH)
    return 0;
  unsigned char bytes[UDP_ERROR_QUOTE_LENGTH];
  const void *read = rte_pktmbuf_read(packet, ETH_HLEN, sizeof(bytes), bytes);
  if (!read)
    return 0;
  if (read != bytes)
    memcpy(bytes, read, sizeof(bytes));
  if ((bytes[0] >> 4) != 4 || (bytes[0] & 0x0fU) != 5 || bytes[9] != 17)
    return 0;
  memcpy(note->bytes, bytes, sizeof(bytes));
  note->length = sizeof(bytes);
  return 0;
}

static void tx_complete(const struct ker_tx_export_observer_note *note,
                        int sink_status, void *arg) {
  struct ker_udp_error_peer *peer = arg;
  if (!note || note->length != UDP_ERROR_QUOTE_LENGTH || sink_status != 0)
    return; /* A rejected sink leaves the original skb pending for retry. */
  struct ker_udp_error_tracker *tracker = peer->tracker;
  if (!note->skb)
    return;
  const unsigned char *ip = note->bytes;
  const unsigned char *udp = ip + 20;
  __be32 local, destination;
  __be16 identification, ip_length, udp_length, source_port, destination_port,
      checksum;
  memcpy(&local, ip + 12, 4);
  memcpy(&destination, ip + 16, 4);
  memcpy(&identification, ip + 4, 2);
  memcpy(&ip_length, ip + 2, 2);
  memcpy(&source_port, udp, 2);
  memcpy(&destination_port, udp + 2, 2);
  memcpy(&udp_length, udp + 4, 2);
  memcpy(&checksum, udp + 6, 2);
  __be16 frag_off;
  memcpy(&frag_off, ip + 6, sizeof(frag_off));
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    struct ker_udp_error_record *record = &tracker->records[i];
    if (record->state != KER_UDP_ERROR_RESERVED || record->accepted_pending ||
        record->skb != note->skb || record->skb_identity != note->skb_identity ||
        record->monitor != peer->monitor ||
        record->local_address != local || record->peer_address != destination ||
        record->identification != identification || record->frag_off != frag_off ||
        record->local_port != source_port ||
        record->peer_port != destination_port || record->ip_length != ntohs(ip_length) ||
        record->udp_length != udp_length ||
        record->udp_checksum != checksum)
      continue;
    if (tracker->busy) {
      record->accepted_pending = true;
      return;
    }
    tracker->busy = true;
    record->accepted_pending = true;
    (void)error_clock(tracker);
    tracker->busy = false;
    return;
  }
}

int ker_udp_error_tracker_init(
    struct ker_udp_error_tracker *tracker, struct ker_icmpv4_service *service,
    struct ker_udp_endpoint_table *endpoints,
    struct ker_udp_error_record *records, size_t record_capacity,
    struct ker_udp_error_peer *peers, size_t peer_capacity,
    size_t queue_capacity,
    ker_udp_error_clock_fn clock, void *clock_arg, uint64_t lifetime_ms) {
  if (!tracker || !service || !service->receiver || !endpoints || !records || !record_capacity ||
      !peers || !peer_capacity || !queue_capacity || !clock ||
      !lifetime_ms || service->receiver != endpoints->receiver ||
      service->receiver->udp_endpoint_table != endpoints ||
      endpoints->icmpv4 != service ||
      record_capacity > SIZE_MAX / sizeof(*records) ||
      peer_capacity > SIZE_MAX / sizeof(*peers))
    return -EINVAL;
  if (tracker->busy)
    return -EBUSY;
  if (tracker->service || tracker->records || tracker->peers ||
      tracker->queue_head)
    return -EALREADY;
  if (endpoints->io_refs == UINT_MAX)
    return -EOVERFLOW;
  int error = tracker_check(&(struct ker_udp_error_tracker){
      .service = service, .endpoints = endpoints});
  if (error)
    return error;
  for (size_t i = 0; i < record_capacity; ++i)
    if (records[i].state != KER_UDP_ERROR_FREE || records[i].token)
      return -EINVAL;
  for (size_t i = 0; i < peer_capacity; ++i)
    if (peers[i].monitor || peers[i].tracker || peers[i].busy)
      return -EINVAL;
  struct ker_udp_error_tracker candidate = {
      .service = service,
      .endpoints = endpoints,
      .records = records,
      .peers = peers,
      .record_capacity = record_capacity,
      .peer_capacity = peer_capacity,
      .queue_capacity = queue_capacity,
      .clock = clock,
      .clock_arg = clock_arg,
      .lifetime_ms = lifetime_ms};
  *tracker = candidate;
  bool service_was_busy = service->busy;
  bool endpoints_were_busy = endpoints->busy;
  tracker->busy = true;
  service->busy = true;
  endpoints->busy = true;
  candidate.last_now_ms = clock(clock_arg);
  candidate.clock_started = true;
  service->busy = service_was_busy;
  endpoints->busy = endpoints_were_busy;
  tracker->busy = false;
  error = ker_icmpv4_service_control_observer_attach(service, observe_control,
                                                      tracker);
  if (error) {
    *tracker = (struct ker_udp_error_tracker){0};
    return error;
  }
  candidate.attached = true;
  *tracker = candidate;
  ++endpoints->io_refs;
  return 0;
}

int ker_udp_error_tracker_cleanup(struct ker_udp_error_tracker *tracker) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (tracker->peer_count || tracker->queue_count || tracker->io_refs)
    return -EBUSY;
  uint64_t now;
  error = read_now(tracker, &now);
  if (error)
    return error;
  expire_sent(tracker, now);
  for (size_t i = 0; i < tracker->record_capacity; ++i)
    if (tracker->records[i].state != KER_UDP_ERROR_FREE)
      return -EBUSY;
  error = ker_icmpv4_service_control_observer_detach(
      tracker->service, observe_control, tracker);
  if (error)
    return error;
  if (!tracker->endpoints->io_refs)
    return -EINVAL;
  --tracker->endpoints->io_refs;
  *tracker = (struct ker_udp_error_tracker){0};
  return 0;
}

int ker_udp_error_peer_register(struct ker_udp_error_tracker *tracker,
                                struct ker_neighbor_monitor *monitor) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (!monitor || !monitor->entry || !monitor->table ||
      !monitor->resolution_tx || !monitor->table->address ||
      !monitor->table->address->native ||
      !monitor->table->address->native->ifa_list)
    return -EINVAL;
  if (monitor->table->lcore !=
      tracker->service->receiver->handler.runtime->lcore)
    return -EXDEV;
  if (monitor->udp_adapter_refs == UINT_MAX)
    return -EOVERFLOW;
  if (monitor->busy || monitor->timer.running || monitor->timer.scoping ||
      !monitor->timer.runtime || monitor->timer.runtime->polling ||
      monitor->resolution_tx->polling || monitor->output_mtu ||
      monitor->output_mtu_ctx)
    return -EBUSY;
  if (find_peer(tracker, monitor))
    return -EALREADY;
  if (tracker->peer_count == tracker->peer_capacity)
    return -ENOSPC;
  struct ker_udp_error_peer *peer = NULL;
  for (size_t i = 0; i < tracker->peer_capacity; ++i)
    if (!tracker->peers[i].monitor) {
      peer = &tracker->peers[i];
      break;
    }
  if (!peer)
    return -ENOSPC;
  peer->tracker = tracker;
  peer->monitor = monitor;
  ++monitor->udp_adapter_refs;
  error = ker_icmpv4_pmtu_init(&peer->pmtu, monitor,
      monitor->entry->dev->mtu, tracker->lifetime_ms, error_clock, tracker,
      pmtu_confirm, peer);
  if (error) {
    --monitor->udp_adapter_refs;
    *peer = (struct ker_udp_error_peer){0};
    return error;
  }
  error = ker_tx_export_observer_attach(monitor->resolution_tx,
      &peer->tx_observer, tx_prepare, tx_complete, peer);
  if (error) {
    (void)ker_icmpv4_pmtu_cleanup(&peer->pmtu);
    --monitor->udp_adapter_refs;
    *peer = (struct ker_udp_error_peer){0};
    return error;
  }
  ++tracker->peer_count;
  return 0;
}

static bool has_live_peer_record(const struct ker_udp_error_tracker *tracker,
                                 const struct ker_neighbor_monitor *monitor,
                                 uint64_t now) {
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    const struct ker_udp_error_record *record = &tracker->records[i];
    if (record->monitor == monitor &&
        (record->state == KER_UDP_ERROR_RESERVED ||
         (record->state == KER_UDP_ERROR_SENT && now < record->expires_ms)))
      return true;
  }
  return false;
}

static void tombstone_stale_peer_records(
    struct ker_udp_error_tracker *tracker,
    const struct ker_neighbor_monitor *monitor) {
  for (size_t i = 0; i < tracker->record_capacity; ++i) {
    struct ker_udp_error_record *record = &tracker->records[i];
    if (record->state != KER_UDP_ERROR_SENT || record->monitor != monitor)
      continue;
    struct ker_udp_endpoint *endpoint =
        current_endpoint(tracker, record->endpoint);
    if (!endpoint || endpoint->incarnation != record->incarnation)
      tombstone(record);
  }
}

int ker_udp_error_peer_unregister(struct ker_udp_error_tracker *tracker,
                                  struct ker_neighbor_monitor *monitor) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  struct ker_udp_error_peer *peer = find_peer(tracker, monitor);
  if (!peer)
    return -ENOENT;
  if (!monitor->timer.runtime || monitor->busy || monitor->timer.running ||
      monitor->timer.scoping || monitor->timer.runtime->polling ||
      monitor->resolution_tx->polling ||
      monitor->output_mtu_ctx != &peer->pmtu)
    return -EBUSY;
  if (!monitor->udp_adapter_refs)
    return -EINVAL;
  uint64_t now;
  error = read_now(tracker, &now);
  if (error)
    return error;
  expire_sent(tracker, now);
  tombstone_stale_peer_records(tracker, monitor);
  if (has_live_peer_record(tracker, monitor, now))
    return -EBUSY;
  error = ker_tx_export_observer_detach(monitor->resolution_tx,
                                        &peer->tx_observer);
  if (error)
    return error;
  error = ker_icmpv4_pmtu_cleanup(&peer->pmtu);
  if (error) {
    int restore = ker_tx_export_observer_attach(monitor->resolution_tx,
        &peer->tx_observer, tx_prepare, tx_complete, peer);
    if (restore)
      return -EIO;
    return error;
  }
  *peer = (struct ker_udp_error_peer){0};
  --monitor->udp_adapter_refs;
  --tracker->peer_count;
  return 0;
}

int ker_udp_error_queue_attach(struct ker_udp_error_tracker *tracker,
                               struct ker_udp_endpoint_handle handle,
                               struct ker_udp_error_queue *queue,
                               struct ker_udp_error_event *events,
                               size_t capacity) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (!queue || !events || !capacity)
    return -EINVAL;
  if (capacity > SIZE_MAX / sizeof(*events))
    return -EOVERFLOW;
  if (!current_endpoint(tracker, handle))
    return -ESTALE;
  if (queue->attached || queue->events || queue->capacity || queue->next)
    return -EALREADY;
  if (tracker->queue_count == tracker->queue_capacity)
    return -ENOSPC;
  for (size_t i = 0; i < capacity; ++i)
    if (events[i].error || events[i].pmtu_status || events[i].type ||
        events[i].code || events[i].next_hop_mtu || events[i].local_address ||
        events[i].peer_address || events[i].reporter_address ||
        events[i].local_port || events[i].peer_port || events[i].sequence ||
        events[i].incarnation)
      return -EINVAL;
  for (struct ker_udp_error_queue *at = tracker->queue_head; at; at = at->next)
    if (at->endpoint.table == handle.table && at->endpoint.slot == handle.slot &&
        at->endpoint.generation == handle.generation)
      return -EALREADY;
  *queue = (struct ker_udp_error_queue){
      .next = tracker->queue_head,
      .endpoint = handle,
      .events = events,
      .capacity = capacity,
      .attached = true};
  tracker->queue_head = queue;
  ++tracker->queue_count;
  return 0;
}

int ker_udp_error_queue_detach(struct ker_udp_error_tracker *tracker,
                               struct ker_udp_endpoint_handle handle) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  struct ker_udp_error_queue **link = &tracker->queue_head;
  while (*link && (!(*link)->attached ||
                   (*link)->endpoint.table != handle.table ||
                   (*link)->endpoint.slot != handle.slot ||
                   (*link)->endpoint.generation != handle.generation))
    link = &(*link)->next;
  if (!*link)
    return -ENOENT;
  struct ker_udp_error_queue *queue = *link;
  if (queue->busy)
    return -EBUSY;
  for (size_t i = 0; i < tracker->record_capacity; ++i)
    if (tracker->records[i].state == KER_UDP_ERROR_RESERVED &&
        tracker->records[i].endpoint.table == handle.table &&
        tracker->records[i].endpoint.slot == handle.slot &&
        tracker->records[i].endpoint.generation == handle.generation)
      return -EBUSY;
  *link = queue->next;
  struct ker_udp_error_event *events = queue->events;
  size_t capacity = queue->capacity;
  memset(events, 0, capacity * sizeof(*events));
  *queue = (struct ker_udp_error_queue){0};
  --tracker->queue_count;
  return 0;
}

int ker_udp_error_recv(struct ker_udp_error_tracker *tracker,
                       struct ker_udp_endpoint_handle handle,
                       struct ker_udp_error_event *out) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (!out)
    return -EINVAL;
  struct ker_udp_error_queue *queue = find_queue(tracker, handle);
  if (!queue)
    return -ESTALE;
  if (!current_endpoint(tracker, handle))
    return -ESTALE;
  while (queue->count) {
    struct ker_udp_error_event *head = &queue->events[queue->head];
    struct ker_udp_endpoint *endpoint = current_endpoint(tracker, handle);
    if (endpoint && head->incarnation == endpoint->incarnation)
      break;
    *head = (struct ker_udp_error_event){0};
    queue->head = (queue->head + 1) % queue->capacity;
    --queue->count;
  }
  if (!queue->count)
    return 0;
  *out = queue->events[queue->head];
  queue->events[queue->head] = (struct ker_udp_error_event){0};
  queue->head = (queue->head + 1) % queue->capacity;
  --queue->count;
  return 1;
}

int ker_udp_error_reserve(struct ker_udp_error_tracker *tracker,
                          struct ker_udp_endpoint_handle handle,
                          struct ker_neighbor_monitor *monitor,
                          __be32 local_address, __be16 local_port,
                          __be32 peer_address, __be16 peer_port,
                          size_t payload_length,
                          struct ker_udp_error_token *out) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (!out || !local_address || !local_port || !peer_address || !peer_port ||
      payload_length > UINT16_MAX - 28U)
    return -EINVAL;
  struct ker_udp_endpoint *endpoint = current_endpoint(tracker, handle);
  if (!endpoint)
    return -ESTALE;
  if (!find_queue(tracker, handle))
    return -ENXIO;
  if (!find_peer(tracker, monitor) ||
      !monitor->entry || memcmp(monitor->entry->primary_key, &peer_address, 4))
    return -EHOSTUNREACH;
  if (endpoint->port != local_port)
    return -EINVAL;
  uint64_t now;
  error = read_now(tracker, &now);
  if (error)
    return error;
  expire_sent(tracker, now);
  size_t slot = tracker->record_capacity;
  for (size_t i = 0; i < tracker->record_capacity; ++i)
    if (tracker->records[i].state == KER_UDP_ERROR_FREE) {
      slot = i;
      break;
    }
  if (slot == tracker->record_capacity)
    return -ENOSPC;
  if (tracker->next_token == UINT64_MAX ||
      tracker->next_sequence == UINT64_MAX)
    return -EOVERFLOW;
  __be16 identification = 0;
  bool available = false;
  for (uint32_t attempt = 0; attempt < UDP_ERROR_ID_SPACE; ++attempt) {
    uint16_t candidate = (uint16_t)(tracker->next_identification + attempt);
    bool used = false;
    for (size_t i = 0; i < tracker->record_capacity; ++i)
      if (tracker->records[i].state != KER_UDP_ERROR_FREE &&
          ntohs(tracker->records[i].identification) == candidate) {
        used = true;
        break;
      }
    if (!used) {
      identification = htons(candidate);
      tracker->next_identification = (uint16_t)(candidate + 1U);
      available = true;
      break;
    }
  }
  if (!available)
    return -ENOSPC;
  uint64_t token_value = tracker->next_token + 1;
  uint64_t sequence = tracker->next_sequence + 1;
  size_t udp_length = payload_length + 8;
  tracker->records[slot] = (struct ker_udp_error_record){
      .state = KER_UDP_ERROR_RESERVED,
      .endpoint = handle,
      .monitor = monitor,
      .token = token_value,
      .sequence = sequence,
      .incarnation = endpoint->incarnation,
      .local_address = local_address,
      .peer_address = peer_address,
      .local_port = local_port,
      .peer_port = peer_port,
      .identification = identification,
      .frag_off = htons(0x4000U),
      .udp_length = htons((uint16_t)udp_length)};
  tracker->next_token = token_value;
  tracker->next_sequence = sequence;
  *out = (struct ker_udp_error_token){tracker, slot, token_value,
                                       identification};
  return 0;
}

int ker_udp_error_publish(struct ker_udp_error_tracker *tracker,
                          struct ker_udp_error_token token,
                          struct sk_buff *skb) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  if (!skb)
    return -EINVAL;
  struct ker_udp_error_record *record = record_for_token(tracker, token);
  if (!record)
    return -ESTALE;
  struct ker_udp_endpoint *endpoint =
      current_endpoint(tracker, record->endpoint);
  if (!endpoint || endpoint->incarnation != record->incarnation)
    return -ESTALE;
  struct ker_skb_context *context =
      tracker->service->receiver->handler.runtime->context;
  error = ker_skb_validate(skb, context);
  if (error)
    return error;
  if (skb_shared(skb) || skb_cloned(skb) || skb_is_nonlinear(skb) ||
      skb->protocol != htons(ETH_P_IP) ||
      skb->network_header != skb_headroom(skb) + ETH_HLEN ||
      skb->head + skb->network_header != skb->data + ETH_HLEN ||
      skb->len < ETH_HLEN + 28)
    return -EINVAL;
  const unsigned char *ip_header = skb->head + skb->network_header;
  unsigned int packet_length = ((unsigned int)ip_header[2] << 8) | ip_header[3];
  __be16 identification;
  memcpy(&identification, ip_header + 4, sizeof(identification));
  __be16 frag_off;
  memcpy(&frag_off, ip_header + 6, sizeof(frag_off));
  if ((ip_header[0] >> 4) != 4 || (ip_header[0] & 0x0fU) != 5 ||
      ip_header[9] != 17 || frag_off != htons(0x4000U) ||
      ip_fast_csum(ip_header, 5) != 0 || packet_length < 28 || packet_length > UINT16_MAX ||
      ETH_HLEN + packet_length > skb->len ||
      identification != record->identification)
    return -EINVAL;
  const unsigned char *udp = ip_header + 20;
  __be32 source, destination;
  __be16 source_port, destination_port, udp_length, checksum;
  memcpy(&source, ip_header + 12, 4);
  memcpy(&destination, ip_header + 16, 4);
  memcpy(&source_port, udp, 2);
  memcpy(&destination_port, udp + 2, 2);
  memcpy(&udp_length, udp + 4, 2);
  memcpy(&checksum, udp + 6, 2);
  if (source != record->local_address || destination != record->peer_address ||
      source_port != record->local_port || destination_port != record->peer_port ||
      udp_length != record->udp_length ||
      packet_length != 20U + ntohs(udp_length))
    return -EINVAL;
  record->ip_length = (uint16_t)packet_length;
  record->udp_checksum = checksum;
  record->skb = skb;
  record->skb_identity = ker_skb_identity(skb);
  return 0;
}

int ker_udp_error_cancel(struct ker_udp_error_tracker *tracker,
                         struct ker_udp_error_token token) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  struct ker_udp_error_record *record = record_for_token(tracker, token);
  if (!record)
    return -ESTALE;
  *record = (struct ker_udp_error_record){0};
  return 0;
}

int ker_udp_error_resync(struct ker_udp_error_tracker *tracker) {
  int error = tracker_check(tracker);
  if (error)
    return error;
  for (size_t i = 0; i < tracker->peer_capacity; ++i) {
    struct ker_udp_error_peer *peer = &tracker->peers[i];
    struct ker_neighbor_monitor *monitor = peer->monitor;
    if (!monitor)
      continue;
    struct ker_tx_export *tx = monitor->resolution_tx;
    if (monitor->busy || monitor->timer.running || monitor->timer.scoping ||
        monitor->timer.runtime->polling || tx->polling || tx->pending ||
        tx->packets || !monitor->entry || monitor->entry->arp_queue.qlen)
      return -EBUSY;
  }
  for (size_t i = 0; i < tracker->record_capacity; ++i)
    if (tracker->records[i].state == KER_UDP_ERROR_RESERVED)
      tracker->records[i] = (struct ker_udp_error_record){0};
  return 0;
}
