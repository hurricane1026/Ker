#include "runtime/tcp-listener.h"
#include "runtime/tcp-active.h"
#include "runtime/tcp-mss.h"
#include "runtime/tcp-neighbor-create.h"
#include <errno.h>
#include <limits.h>
#include <linux/irqflags.h>
#include <linux/if.h>
#include <string.h>

static int owner(struct ker_tcp_listener *t)
{
    if (!t || !t->receiver || !t->receiver->handler.registered) return -EINVAL;
    if (rte_lcore_id() != t->receiver->handler.runtime->lcore) return -EXDEV;
    if (t->busy || t->receiver->handler.runtime->dispatching || t->tx->polling ||
        ker_local_irq_disabled()) return -EBUSY;
    return 0;
}
static bool unicast(__be32 ip, struct ker_ipv4_address *a)
{
    uint32_t host = rte_be_to_cpu_32(ip);
    if (!(host >> 24) || (host >> 24) == 127 || (host >> 28) >= 14) return false;
    struct in_ifaddr *ifa = a->native->ifa_list;
    uint32_t mask = ifa->ifa_prefixlen ? UINT32_MAX << (32 - ifa->ifa_prefixlen) : 0;
    return ifa->ifa_prefixlen >= 31 ||
        (host & mask) != (rte_be_to_cpu_32(ifa->ifa_local) & mask) ||
        (host & ~mask) != ~mask;
}
static bool stream_enabled(const struct ker_tcp_listener *t)
{ return t->config.receive_storage != NULL; }
static bool send_enabled(const struct ker_tcp_listener *t)
{ return t->config.send_storage != NULL; }
static uint16_t initial_window(const struct ker_tcp_listener *t)
{ return stream_enabled(t) && t->config.receive_capacity < t->config.window ?
    t->config.receive_capacity : t->config.window; }
static uint16_t advertised_window(const struct ker_tcp_listener *t,
                                 const struct ker_tcp_request *r)
{
    uint16_t limit = initial_window(t);
    return r->receive_bytes < limit ? limit - r->receive_bytes : 0;
}
static bool before(uint32_t a, uint32_t b)
{ return (int32_t)(a - b) < 0; }
static bool at_contiguous_edge(const struct ker_tcp_packet_view *p, uint32_t next)
{
    return p->sequence == next ||
        (before(p->sequence, next) && p->sequence + p->payload_length == next);
}
static unsigned char *receive_ring(struct ker_tcp_listener *t, struct ker_tcp_request *r)
{ return t->config.receive_storage + (size_t)(r - t->requests) * t->config.receive_capacity; }
static unsigned char *send_ring(struct ker_tcp_listener *t, struct ker_tcp_request *r)
{ return t->config.send_storage + (size_t)(r - t->requests) * t->config.send_capacity; }
static void discard_stream_data(struct ker_tcp_request *r)
{
    r->receive_bytes = r->receive_head = 0;
    r->ack_pending = false;
}
static void discard_stream(struct ker_tcp_request *r)
{
    discard_stream_data(r);
    r->receive_next = r->receive_right = 0;
}
static void discard_send(struct ker_tcp_request *r)
{
    r->send_bytes = r->send_head = 0;
    r->send_retry_ms = r->send_deadline_ms = r->send_backoff_ms = 0;
}
static bool valid_send_ack(const struct ker_tcp_request *r, uint32_t ack)
{ return !before(ack, r->send_unacknowledged) && !before(r->send_next, ack); }
static bool expire_send(struct ker_tcp_request *r, uint64_t now)
{
    if (r->state != KER_TCP_REQUEST_READY || !r->send_bytes || now < r->send_deadline_ms)
        return false;
    r->state = KER_TCP_REQUEST_FAILED;
    r->error = -ETIMEDOUT;
    discard_send(r);
    return true;
}
static bool send_ack_eligible(const struct ker_tcp_listener *t,
                              const struct ker_tcp_request *r,
                              const struct ker_tcp_packet_view *p)
{
    if (!(p->flags & KER_TCP_ACK)) return false;
    if (!p->payload_length) return p->sequence == r->receive_next;
    if (!stream_enabled(t) || r->receive_right == r->receive_next) return false;
    if (p->sequence == r->receive_next) return true;
    if (!before(p->sequence, r->receive_next)) return false;
    return r->receive_next - p->sequence < p->payload_length;
}
static int emit(struct ker_tcp_listener *t, struct ker_tcp_request *r, uint8_t flags)
{
    unsigned char options[4] = {2, 4, (unsigned char)(t->config.mss >> 8),
                                (unsigned char)t->config.mss};
    struct sk_buff *skb = NULL;
    bool syn = (flags & KER_TCP_SYN) != 0;
    uint16_t window = syn ? initial_window(t) : t->config.window;
    if (stream_enabled(t) && r->state == KER_TCP_REQUEST_READY) {
        if (flags == KER_TCP_ACK) window = advertised_window(t, r);
        else window = initial_window(t);
    }
    uint32_t ack = (stream_enabled(t) || send_enabled(t)) && r->state != KER_TCP_REQUEST_SYN ?
        r->receive_next : r->peer_isn + 1U;
    uint32_t sequence = syn ? r->local_isn : send_enabled(t) && r->state != KER_TCP_REQUEST_SYN ?
        r->send_next : r->local_isn + (syn ? 0U : 1U);
    int error = ker_tcp_ipv4_create_neighbor(t->neighbors, t->peer_ip,
        t->config.port, r->peer_port,
        rte_cpu_to_be_32(sequence),
        rte_cpu_to_be_32(ack), rte_cpu_to_be_16(window), flags, t->config.ttl,
        syn ? options : NULL, syn ? sizeof(options) : 0, NULL, 0, &skb);
    if (error) return error;
    error = ker_tx_export_enqueue(t->tx, &skb);
    if (skb) BUG_ON(ker_skb_free(skb));
    if (!error && flags == KER_TCP_ACK && stream_enabled(t) && r->state == KER_TCP_REQUEST_READY) {
        r->receive_right = r->receive_next + window;
        r->ack_pending = false;
    }
    return error;
}
static int emit_data(struct ker_tcp_listener *t, struct ker_tcp_request *r,
                     uint32_t sequence, const void *data, uint16_t length)
{
    uint16_t window = advertised_window(t, r);
    struct sk_buff *skb = NULL;
    int error = ker_tcp_ipv4_create_neighbor(t->neighbors, t->peer_ip,
        t->config.port, r->peer_port, rte_cpu_to_be_32(sequence),
        rte_cpu_to_be_32(r->receive_next), rte_cpu_to_be_16(window),
        KER_TCP_ACK | KER_TCP_PSH, t->config.ttl, NULL, 0, data, length, &skb);
    if (error) return error;
    error = ker_tx_export_enqueue(t->tx, &skb);
    if (skb) BUG_ON(ker_skb_free(skb));
    if (!error && stream_enabled(t)) {
        r->receive_right = r->receive_next + window;
        r->ack_pending = false;
    }
    return error;
}
static int retransmit(struct ker_tcp_listener *t, struct ker_tcp_request *r)
{
    if (!r->send_bytes) return 0;
    return emit_data(t, r, r->send_unacknowledged,
        send_ring(t, r) + r->send_head, r->send_bytes);
}
static void acknowledge_send(struct ker_tcp_listener *t, struct ker_tcp_request *r,
                             const struct ker_tcp_packet_view *p)
{
    if (!send_enabled(t) || !(p->flags & KER_TCP_ACK) || !valid_send_ack(r, p->acknowledgment)) return;
    r->peer_window = p->window;
    r->send_right = p->acknowledgment + p->window;
    if (before(r->send_unacknowledged, p->acknowledgment)) {
        uint32_t advance = p->acknowledgment - r->send_unacknowledged;
        r->send_unacknowledged = p->acknowledgment;
        if (advance >= r->send_bytes) discard_send(r);
        else {
            r->send_head = (r->send_head + advance) % t->config.send_capacity;
            r->send_bytes -= advance;
        }
    }
}
static void discard(struct ker_tcp_listener *t, struct ker_tcp_request *r)
{
    *r = (struct ker_tcp_request){0};
    --t->count;
}
static int receive_data(struct ker_tcp_listener *t, struct ker_tcp_request *r,
                        const struct ker_tcp_packet_view *p)
{
    uint32_t next = r->receive_next, seq = p->sequence;
    unsigned int skip = 0, length = p->payload_length;
    if (before(seq, next)) {
        skip = next - seq;
        if (skip >= length) length = 0;
        else { length -= skip; seq = next; }
    }
    if (seq != next) length = 0;
    uint32_t available = r->receive_right - next;
    if (length > available) length = available;
    uint16_t capacity = t->config.receive_capacity;
    if (length > capacity - r->receive_bytes) return -EOVERFLOW;
    if (length) {
        unsigned char *ring = receive_ring(t, r);
        unsigned int tail = (r->receive_head + r->receive_bytes) % capacity;
        unsigned int first = length < capacity - tail ? length : capacity - tail;
        memcpy(ring + tail, p->payload + skip, first);
        memcpy(ring, p->payload + skip + first, length - first);
        r->receive_bytes += length;
        r->receive_next += length;
    }
    r->ack_pending = true;
    t->last_tx_error = emit(t, r, KER_TCP_ACK);
    return t->last_tx_error;
}
static bool syn_only(const struct ker_tcp_packet_view *p)
{
    /* ECE/CWR offers are declined by our SYN-ACK; no ECN negotiation. */
    return (p->flags & ~(KER_TCP_ECE | KER_TCP_CWR)) == KER_TCP_SYN && !p->payload_length;
}
static int receive_request(void *arg, struct sk_buff *skb,
                            const struct ker_transport_message *m)
{
    struct ker_tcp_listener *t = arg;
    const struct ker_tcp_packet_view *p = &m->packet.tcp;
    if (p->destination_port != t->config.port) return 0;
    __be32 src, dst;
    memcpy(&src, m->ipv4.header + 12, 4);
    memcpy(&dst, m->ipv4.header + 16, 4);
    struct ker_eth_device *d = t->receiver->handler.device;
    const unsigned char *eth = skb->head + skb->mac_header;
    if (t->busy || src != t->peer_ip || !p->source_port || skb->pkt_type != PACKET_HOST ||
        m->ipv4.header_length != 20 || !m->ipv4.header[8] ||
        (rte_be_to_cpu_16(m->ipv4.frag_off) & 0xbfff) ||
        ker_ipv4_address_is_local(t->neighbors->address, dst) != 1 ||
        memcmp(eth, d->native->dev_addr, ETH_ALEN) || (eth[ETH_ALEN] & 1))
        return -EOPNOTSUPP;
    struct ker_tcp_request *r = NULL, *empty = NULL;
    for (size_t i = 0; i < t->capacity; ++i) {
        if (!t->requests[i].state) { if (!empty) empty = &t->requests[i]; }
        else if (t->requests[i].peer_port == p->source_port) r = &t->requests[i];
    }
    t->busy = true;
    int error = 0;
    if (r) {
        if (r->state == KER_TCP_REQUEST_SYN && t->now_ms >= r->deadline_ms) {
            /* RX never establishes a request already expired at this sample. */
            r->state = KER_TCP_REQUEST_FAILED;
            r->error = -ETIMEDOUT;
            ++t->timed_out;
        }
        if (expire_send(r, t->now_ms)) goto done;
        if (r->state == KER_TCP_REQUEST_RESET || r->state == KER_TCP_REQUEST_FAILED)
            goto done;
        uint32_t expected_peer_sequence = (stream_enabled(t) || send_enabled(t)) && r->state == KER_TCP_REQUEST_READY ?
            r->receive_next : r->peer_isn + 1U;
        if ((p->flags & KER_TCP_RST) && p->sequence == expected_peer_sequence) {
            r->state = KER_TCP_REQUEST_FAILED;
            r->error = -ECONNRESET;
            discard_stream_data(r);
            discard_send(r);
            goto done;
        }
        if (r->state == KER_TCP_REQUEST_SYN) {
            bool final_ack = (p->flags == KER_TCP_ACK ||
                (stream_enabled(t) && p->flags == (KER_TCP_ACK | KER_TCP_PSH))) &&
                p->sequence == r->peer_isn + 1U &&
                p->acknowledgment == r->local_isn + 1U;
            if (final_ack && (!p->payload_length || stream_enabled(t)) &&
                !(p->flags & KER_TCP_FIN)) {
                r->state = KER_TCP_REQUEST_READY;
                if (stream_enabled(t) || send_enabled(t))
                    r->receive_next = p->sequence;
                if (stream_enabled(t)) {
                    r->receive_right = r->receive_next + initial_window(t);
                }
                if (send_enabled(t)) {
                    r->send_unacknowledged = r->send_next = r->local_isn + 1U;
                    r->peer_window = p->window;
                    r->send_right = r->send_next + p->window;
                }
                if (stream_enabled(t) && p->payload_length) error = receive_data(t, r, p);
            } else if ((p->payload_length || (p->flags & KER_TCP_FIN)) &&
                p->sequence == r->peer_isn + 1U &&
                p->acknowledgment == r->local_isn + 1U && (p->flags & KER_TCP_ACK)) {
                error = emit(t, r, KER_TCP_RST | KER_TCP_ACK);
                if (!error) {
                    r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP;
                    discard_stream(r);
                    error = -EOPNOTSUPP;
                }
            }
            /* Duplicate SYN does not reset the deadline or amplify TX; poll
             * retransmits at the configured interval with the same ISN. */
            goto done;
        }
        bool ack_valid = send_enabled(t) ? valid_send_ack(r, p->acknowledgment) :
            p->acknowledgment == r->local_isn + 1U;
        if (stream_enabled(t) && (p->flags & KER_TCP_FIN) &&
            at_contiguous_edge(p, r->receive_next) && ack_valid && (p->flags & KER_TCP_ACK)) {
            error = emit(t, r, KER_TCP_RST | KER_TCP_ACK);
            if (!error) { r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP;
                discard_stream(r); discard_send(r); error = -EOPNOTSUPP; }
        } else if (stream_enabled(t) && (p->flags == KER_TCP_ACK ||
                p->flags == (KER_TCP_ACK | KER_TCP_PSH)) && ack_valid && p->payload_length) {
            if (send_ack_eligible(t, r, p)) acknowledge_send(t, r, p);
            error = receive_data(t, r, p);
        } else if (stream_enabled(t) && p->payload_length &&
            at_contiguous_edge(p, r->receive_next) &&
            ack_valid && (p->flags & KER_TCP_ACK)) {
            error = emit(t, r, KER_TCP_RST | KER_TCP_ACK);
            if (!error) { r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP;
                discard_stream(r); discard_send(r); error = -EOPNOTSUPP; }
        } else if ((p->payload_length || (p->flags & KER_TCP_FIN)) &&
            p->sequence == expected_peer_sequence &&
            ack_valid && (p->flags & KER_TCP_ACK)) {
            error = emit(t, r, KER_TCP_RST | KER_TCP_ACK);
            if (!error) { r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP;
                discard_stream(r); discard_send(r); error = -EOPNOTSUPP; }
        }
        if (!error && send_enabled(t) && p->flags == KER_TCP_ACK &&
            !p->payload_length && send_ack_eligible(t, r, p))
            acknowledge_send(t, r, p);
        goto done;
    }
    if (p->payload_length || (p->flags & (KER_TCP_AE | KER_TCP_URG))) {
        error = -EOPNOTSUPP; goto done;
    }
    if (!syn_only(p)) goto done;
    if (!empty) { ++t->dropped_full; goto done; }
    if (t->next_generation == UINT64_MAX || t->now_ms > UINT64_MAX - t->config.timeout_ms) {
        error = -EOVERFLOW; goto done;
    }
    struct ker_tcp_request candidate = {.peer_port = p->source_port,
        .peer_isn = p->sequence, .state = KER_TCP_REQUEST_SYN,
        .receive_next = (stream_enabled(t) || send_enabled(t)) ? p->sequence + 1U : 0,
        .generation = t->next_generation + 1,
        .retry_ms = t->now_ms + t->config.retry_ms,
        .deadline_ms = t->now_ms + t->config.timeout_ms};
    error = ker_tcp_syn_mss(d->context, skb, t->config.mss, &candidate.send_mss);
    if (error) goto done;
    if (!candidate.send_mss) candidate.send_mss = t->config.mss < 536 ? t->config.mss : 536;
    error = t->config.next_isn(t->config.arg, p->source_port, &candidate.local_isn);
    if (error > 0) error = -EPROTO;
    if (error) goto done;
    if (send_enabled(t)) {
        candidate.send_unacknowledged = candidate.send_next = candidate.local_isn + 1U;
    }
    error = emit(t, &candidate, KER_TCP_SYN | KER_TCP_ACK);
    if (!error) { *empty = candidate; t->next_generation = candidate.generation; ++t->count; }
done:
    t->busy = false;
    return error ? error : 1;
}

int ker_tcp_listener_init(struct ker_tcp_listener *t, struct ker_transport_receiver *r,
    struct ker_neighbor_table *n, __be32 peer, struct ker_tx_export *tx,
    struct ker_tcp_request *requests, size_t capacity,
    const struct ker_tcp_listener_config *cfg, uint64_t now)
{
    if (!t || !r || !n || !tx || !requests || !capacity || !cfg || !cfg->port ||
        !cfg->window || !cfg->mss || !cfg->ttl || !cfg->next_isn ||
        !cfg->retry_ms || cfg->timeout_ms < cfg->retry_ms ||
        now > UINT64_MAX - cfg->timeout_ms || !r->handler.registered ||
        !n->native || !n->address || !n->address->native || !tx->queue.context ||
        n->address->device != r->handler.device ||
        tx->queue.context != r->handler.device->context ||
        r->handler.device->native->mtu < 44 ||
        cfg->mss > r->handler.device->native->mtu - 40 ||
        !unicast(peer, n->address) ||
        !unicast(n->address->native->ifa_list->ifa_local, n->address)) return -EINVAL;
    if ((!cfg->receive_storage && (cfg->receive_storage_size || cfg->receive_capacity)) ||
        (cfg->receive_storage && (!cfg->receive_capacity ||
         capacity > SIZE_MAX / cfg->receive_capacity ||
         cfg->receive_storage_size < capacity * cfg->receive_capacity))) return -EINVAL;
    if ((!cfg->send_storage && (cfg->send_storage_size || cfg->send_capacity)) ||
        (cfg->send_storage && (!cfg->send_capacity || capacity > SIZE_MAX / cfg->send_capacity ||
         cfg->send_storage_size < capacity * cfg->send_capacity))) return -EINVAL;
    if (t->receiver || t->neighbors || t->tx || t->peer || t->requests ||
        t->capacity || t->count || t->busy || r->tcp_listener ||
        r->tcp_listener_receive) return -EALREADY;
    if (r->tcp_active && r->tcp_active->config.local_port == cfg->port) return -EADDRINUSE;
    if (rte_lcore_id() != n->lcore || rte_lcore_id() != r->handler.runtime->lcore) return -EXDEV;
    if (r->handler.runtime->dispatching || tx->polling || ker_local_irq_disabled()) return -EBUSY;
    if (capacity > SIZE_MAX / sizeof(*requests) || tx->listener_refs == UINT_MAX) return -EOVERFLOW;
    for (size_t i = 0; i < capacity; ++i) {
        const struct ker_tcp_request *q = &requests[i];
        if (q->generation || q->retry_ms || q->deadline_ms || q->local_isn ||
            q->peer_isn || q->peer_port || q->send_mss || q->state || q->error ||
            q->accepted || q->receive_next || q->receive_right || q->receive_bytes ||
            q->receive_head || q->ack_pending || q->send_unacknowledged || q->send_next || q->send_right ||
            q->peer_window || q->send_bytes || q->send_head ||
            q->send_retry_ms || q->send_deadline_ms || q->send_backoff_ms) return -EINVAL;
    }
    struct neighbour *entry = NULL;
    int error = ker_neighbor_lookup(n, peer, &entry);
    if (error) return error;
    unsigned char mac[ETH_ALEN];
    error = ker_neighbor_mac(n, entry, mac);
    if (error || (mac[0] & 1)) { ker_neighbor_release(n, entry); return error ? error : -EINVAL; }
    uint64_t generation = t->next_generation;
    *t = (struct ker_tcp_listener){.receiver = r, .neighbors = n, .peer = entry,
        .peer_ip = peer, .tx = tx, .requests = requests, .capacity = capacity,
        .config = *cfg, .now_ms = now, .next_generation = generation};
    ++tx->listener_refs;
    r->tcp_listener = t;
    r->tcp_listener_receive = receive_request;
    return 0;
}
int ker_tcp_listener_poll(struct ker_tcp_listener *t, uint64_t now, unsigned int budget)
{
    int error = owner(t);
    if (error) return error;
    if (now < t->now_ms) return -EINVAL;
    if (budget > INT_MAX) return -EOVERFLOW;
    t->now_ms = now;
    unsigned int inspected = 0;
    while (inspected < t->capacity && inspected < budget) {
        struct ker_tcp_request *r = &t->requests[t->cursor++];
        if (t->cursor == t->capacity) t->cursor = 0;
        ++inspected;
        if (!r->state) continue;
        if (r->state == KER_TCP_REQUEST_RESET && !t->tx->packets) { discard(t, r); continue; }
        if (r->state == KER_TCP_REQUEST_FAILED && !r->accepted && !t->tx->packets) {
            discard(t, r); continue;
        }
        if (r->state == KER_TCP_REQUEST_READY && r->send_bytes) {
            if (expire_send(r, now)) continue;
            if (now >= r->send_retry_ms) {
                t->last_tx_error = retransmit(t, r);
                r->send_backoff_ms = r->send_backoff_ms > UINT64_MAX / 2 ?
                    UINT64_MAX : r->send_backoff_ms * 2;
                r->send_retry_ms = now > UINT64_MAX - r->send_backoff_ms ?
                    UINT64_MAX : now + r->send_backoff_ms;
                continue;
            }
        }
        if (r->state == KER_TCP_REQUEST_READY && r->ack_pending) {
            t->last_tx_error = emit(t, r, KER_TCP_ACK);
            continue;
        }
        if (r->state != KER_TCP_REQUEST_SYN) continue;
        if (now >= r->deadline_ms) {
            r->state = KER_TCP_REQUEST_FAILED; r->error = -ETIMEDOUT; ++t->timed_out;
            if (!t->tx->packets) discard(t, r);
        } else if (now >= r->retry_ms) {
            t->last_tx_error = emit(t, r, KER_TCP_SYN | KER_TCP_ACK);
            /* Deadline remains absolute even when bounded TX admission fails. */
            r->retry_ms = now > UINT64_MAX - t->config.retry_ms ? UINT64_MAX : now + t->config.retry_ms;
        }
    }
    return (int)inspected;
}
static int get(struct ker_tcp_listener *t, struct ker_tcp_request_handle h,
                struct ker_tcp_request **out)
{
    int error = owner(t);
    if (error) return error;
    if (h.listener != t || h.slot >= t->capacity || !h.generation ||
        !t->requests[h.slot].state || t->requests[h.slot].generation != h.generation)
        return -ESTALE;
    *out = &t->requests[h.slot];
    return 0;
}
int ker_tcp_listener_accept(struct ker_tcp_listener *t, struct ker_tcp_request_handle *out)
{
    if (!out) return -EINVAL;
    int error = owner(t);
    if (error) return error;
    for (size_t i = 0; i < t->capacity; ++i)
        if (t->requests[i].state == KER_TCP_REQUEST_READY && !t->requests[i].accepted) {
            t->requests[i].accepted = true;
            *out = (struct ker_tcp_request_handle){t, i, t->requests[i].generation};
            return 1;
        }
    return 0;
}
int ker_tcp_listener_snapshot(struct ker_tcp_listener *t, struct ker_tcp_request_handle h,
                              struct ker_tcp_request *out)
{
    if (!out) return -EINVAL;
    struct ker_tcp_request *r;
    int error = get(t, h, &r);
    if (error) return error;
    *out = *r;
    return 0;
}
int ker_tcp_listener_reset(struct ker_tcp_listener *t, struct ker_tcp_request_handle h)
{
    struct ker_tcp_request *r;
    int error = get(t, h, &r);
    if (error) return error;
    if (r->state == KER_TCP_REQUEST_RESET) return -EALREADY;
    error = emit(t, r, KER_TCP_RST | KER_TCP_ACK);
    if (error) return error;
    discard_stream(r);
    discard_send(r);
    r->state = KER_TCP_REQUEST_RESET;
    return 0;
}
int ker_tcp_listener_read(struct ker_tcp_listener *t, struct ker_tcp_request_handle h,
                          void *destination, uint16_t capacity)
{
    if (!destination || !capacity) return -EINVAL;
    struct ker_tcp_request *r;
    int error = get(t, h, &r);
    if (error) return error;
    if (!stream_enabled(t)) return -EOPNOTSUPP;
    if (!r->accepted) return -EPERM;
    if (r->state != KER_TCP_REQUEST_READY) return r->error ? r->error : -ENOTCONN;
    if (!r->receive_bytes) return -EAGAIN;
    uint16_t count = capacity < r->receive_bytes ? capacity : r->receive_bytes;
    unsigned char *ring = receive_ring(t, r);
    uint16_t first = count < t->config.receive_capacity - r->receive_head ?
        count : t->config.receive_capacity - r->receive_head;
    memcpy(destination, ring + r->receive_head, first);
    memcpy((unsigned char *)destination + first, ring, count - first);
    r->receive_head = (r->receive_head + count) % t->config.receive_capacity;
    r->receive_bytes -= count;
    r->ack_pending = true;
    return count;
}
int ker_tcp_listener_write(struct ker_tcp_listener *t, struct ker_tcp_request_handle h,
                           const void *source, uint16_t length)
{
    if (!source || !length) return -EINVAL;
    struct ker_tcp_request *r;
    int error = get(t, h, &r);
    if (error) return error;
    if (!send_enabled(t)) return -EOPNOTSUPP;
    if (!r->accepted) return -EPERM;
    if (r->state != KER_TCP_REQUEST_READY) return r->error ? r->error : -ENOTCONN;
    if (r->send_bytes || !r->peer_window || !before(r->send_next, r->send_right)) return -EAGAIN;
    if (t->now_ms > UINT64_MAX - t->config.timeout_ms) return -EOVERFLOW;
    uint16_t count = length;
    if (count > r->send_mss) count = r->send_mss;
    if (count > t->config.send_capacity) count = t->config.send_capacity;
    if (count > r->peer_window) count = r->peer_window;
    uint32_t available = r->send_right - r->send_next;
    if (count > available) count = (uint16_t)available;
    if (!count) return -EAGAIN;
    error = emit_data(t, r, r->send_next, source, count);
    if (error) return error;
    memmove(send_ring(t, r), source, count);
    r->send_head = 0;
    r->send_bytes = count;
    r->send_next += count;
    r->send_backoff_ms = t->config.retry_ms;
    r->send_retry_ms = t->now_ms + t->config.retry_ms;
    r->send_deadline_ms = t->now_ms + t->config.timeout_ms;
    return count;
}
int ker_tcp_listener_cleanup(struct ker_tcp_listener *t)
{
    int error = owner(t);
    if (error) return error;
    if (t->count || t->tx->packets) return -EBUSY;
    t->receiver->tcp_listener = NULL;
    t->receiver->tcp_listener_receive = NULL;
    --t->tx->listener_refs;
    error = ker_neighbor_release(t->neighbors, t->peer);
    BUG_ON(error);
    uint64_t generation = t->next_generation;
    *t = (struct ker_tcp_listener){.next_generation = generation};
    return 0;
}
