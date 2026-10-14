#include "runtime/tcp-listener.h"
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
static int emit(struct ker_tcp_listener *t, const struct ker_tcp_request *r, bool reset)
{
    unsigned char options[4] = {2, 4, (unsigned char)(t->config.mss >> 8),
                                (unsigned char)t->config.mss};
    struct sk_buff *skb = NULL;
    int error = ker_tcp_ipv4_create_neighbor(t->neighbors, t->peer_ip,
        t->config.port, r->peer_port,
        rte_cpu_to_be_32(r->local_isn + (reset ? 1U : 0U)),
        rte_cpu_to_be_32(r->peer_isn + 1U), rte_cpu_to_be_16(t->config.window),
        KER_TCP_ACK | (reset ? KER_TCP_RST : KER_TCP_SYN), t->config.ttl,
        reset ? NULL : options, reset ? 0 : sizeof(options), NULL, 0, &skb);
    if (error) return error;
    error = ker_tx_export_enqueue(t->tx, &skb);
    if (skb) BUG_ON(ker_skb_free(skb));
    return error;
}
static void discard(struct ker_tcp_listener *t, struct ker_tcp_request *r)
{
    *r = (struct ker_tcp_request){0};
    --t->count;
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
        if (r->state == KER_TCP_REQUEST_RESET || r->state == KER_TCP_REQUEST_FAILED)
            goto done;
        if ((p->flags & KER_TCP_RST) && p->sequence == r->peer_isn + 1U) {
            r->state = KER_TCP_REQUEST_FAILED;
            r->error = -ECONNRESET;
            goto done;
        }
        if (r->state == KER_TCP_REQUEST_SYN) {
            if (p->flags == KER_TCP_ACK && !p->payload_length &&
                p->sequence == r->peer_isn + 1U && p->acknowledgment == r->local_isn + 1U)
                r->state = KER_TCP_REQUEST_READY;
            else if ((p->payload_length || (p->flags & KER_TCP_FIN)) &&
                p->sequence == r->peer_isn + 1U &&
                p->acknowledgment == r->local_isn + 1U && (p->flags & KER_TCP_ACK)) {
                error = emit(t, r, true);
                if (!error) {
                    r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP;
                    error = -EOPNOTSUPP;
                }
            }
            /* Duplicate SYN does not reset the deadline or amplify TX; poll
             * retransmits at the configured interval with the same ISN. */
            goto done;
        }
        if (p->sequence == r->peer_isn + 1U &&
            p->acknowledgment == r->local_isn + 1U && (p->flags & KER_TCP_ACK) &&
            (p->payload_length || (p->flags & KER_TCP_FIN))) {
            error = emit(t, r, true);
            if (!error) { r->state = KER_TCP_REQUEST_RESET; r->error = -EOPNOTSUPP; error = -EOPNOTSUPP; }
        }
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
        .generation = t->next_generation + 1,
        .retry_ms = t->now_ms + t->config.retry_ms,
        .deadline_ms = t->now_ms + t->config.timeout_ms};
    error = ker_tcp_syn_mss(d->context, skb, t->config.mss, &candidate.send_mss);
    if (error) goto done;
    if (!candidate.send_mss) candidate.send_mss = t->config.mss < 536 ? t->config.mss : 536;
    error = t->config.next_isn(t->config.arg, p->source_port, &candidate.local_isn);
    if (error > 0) error = -EPROTO;
    if (error) goto done;
    error = emit(t, &candidate, false);
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
    if (t->receiver || t->neighbors || t->tx || t->peer || t->requests ||
        t->capacity || t->count || t->busy || r->tcp_listener ||
        r->tcp_listener_receive) return -EALREADY;
    if (rte_lcore_id() != n->lcore || rte_lcore_id() != r->handler.runtime->lcore) return -EXDEV;
    if (r->handler.runtime->dispatching || tx->polling || ker_local_irq_disabled()) return -EBUSY;
    if (capacity > SIZE_MAX / sizeof(*requests) || tx->listener_refs == UINT_MAX) return -EOVERFLOW;
    for (size_t i = 0; i < capacity; ++i) {
        const struct ker_tcp_request *q = &requests[i];
        if (q->generation || q->retry_ms || q->deadline_ms || q->local_isn ||
            q->peer_isn || q->peer_port || q->send_mss || q->state || q->error ||
            q->accepted) return -EINVAL;
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
        if (r->state != KER_TCP_REQUEST_SYN) continue;
        if (now >= r->deadline_ms) {
            r->state = KER_TCP_REQUEST_FAILED; r->error = -ETIMEDOUT; ++t->timed_out;
            if (!t->tx->packets) discard(t, r);
        } else if (now >= r->retry_ms) {
            t->last_tx_error = emit(t, r, false);
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
    error = emit(t, r, true);
    if (error) return error;
    r->state = KER_TCP_REQUEST_RESET;
    return 0;
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
