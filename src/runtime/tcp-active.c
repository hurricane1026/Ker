#include "runtime/tcp-active.h"
#include "runtime/tcp-listener.h"
#include "runtime/tcp-mss.h"
#include "runtime/tcp-neighbor-create.h"
#include <errno.h>
#include <limits.h>
#include <linux/irqflags.h>
#include <linux/if.h>
#include <string.h>

static int owner(struct ker_tcp_active *t)
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
static int emit(struct ker_tcp_active *t, uint8_t flags, uint32_t peer_isn)
{
    unsigned char options[4] = {2, 4, (unsigned char)(t->config.mss >> 8),
                                (unsigned char)t->config.mss};
    struct sk_buff *skb = NULL;
    uint16_t window = t->config.window - t->status.receive_bytes;
    uint32_t ack = t->peer_known ? t->status.receive_next : peer_isn + 1U;
    int error = ker_tcp_ipv4_create_neighbor(t->neighbors, t->peer_ip,
        t->config.local_port, t->config.peer_port,
        rte_cpu_to_be_32(t->status.local_isn + ((flags & KER_TCP_SYN) ? 0U : 1U)),
        flags & KER_TCP_ACK ? rte_cpu_to_be_32(ack) : 0,
        rte_cpu_to_be_16(window), flags, t->config.ttl,
        flags & KER_TCP_SYN ? options : NULL, flags & KER_TCP_SYN ? sizeof(options) : 0,
        NULL, 0, &skb);
    if (error) return error;
    error = ker_tx_export_enqueue(t->tx, &skb);
    if (skb) BUG_ON(ker_skb_free(skb));
    if (!error && t->peer_known && flags == KER_TCP_ACK) {
        t->receive_right = t->status.receive_next + window;
        t->status.ack_pending = false;
    }
    return error;
}
/* All live windows are <= 65535, strictly below the serial half-space. */
static bool before(uint32_t a, uint32_t b)
{ return (int32_t)(a - b) < 0; }
static void discard_receive(struct ker_tcp_active *t)
{
    t->status.receive_bytes = 0; t->receive_head = 0;
    t->status.ack_pending = false;
}
static int receive_data(struct ker_tcp_active *t, const struct ker_tcp_packet_view *p)
{
    uint32_t next = t->status.receive_next, seq = p->sequence;
    unsigned int skip = 0, length = p->payload_length;
    if (before(seq, next)) {
        skip = next - seq;
        if (skip >= length) length = 0;
        else { length -= skip; seq = next; }
    }
    /* A future gap is discarded; no out-of-order allocation. Limit to the
     * right edge actually admitted, even if the application freed space. */
    if (seq != next) length = 0;
    uint32_t available = t->receive_right - next;
    if (length > available) length = available;
    uint16_t capacity = t->config.receive_capacity;
    if (length > capacity - t->status.receive_bytes) return -EOVERFLOW;
    if (length) {
        unsigned int tail = (t->receive_head + t->status.receive_bytes) % capacity;
        unsigned int first = length < capacity - tail ? length : capacity - tail;
        memcpy(t->config.receive_buffer + tail, p->payload + skip, first);
        memcpy(t->config.receive_buffer, p->payload + skip + first, length - first);
        t->status.receive_bytes += length;
        t->status.receive_next += length;
    }
    t->status.ack_pending = true;
    t->status.last_tx_error = emit(t, KER_TCP_ACK, t->status.peer_isn);
    return t->status.last_tx_error;
}
static int receive_active(void *arg, struct sk_buff *skb,
                          const struct ker_transport_message *m)
{
    struct ker_tcp_active *t = arg;
    const struct ker_tcp_packet_view *p = &m->packet.tcp;
    if (p->destination_port != t->config.local_port) return 0;
    __be32 src, dst;
    memcpy(&src, m->ipv4.header + 12, 4); memcpy(&dst, m->ipv4.header + 16, 4);
    struct ker_eth_device *d = t->receiver->handler.device;
    const unsigned char *eth = skb->head + skb->mac_header;
    if (t->busy || src != t->peer_ip || p->source_port != t->config.peer_port ||
        skb->pkt_type != PACKET_HOST || m->ipv4.header_length != 20 || !m->ipv4.header[8] ||
        (rte_be_to_cpu_16(m->ipv4.frag_off) & 0xbfff) ||
        ker_ipv4_address_is_local(t->neighbors->address, dst) != 1 ||
        memcmp(eth, d->native->dev_addr, ETH_ALEN) || (eth[ETH_ALEN] & 1)) return -EOPNOTSUPP;
    if (t->status.state == KER_TCP_ACTIVE_SYN && t->now_ms >= t->deadline_ms) {
        t->status.state = KER_TCP_ACTIVE_FAILED; t->status.error = -ETIMEDOUT;
    }
    if (t->status.state == KER_TCP_ACTIVE_FAILED || t->status.state == KER_TCP_ACTIVE_RESET)
        return 1;
    t->busy = true;
    int error = 0;
    if (t->status.state == KER_TCP_ACTIVE_SYN) {
        /* An ACK-less reset cannot cancel an active open. */
        if ((p->flags & (KER_TCP_RST | KER_TCP_ACK)) == (KER_TCP_RST | KER_TCP_ACK) &&
            p->acknowledgment == t->status.local_isn + 1U) {
            t->status.state = KER_TCP_ACTIVE_FAILED; t->status.error = -ECONNREFUSED;
        } else if ((p->flags & (KER_TCP_SYN | KER_TCP_ACK)) == (KER_TCP_SYN | KER_TCP_ACK) &&
                   p->acknowledgment == t->status.local_isn + 1U) {
            uint16_t mss;
            error = ker_tcp_syn_mss(d->context, skb, t->config.mss, &mss);
            if (error) goto done;
            if (!mss) mss = t->config.mss < 536 ? t->config.mss : 536;
            bool unsupported = p->payload_length || p->flags != (KER_TCP_SYN | KER_TCP_ACK);
            error = emit(t, unsupported ? KER_TCP_RST | KER_TCP_ACK : KER_TCP_ACK,
                          p->sequence);
            t->status.last_tx_error = error;
            if (!error) {
                t->status.peer_isn = p->sequence; t->status.send_mss = mss;
                t->status.peer_window = p->window; t->peer_known = true;
                t->status.receive_next = p->sequence + 1U;
                t->receive_right = t->status.receive_next + t->config.window;
                t->status.state = unsupported ? KER_TCP_ACTIVE_RESET : KER_TCP_ACTIVE_READY;
                if (unsupported) { t->status.error = -EOPNOTSUPP; discard_receive(t); error = -EOPNOTSUPP; }
            }
        } else if (p->flags == KER_TCP_SYN) error = -EOPNOTSUPP; /* simultaneous open */
    } else {
        if ((p->flags & KER_TCP_RST) && p->sequence == t->status.receive_next) {
            t->status.state = KER_TCP_ACTIVE_FAILED; t->status.error = -ECONNRESET;
            discard_receive(t);
        } else if (p->flags == (KER_TCP_SYN | KER_TCP_ACK) && !p->payload_length &&
                   p->sequence == t->status.peer_isn &&
                   p->acknowledgment == t->status.local_isn + 1U) {
            /* Repair a lost final ACK without restarting the connection. */
            error = emit(t, KER_TCP_ACK, t->status.peer_isn);
            t->status.last_tx_error = error;
        } else if (t->config.receive_buffer && p->payload_length &&
                   (p->flags == KER_TCP_ACK || p->flags == (KER_TCP_ACK | KER_TCP_PSH)) &&
                   p->acknowledgment == t->status.local_isn + 1U) {
            error = receive_data(t, p);
        } else if ((p->payload_length || (p->flags & KER_TCP_FIN)) && (p->flags & KER_TCP_ACK) &&
                   (p->sequence == t->status.receive_next ||
                    (t->config.receive_buffer && (p->flags & KER_TCP_FIN) &&
                     before(p->sequence, t->status.receive_next) &&
                     !before(p->end_sequence, t->status.receive_next))) &&
                   p->acknowledgment == t->status.local_isn + 1U) {
            error = emit(t, KER_TCP_RST | KER_TCP_ACK, t->status.peer_isn);
            t->status.last_tx_error = error;
            if (!error) { t->status.state = KER_TCP_ACTIVE_RESET;
                t->status.error = -EOPNOTSUPP; discard_receive(t); error = -EOPNOTSUPP; }
        }
    }
done:
    t->busy = false;
    return error ? error : 1;
}
int ker_tcp_active_start(struct ker_tcp_active *t, struct ker_transport_receiver *r,
    struct ker_neighbor_table *n, __be32 peer, struct ker_tx_export *tx,
    const struct ker_tcp_active_config *cfg, uint64_t now)
{
    if (!t || !r || !n || !tx || !cfg || !cfg->local_port || !cfg->peer_port ||
        !cfg->window ||
        (!!cfg->receive_buffer != !!cfg->receive_capacity) ||
        (cfg->receive_buffer && cfg->receive_capacity != cfg->window) || !cfg->mss || !cfg->ttl || !cfg->next_isn || !cfg->retry_ms ||
        cfg->timeout_ms < cfg->retry_ms || now > UINT64_MAX - cfg->timeout_ms ||
        !r->handler.registered || !n->native || !n->address || !n->address->native ||
        !tx->queue.context || n->address->device != r->handler.device ||
        tx->queue.context != r->handler.device->context || r->handler.device->native->mtu < 44 ||
        cfg->mss > r->handler.device->native->mtu - 40 || !unicast(peer, n->address) ||
        !unicast(n->address->native->ifa_list->ifa_local, n->address)) return -EINVAL;
    if (t->receiver || t->peer || t->neighbors || t->tx || t->busy ||
        t->status.state || r->tcp_active || r->tcp_active_receive) return -EALREADY;
    if (r->tcp_listener && r->tcp_listener->config.port == cfg->local_port) return -EADDRINUSE;
    if (rte_lcore_id() != n->lcore || rte_lcore_id() != r->handler.runtime->lcore) return -EXDEV;
    if (r->handler.runtime->dispatching || tx->polling || ker_local_irq_disabled()) return -EBUSY;
    if (tx->active_refs == UINT_MAX) return -EOVERFLOW;
    struct neighbour *entry;
    int error = ker_neighbor_lookup(n, peer, &entry);
    if (error) return error;
    unsigned char mac[ETH_ALEN];
    error = ker_neighbor_mac(n, entry, mac);
    if (error || (mac[0] & 1)) { ker_neighbor_release(n, entry); return error ? error : -EINVAL; }
    *t = (struct ker_tcp_active){.receiver = r, .neighbors = n, .peer = entry,
        .tx = tx, .peer_ip = peer, .config = *cfg, .now_ms = now,
        .retry_ms = now + cfg->retry_ms, .deadline_ms = now + cfg->timeout_ms, .busy = true};
    ++tx->active_refs;
    r->tcp_active = t; r->tcp_active_receive = receive_active;
    error = t->config.next_isn(t->config.arg, cfg->peer_port, &t->status.local_isn);
    if (error > 0) error = -EPROTO;
    if (!error) error = emit(t, KER_TCP_SYN, 0);
    if (error) {
        r->tcp_active = NULL; r->tcp_active_receive = NULL; --tx->active_refs;
        BUG_ON(ker_neighbor_release(n, entry)); memset(t, 0, sizeof(*t)); return error;
    }
    t->status.state = KER_TCP_ACTIVE_SYN; t->busy = false;
    return 0;
}
int ker_tcp_active_poll(struct ker_tcp_active *t, uint64_t now)
{
    int error = owner(t); if (error) return error;
    if (now < t->now_ms) return -EINVAL;
    t->now_ms = now;
    if (t->status.state == KER_TCP_ACTIVE_READY && t->status.ack_pending) {
        t->status.last_tx_error = emit(t, KER_TCP_ACK, t->status.peer_isn);
        return 1;
    }
    if (t->status.state != KER_TCP_ACTIVE_SYN) return 0;
    if (now >= t->deadline_ms) {
        t->status.state = KER_TCP_ACTIVE_FAILED; t->status.error = -ETIMEDOUT; return 1;
    }
    if (now < t->retry_ms) return 0;
    t->status.last_tx_error = emit(t, KER_TCP_SYN, 0);
    t->retry_ms = now > UINT64_MAX - t->config.retry_ms ? UINT64_MAX : now + t->config.retry_ms;
    return 1;
}
int ker_tcp_active_snapshot(struct ker_tcp_active *t, struct ker_tcp_active_snapshot *out)
{
    if (!out) return -EINVAL;
    int error = owner(t); if (error) return error;
    *out = t->status; return 0;
}
int ker_tcp_active_reset(struct ker_tcp_active *t)
{
    int error = owner(t); if (error) return error;
    if (t->status.state == KER_TCP_ACTIVE_RESET) return -EALREADY;
    error = emit(t, KER_TCP_RST | (t->peer_known ? KER_TCP_ACK : 0), t->status.peer_isn);
    if (error) return error;
    t->status.state = KER_TCP_ACTIVE_RESET; discard_receive(t); return 0;
}
int ker_tcp_active_cleanup(struct ker_tcp_active *t)
{
    int error = owner(t); if (error) return error;
    if ((t->status.state != KER_TCP_ACTIVE_RESET && t->status.state != KER_TCP_ACTIVE_FAILED) ||
        t->tx->packets) return -EBUSY;
    t->receiver->tcp_active = NULL; t->receiver->tcp_active_receive = NULL;
    --t->tx->active_refs;
    BUG_ON(ker_neighbor_release(t->neighbors, t->peer));
    memset(t, 0, sizeof(*t)); return 0;
}

int ker_tcp_active_read(struct ker_tcp_active *t, void *destination, uint16_t capacity)
{
    int error = owner(t); if (error) return error;
    if (!t->config.receive_buffer) return -EOPNOTSUPP;
    if (!destination || !capacity) return -EINVAL;
    if (t->status.state != KER_TCP_ACTIVE_READY)
        return t->status.error ? t->status.error : -ENOTCONN;
    uint16_t length = t->status.receive_bytes < capacity ? t->status.receive_bytes : capacity;
    if (!length) return t->status.error ? t->status.error : -EAGAIN;
    uint16_t ring = t->config.receive_capacity;
    uint16_t first = length < ring - t->receive_head ? length : ring - t->receive_head;
    memcpy(destination, t->config.receive_buffer + t->receive_head, first);
    memcpy((unsigned char *)destination + first, t->config.receive_buffer, length - first);
    t->receive_head = (t->receive_head + length) % ring;
    t->status.receive_bytes -= length;
    t->status.ack_pending = true;
    return length;
}
