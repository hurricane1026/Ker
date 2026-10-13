#include "runtime/icmpv4-service.h"
#include "runtime/ethernet.h"
#include "runtime/icmpv4-create.h"
#include "runtime/ipv4-address.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/irqflags.h>
#include <string.h>

static void inc(uint64_t *v) {
  if (*v != UINT64_MAX)
    ++*v;
}
static __be32 word_ip(const unsigned char *p) {
  __be32 v;
  memcpy(&v, p, 4);
  return v;
}
static bool invalid_source(const struct ker_ipv4_address *address,
                           __be32 source) {
  uint32_t host = ntohl(source);
  if ((host >> 24) == 0 || (host >> 24) == 127 || (host >> 28) >= 0xe)
    return true;
  const struct in_ifaddr *ifa = address->native->ifa_list;
  if (ifa->ifa_prefixlen >= 31)
    return false;
  uint32_t mask =
      ifa->ifa_prefixlen ? UINT32_MAX << (32 - ifa->ifa_prefixlen) : 0;
  return (host & mask) == (ntohl(ifa->ifa_local) & mask) &&
         (host & ~mask) == ~mask;
}
static uint64_t now(struct ker_icmpv4_service *s) {
  bool was_busy = s->monitor->busy;
  s->monitor->busy = true;
  uint64_t t = s->config.monotonic_ms(s->config.clock_arg);
  s->monitor->busy = was_busy;
  return t;
}
static int utc_now(struct ker_icmpv4_service *s, uint32_t *t) {
  if (s->monitor->busy || s->monitor->timer.running ||
      s->monitor->timer.scoping || s->monitor->timer.runtime->polling ||
      s->monitor->resolution_tx->polling)
    return -EBUSY;
  bool was_busy = s->monitor->busy;
  s->monitor->busy = true;
  int e = s->config.utc_ms(s->config.clock_arg, t);
  s->monitor->busy = was_busy;
  return e > 0 ? -EINVAL : e;
}
static int token(struct ker_icmpv4_service *s) {
  if (s->monitor->busy || s->monitor->timer.running ||
      s->monitor->timer.scoping || s->monitor->timer.runtime->polling ||
      s->monitor->resolution_tx->polling)
    return -EBUSY;
  uint64_t t = now(s);
  if (!s->clock_started) {
    s->clock_started = true;
    s->last_refill_ms = t;
    s->last_now_ms = t;
  } else if (t < s->last_now_ms)
    return -ERANGE;
  else {
    s->last_now_ms = t;
    if (!s->config.refill_ms)
      goto consume;
    uint64_t elapsed = t - s->last_refill_ms;
    uint64_t add = elapsed / s->config.refill_ms;
    if (add) {
      s->tokens = add >= s->config.burst - s->tokens ? s->config.burst
                                                     : s->tokens + add;
      /* Carry fractional time only when not saturated. */
      s->last_refill_ms = s->tokens == s->config.burst
                              ? t
                              : s->last_refill_ms + add * s->config.refill_ms;
    }
  }
consume:
  if (!s->tokens)
    return -EAGAIN;
  --s->tokens;
  return 0;
}
static int monitor_valid(const struct ker_icmpv4_service *s) {
  if (!s || !s->receiver || !s->monitor || !s->monitor->timer.runtime ||
      !s->monitor->resolution_tx)
    return -EINVAL;
  const struct ker_neighbor_monitor *m = s->monitor;
  if (m->busy || m->timer.running || m->timer.scoping ||
      m->timer.runtime->polling || m->resolution_tx->polling ||
      ker_local_irq_disabled())
    return -EBUSY;
  return 0;
}
static int output(struct ker_icmpv4_service *s, struct sk_buff **slot) {
  int e = ker_neighbor_monitor_resolve_output(s->monitor, slot);
  if (*slot)
    BUG_ON(ker_skb_free(*slot));
  return e;
}

static int common_checks(struct ker_icmpv4_service *s, struct sk_buff *skb,
                         const struct ker_transport_message *m, __be32 *src,
                         __be32 *dst) {
  struct ker_eth_device *dev = s->receiver->handler.device;
  struct ker_ipv4_address *a = s->monitor->table->address;
  if (!skb || !m || skb->pkt_type != PACKET_HOST ||
      m->ipv4.header_length != 20 || !m->ipv4.header[8])
    return -ENOTSUP;
  if (m->ipv4.frag_off != 0 && m->ipv4.frag_off != htons(0x4000U))
    return -ENOTSUP;
  *src = word_ip(m->ipv4.header + 12);
  *dst = word_ip(m->ipv4.header + 16);
  if (invalid_source(a, *src))
    return -EHOSTUNREACH;
  int local = ker_ipv4_address_is_local(a, *dst);
  if (local <= 0)
    return local < 0 ? local : -EHOSTUNREACH;
  const unsigned char *eth = skb->head + skb->mac_header;
  if (memcmp(eth, dev->native->dev_addr, ETH_ALEN) || (eth[ETH_ALEN] & 1U))
    return -EHOSTUNREACH;
  return 0;
}

static int send_reply(struct ker_icmpv4_service *s, __be32 peer, uint8_t type,
                      const unsigned char rest[4], const unsigned char *payload,
                      unsigned int length) {
  struct ker_ipv4_address *a = s->monitor->table->address;
  __be32 monitored;
  memcpy(&monitored, s->monitor->entry->primary_key, 4);
  if (peer != monitored)
    return -EHOSTUNREACH;
  static const unsigned char zero_mac[ETH_ALEN] = {0};
  struct sk_buff *reply = NULL;
  int e = ker_icmpv4_ipv4_create(
      a->device->context, a->device->native->dev_addr, zero_mac,
      a->native->ifa_list->ifa_address, peer, type, 0, rest, s->config.ttl,
      payload, length, &reply);
  if (!e)
    e = output(s, &reply);
  return e;
}

static int send_probe_reply(struct ker_icmpv4_service *s, __be32 peer,
                            __be16 identifier, uint8_t sequence, uint8_t code,
                            uint8_t state) {
  struct ker_ipv4_address *a = s->monitor->table->address;
  __be32 monitored;
  memcpy(&monitored, s->monitor->entry->primary_key, 4);
  if (peer != monitored)
    return -EHOSTUNREACH;
  unsigned char rest[4];
  memcpy(rest, &identifier, 2);
  rest[2] = sequence;
  rest[3] = state;
  struct sk_buff *reply = NULL;
  int e = ker_icmpv4_ipv4_create(
      a->device->context, a->device->native->dev_addr,
      (const unsigned char[6]){0}, a->native->ifa_list->ifa_local, peer, 43,
      code, rest, 255, NULL, 0, &reply);
  if (!e)
    e = output(s, &reply);
  return e;
}

static int probe_receive(struct ker_icmpv4_service *s, struct sk_buff *skb,
                         const struct ker_transport_message *m) {
  if (!s->config.probe_enabled)
    return 0;
  __be32 source, dest;
  int e = common_checks(s, skb, m, &source, &dest);
  if (e)
    return e;
  __be32 monitored;
  memcpy(&monitored, s->monitor->entry->primary_key, 4);
  if (source != monitored)
    return -EHOSTUNREACH;
  struct ker_icmpv4_extended_echo_view q;
  e = ker_icmpv4_extended_echo_view_init(&m->icmpv4, &q);
  if ((!e && !q.local) || (e && !(m->icmpv4.rest[3] & 1U)))
    return -ENOTSUP; /* no remote interface discovery backend */
  uint8_t code = 0, state = 0;
  struct net_device *nd = s->receiver->handler.device->native;
  struct in_ifaddr *ifa = s->monitor->table->address->native->ifa_list;
  if (e)
    code = 1;
  else {
    bool found = false, address_match = false;
    if (q.object_type == 1) {
      size_t n = strlen(nd->name);
      found =
          n == q.identifier_length && !memcmp(nd->name, q.identifier_data, n);
    } else if (q.object_type == 2) {
      uint32_t index;
      memcpy(&index, q.identifier_data, 4);
      found = nd->ifindex > 0 && ntohl(index) == (uint32_t)nd->ifindex;
    } else if (q.object_type == 3) {
      if (q.identifier_length == 4) {
        __be32 asked;
        memcpy(&asked, q.identifier_data, 4);
        found = true;
        address_match = asked == ifa->ifa_local;
      } else
        return -ENOTSUP;
    }
    if (!found) {
      code = 2;
    } else if (!address_match && q.object_type != 3)
      address_match = true; /* configured IPv4 address on this interface */
    if (q.object_type == 3 && !address_match)
      code = 2; /* The address does not identify this local interface. */
    if (code == 0 && (nd->flags & IFF_UP))
      state = 6;
  }
  e = token(s);
  if (e)
    return e;
  __be16 identifier;
  memcpy(&identifier, m->icmpv4.rest, 2);
  e = send_probe_reply(s, source, identifier, m->icmpv4.rest[2], code, state);
  if (e)
    return e;
  inc(&s->replies_submitted);
  return 1;
}

static int event_receive(struct ker_icmpv4_service *s, struct sk_buff *skb,
                         const struct ker_transport_message *m) {
  const struct ker_icmpv4_packet_view *v = &m->icmpv4;
  if (v->type != 3 && v->type != 5 && v->type != 11 && v->type != 12)
    return 0;
  struct ker_eth_device *dev = s->receiver->handler.device;
  struct ker_ipv4_address *local_address = s->monitor->table->address;
  __be32 outer_source = word_ip(m->ipv4.header + 12),
         outer_destination = word_ip(m->ipv4.header + 16);
  const unsigned char *eth = skb->head + skb->mac_header;
  if (skb->pkt_type != PACKET_HOST || m->ipv4.header_length != 20 ||
      (m->ipv4.frag_off != 0 && m->ipv4.frag_off != htons(0x4000U)) ||
      ker_ipv4_address_is_local(local_address, outer_destination) != 1 ||
      invalid_source(local_address, outer_source) || (eth[ETH_ALEN] & 1U) ||
      memcmp(eth, dev->native->dev_addr, ETH_ALEN)) {
    inc(&s->suppressed);
    return 1;
  }
  struct ker_icmpv4_control_event ev = {.type = v->type,
                                        .code = v->code,
                                        .source = word_ip(m->ipv4.header + 12),
                                        .destination =
                                            word_ip(m->ipv4.header + 16),
                                        .message = *v};
  if (v->type == 3 && v->code == 4) {
    uint16_t mtu;
    memcpy(&mtu, v->rest + 2, 2);
    ev.next_hop_mtu = ntohs(mtu);
  }
  if (v->type == 12)
    ev.pointer = v->rest[0];
  if (v->type == 5)
    ev.gateway = word_ip(v->rest);
  if (v->quoted_length) {
    int e = ker_icmpv4_quoted_ipv4_view_init(v->quoted_ipv4, v->quoted_length,
                                             &ev.quote);
    if (!e) {
      ev.has_quote = true;
      struct ker_ipv4_address *a = s->monitor->table->address;
      __be32 local, peer;
      memcpy(&local, ev.quote.header + 12, 4);
      memcpy(&peer, ev.quote.header + 16, 4);
      __be32 monitored;
      memcpy(&monitored, s->monitor->entry->primary_key, 4);
      /* ICMP errors may be sent by an intermediate gateway. Accept only
       * quotations for this host's locally originated monitored flow. */
      if (!ev.quote.flow_available ||
          ker_ipv4_address_is_local(a, local) != 1 || peer != monitored) {
        inc(&s->suppressed);
        return 1;
      }
    } else {
      inc(&s->malformed);
      return 1;
    }
  } else {
    inc(&s->malformed);
    return 1;
  }
  if (!s->config.event) {
    inc(&s->unsupported);
    return -EOPNOTSUPP;
  }
  s->config.event(&ev, s->config.event_arg);
  inc(&s->events_delivered);
  return 1;
}

static int service_receive_impl(void *opaque, struct sk_buff *skb,
                                const struct ker_transport_message *m) {
  struct ker_icmpv4_service *s = opaque;
  int e = monitor_valid(s);
  if (e)
    return e;
  inc(&s->received);
  e = event_receive(s, skb, m);
  if (e < 0)
    goto fail;
  if (e > 0)
    return e;
  uint8_t type = m->icmpv4.type;
  if (type == 42) {
    e = probe_receive(s, skb, m);
    if (e >= 0)
      return e;
    goto fail;
  }
  if ((type == 8 && s->config.echo_enabled) ||
      (type == 13 && s->config.timestamp_enabled)) {
    __be32 source, dest;
    e = common_checks(s, skb, m, &source, &dest);
    if (e)
      goto fail;
    __be32 monitored;
    memcpy(&monitored, s->monitor->entry->primary_key, 4);
    if (source != monitored) {
      e = -EHOSTUNREACH;
      goto fail;
    }
    if (type == 13 &&
        (m->icmpv4.payload_length != 12 || !s->config.utc_ms)) {
      e = -EINVAL;
      goto fail;
    }
    e = token(s);
    if (e)
      goto fail;
    if (type == 8) {
      e = send_reply(s, source, 0, m->icmpv4.rest, m->icmpv4.payload,
                     m->icmpv4.payload_length);
    } else {
      uint32_t receive, transmit;
      e = utc_now(s, &receive);
      if (e)
        goto fail;
      receive %= 86400000U;
      unsigned char payload[12];
      memcpy(payload, m->icmpv4.payload, 4);
      uint32_t net = htonl(receive);
      memcpy(payload + 4, &net, 4);
      e = utc_now(s, &transmit);
      if (e)
        goto fail;
      net = htonl(transmit % 86400000U);
      memcpy(payload + 8, &net, 4);
      e = send_reply(s, source, 14, m->icmpv4.rest, payload, sizeof(payload));
    }
    if (e)
      goto fail;
    inc(&s->replies_submitted);
    s->last_error = 0;
    return 1;
  }
  return 0;
fail:
  if (e == -ENOTSUP || e == -EHOSTUNREACH || e == -EINVAL || e == -ERANGE ||
      e == -EAGAIN)
    inc(&s->suppressed);
  inc(&s->dropped);
  s->last_error = e;
  return e;
}

static int service_receive(void *opaque, struct sk_buff *skb,
                           const struct ker_transport_message *m) {
  struct ker_icmpv4_service *s = opaque;
  if (!s || s->busy)
    return -EBUSY;
  s->busy = true;
  int e = service_receive_impl(opaque, skb, m);
  if (e > 0)
    s->last_error = 0;
  s->busy = false;
  return e;
}

int ker_icmpv4_service_enable(struct ker_icmpv4_service *s,
                              struct ker_transport_receiver *r,
                              struct ker_neighbor_monitor *m,
                              const struct ker_icmpv4_service_config *c) {
  if (!s || !r || !m || !c || !c->ttl || !c->burst || !c->refill_ms ||
      !c->monotonic_ms || (c->timestamp_enabled && !c->utc_ms))
    return -EINVAL;
  if (s->receiver || s->monitor)
    return -EALREADY;
  if (!r->handler.registered || r->echo_service || r->icmpv4_service ||
      !r->handler.runtime || !r->handler.device || !r->handler.runtime->context)
    return -EINVAL;
  if (!m->entry || !m->table || !m->table->address || !m->resolution_enabled ||
      !m->resolution_tx)
    return -EINVAL;
  struct ker_eth_device *d = r->handler.device;
  if (r->handler.runtime->dispatching)
    return -EBUSY;
  if (r->handler.runtime->context != d->context ||
      m->table->address->device != d ||
      m->resolution_tx->queue.context != d->context ||
      m->table->lcore != d->lcore || rte_lcore_id() != d->lcore)
    return -EXDEV;
  if (!m->timer.runtime || m->timer.runtime->polling || m->timer.running ||
      m->timer.scoping || m->resolution_tx->polling || m->busy ||
      ker_local_irq_disabled())
    return -EBUSY;
  if (m->echo_service_refs == UINT_MAX)
    return -EOVERFLOW;
  *s = (struct ker_icmpv4_service){
      .receiver = r, .monitor = m, .config = *c, .tokens = c->burst};
  r->icmpv4_service = s;
  r->icmpv4_service_receive = service_receive;
  ++m->echo_service_refs;
  return 0;
}
int ker_icmpv4_service_disable(struct ker_icmpv4_service *s) {
  int e = monitor_valid(s);
  if (e)
    return e;
  struct ker_transport_receiver *r = s->receiver;
  struct ker_neighbor_monitor *m = s->monitor;
  if (rte_lcore_id() != r->handler.runtime->lcore)
    return -EXDEV;
  if (r->icmpv4_service != s || !m->echo_service_refs)
    return -EINVAL;
  if (s->busy || r->handler.runtime->dispatching || m->busy ||
      m->timer.runtime->polling || m->timer.running || m->timer.scoping ||
      m->resolution_tx->polling)
    return -EBUSY;
  r->icmpv4_service = NULL;
  r->icmpv4_service_receive = NULL;
  --m->echo_service_refs;
  *s = (struct ker_icmpv4_service){0};
  return 0;
}

static int emit_error_internal(struct ker_icmpv4_service *s,
                               struct sk_buff *offending, uint8_t type,
                               uint8_t code, uint32_t information) {
  int e = monitor_valid(s);
  if (e)
    return e;
  if (!offending || (type != 3 && type != 11 && type != 12) ||
      (type == 3 && code > 15) || (type == 11 && code > 1) ||
      (type == 12 && code > 2))
    return -EINVAL;
  struct ker_skb_context *ctx = s->receiver->handler.runtime->context;
  struct ker_ipv4_packet_view ip;
  struct net_device *dev = s->receiver->handler.device->native;
  e = ker_ipv4_packet_view_init(ctx, offending, &ip);
  if (e) {
    inc(&s->malformed);
    return e;
  }
  uint16_t fragment = ntohs(ip.frag_off);
  const unsigned char *eth = offending->head + offending->mac_header;
  if (offending->pkt_type != PACKET_HOST || ip.header_length != 20 ||
      offending->dev != dev || memcmp(eth, dev->dev_addr, ETH_ALEN) ||
      (eth[ETH_ALEN] & 1U) || (fragment & 0x8000U) || (fragment & 0x1fffU)) {
    inc(&s->suppressed);
    return -EHOSTUNREACH;
  }
  __be32 source = word_ip(ip.header + 12), dest = word_ip(ip.header + 16);
  uint32_t hs = ntohl(source), hd = ntohl(dest);
  if ((hs >> 24) == 0 || (hs >> 24) == 127 || (hs >> 28) >= 0xe ||
      (hd >> 24) == 0 || (hd >> 24) == 127 || (hd >> 28) >= 0xe) {
    inc(&s->suppressed);
    return -EHOSTUNREACH;
  }
  struct ker_ipv4_address *a = s->monitor->table->address;
  struct in_ifaddr *ifa = a->native->ifa_list;
  uint32_t mask =
      ifa->ifa_prefixlen ? UINT32_MAX << (32 - ifa->ifa_prefixlen) : 0;
  uint32_t network = ntohl(ifa->ifa_local) & mask;
  if (ifa->ifa_prefixlen < 31 &&
      ((hd & mask) == network && (hd & ~mask) == ~mask)) {
    inc(&s->suppressed);
    return -EHOSTUNREACH;
  }
  if (ifa->ifa_prefixlen < 31 && (hs & mask) == network &&
      (hs & ~mask) == ~mask) {
    inc(&s->suppressed);
    return -EHOSTUNREACH;
  }
  if (dest != ifa->ifa_local) {
    inc(&s->suppressed);
    return -EHOSTUNREACH;
  }
  unsigned char quote[576];
  unsigned int n =
      ip.packet_length < sizeof(quote) ? ip.packet_length : sizeof(quote);
  memcpy(quote, ip.header, n);
  if (ip.header[9] == 1) {
    if (n < ip.header_length + 1) {
      inc(&s->suppressed);
      return -EMSGSIZE;
    }
    uint8_t inner = ip.header[ip.header_length];
    if (inner != 0 && inner != 8 && inner != 13 && inner != 14 && inner != 42 &&
        inner != 43) {
      inc(&s->suppressed);
      return -EHOSTUNREACH;
    }
  }
  unsigned char rest[4] = {0};
  if (type == 3 && code == 4) {
    if (information > UINT16_MAX || !information) {
      inc(&s->malformed);
      return -EINVAL;
    }
    uint16_t mtu = htons((uint16_t)information);
    memcpy(rest + 2, &mtu, 2);
  } else if (type == 12 && code == 0) {
    if (information > 255) {
      inc(&s->malformed);
      return -EINVAL;
    }
    rest[0] = (uint8_t)information;
  } else if (type == 12 && information) {
    inc(&s->malformed);
    return -EINVAL;
  } else if (type == 3 && code > 15) {
    inc(&s->malformed);
    return -EINVAL;
  } else if (type == 11 && code > 1) {
    inc(&s->malformed);
    return -EINVAL;
  }
  __be32 monitored;
  memcpy(&monitored, s->monitor->entry->primary_key, 4);
  if (source != monitored) {
    inc(&s->unsupported);
    return -EHOSTUNREACH;
  }
  uint32_t path_mtu = s->receiver->handler.device->native->mtu;
  if (s->monitor->output_mtu) {
    e = s->monitor->output_mtu(s->monitor->output_mtu_ctx, &path_mtu);
    if (e) {
      s->last_error = e;
      return e;
    }
  }
  if (!path_mtu) {
    inc(&s->malformed);
    return -EINVAL;
  }
  e = token(s);
  if (e) {
    inc(&s->suppressed);
    return e;
  }
  struct sk_buff *packet = NULL;
  e = ker_icmpv4_ipv4_error_create(
      ctx, a->device->native->dev_addr, (const unsigned char[6]){0}, dest,
      source, type, code, rest, s->config.ttl, quote, n,
      (uint16_t)(path_mtu > UINT16_MAX ? UINT16_MAX : path_mtu), &packet);
  if (!e)
    e = output(s, &packet);
  if (e) {
    inc(&s->dropped);
    s->last_error = e;
    return e;
  }
  inc(&s->errors_submitted);
  s->last_error = 0;
  return 0;
}

int ker_icmpv4_service_emit_error(struct ker_icmpv4_service *s,
                                  struct sk_buff *offending, uint8_t type,
                                  uint8_t code, uint32_t information) {
  int e = monitor_valid(s);
  if (e)
    return e;
  if (s->receiver->icmpv4_service != s || !s->receiver->handler.registered)
    return -EINVAL;
  if (rte_lcore_id() != s->receiver->handler.runtime->lcore)
    return -EXDEV;
  if (s->monitor->busy || s->monitor->timer.running ||
      s->monitor->timer.scoping || s->monitor->timer.runtime->polling ||
      s->monitor->resolution_tx->polling)
    return -EBUSY;
  if (s->busy)
    return -EBUSY;
  s->busy = true;
  e = emit_error_internal(s, offending, type, code, information);
  s->busy = false;
  return e;
}
