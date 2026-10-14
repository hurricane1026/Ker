#include "runtime/udp-endpoint.h"
#include "runtime/ipv4-address.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/irqflags.h>
#include <string.h>

#define UDP_HOOK_HANDLED 1
#define UDP_HOOK_DROP 2

static int owner_check(const struct ker_udp_endpoint_table *t) {
  if (!t || !t->receiver || !t->receiver->handler.runtime)
    return -EINVAL;
  if (rte_lcore_id() != t->receiver->handler.runtime->lcore)
    return -EXDEV;
  struct ker_neighbor_monitor *monitor = t->icmpv4->monitor;
  if (t->receiver->handler.runtime->dispatching || t->busy || t->icmpv4->busy ||
      monitor->busy || monitor->timer.running || monitor->timer.scoping ||
      monitor->timer.runtime->polling || monitor->resolution_tx->polling ||
      ker_local_irq_disabled())
    return -EBUSY;
  return 0;
}

static int eligible(struct ker_udp_endpoint_table *t, struct sk_buff *skb,
                    const struct ker_transport_message *m) {
  struct ker_eth_device *d = t->receiver->handler.device;
  if (!skb || !m || skb->pkt_type != PACKET_HOST ||
      m->ipv4.header_length != 20 || m->ipv4.header[8] == 0 ||
      (rte_be_to_cpu_16(m->ipv4.frag_off) & 0xbfffU) != 0)
    return 0;
  uint32_t source;
  memcpy(&source, m->ipv4.header + 12, sizeof(source));
  uint32_t source_host = ntohl(source);
  if ((source_host >> 24) == 0 || (source_host >> 24) == 127 ||
      (source_host >> 28) >= 14)
    return 0;
  struct in_ifaddr *ifa = t->icmpv4->monitor->table->address->native->ifa_list;
  if (ifa->ifa_prefixlen < 31) {
    uint32_t mask =
        ifa->ifa_prefixlen ? UINT32_MAX << (32 - ifa->ifa_prefixlen) : 0;
    if ((source_host & mask) == (ntohl(ifa->ifa_local) & mask) &&
        (source_host & ~mask) == ~mask)
      return 0;
  }
  __be32 dst;
  memcpy(&dst, m->ipv4.header + 16, sizeof(dst));
  uint32_t destination_host = ntohl(dst);
  if ((destination_host >> 24) == 0 || (destination_host >> 24) == 127 ||
      (destination_host >> 28) >= 14)
    return 0;
  if (ifa->ifa_prefixlen < 31) {
    uint32_t mask =
        ifa->ifa_prefixlen ? UINT32_MAX << (32 - ifa->ifa_prefixlen) : 0;
    if ((destination_host & mask) == (ntohl(ifa->ifa_local) & mask) &&
        (destination_host & ~mask) == ~mask)
      return 0;
  }
  if (ker_ipv4_address_is_local(t->icmpv4->monitor->table->address, dst) != 1)
    return 0;
  const unsigned char *eth = skb->head + skb->mac_header;
  if (memcmp(eth, d->native->dev_addr, ETH_ALEN) || (eth[ETH_ALEN] & 1U))
    return 0;
  return 1;
}

static int endpoint_receive(void *opaque, struct sk_buff *skb,
                            const struct ker_transport_message *m) {
  struct ker_udp_endpoint_table *t = opaque;
  if (!eligible(t, skb, m)) {
    t->receiver->validation_error = -EOPNOTSUPP;
    return -EOPNOTSUPP;
  }
  __be32 source;
  memcpy(&source, m->ipv4.header + 12, sizeof(source));
  for (size_t i = 0; i < t->capacity; ++i) {
    struct ker_udp_endpoint *e = &t->entries[i];
    if (!e->receive || e->port != m->packet.udp.destination_port)
      continue;
    if (e->connected &&
        (e->peer_address != source ||
         e->peer_port != m->packet.udp.source_port))
      continue;
    t->busy = true;
    int status = e->receive(m, e->arg);
    t->busy = false;
    if (status == NET_RX_SUCCESS)
      return UDP_HOOK_HANDLED;
    if (status == NET_RX_DROP)
      return UDP_HOOK_DROP;
    t->receiver->validation_error = -EPROTO;
    return -EPROTO;
  }
  /* Unbound ports and connected-peer mismatches share the existing ICMP
   * safety path. It applies source, configured-peer, rate and resource limits. */
  (void)ker_icmpv4_service_emit_error(t->icmpv4, skb, 3, 3, 0);
  return UDP_HOOK_DROP;
}

int ker_udp_endpoint_table_enable(struct ker_udp_endpoint_table *t,
                                  struct ker_transport_receiver *r,
                                  struct ker_icmpv4_service *icmp,
                                  struct ker_udp_endpoint *entries,
                                  size_t capacity) {
  if (!t || !r || !icmp || !entries || !capacity || !r->handler.registered ||
      r->udp_endpoint_table || !icmp->receiver || icmp->receiver != r ||
      r->icmpv4_service != icmp || !icmp->monitor ||
      !icmp->monitor->timer.runtime || !icmp->monitor->resolution_tx)
    return -EINVAL;
  if (t->receiver || t->icmpv4 || t->entries || t->capacity || t->count ||
      t->io_refs || t->busy)
    return -EALREADY;
  struct ker_neighbor_monitor *monitor = icmp->monitor;
  if (r->handler.runtime->dispatching || icmp->busy || monitor->busy ||
      monitor->timer.running || monitor->timer.scoping ||
      monitor->timer.runtime->polling || monitor->resolution_tx->polling ||
      ker_local_irq_disabled())
    return -EBUSY;
  if (rte_lcore_id() != r->handler.runtime->lcore)
    return -EXDEV;
  for (size_t i = 0; i < capacity; ++i)
    if (entries[i].receive || entries[i].port || entries[i].arg ||
        entries[i].peer_address || entries[i].peer_port ||
        entries[i].generation || entries[i].incarnation ||
        entries[i].connected)
      return -EINVAL;
  uint64_t next_generation = t->next_generation;
  *t = (struct ker_udp_endpoint_table){
      .receiver = r, .icmpv4 = icmp, .entries = entries, .capacity = capacity,
      .next_generation = next_generation};
  r->udp_endpoint_table = t;
  r->udp_endpoint_receive = endpoint_receive;
  return 0;
}
int ker_udp_endpoint_table_disable(struct ker_udp_endpoint_table *t) {
  int error = owner_check(t);
  if (error)
    return error;
  if (t->count || t->io_refs)
    return -EBUSY;
  struct ker_transport_receiver *r = t->receiver;
  if (r->udp_endpoint_table != t)
    return -EINVAL;
  r->udp_endpoint_table = NULL;
  r->udp_endpoint_receive = NULL;
  uint64_t next_generation = t->next_generation;
  *t = (struct ker_udp_endpoint_table){.next_generation = next_generation};
  return 0;
}
static int bind_common(struct ker_udp_endpoint_table *t, __be16 port,
                       ker_udp_endpoint_receive_fn receive, void *arg,
                       struct ker_udp_endpoint_handle *handle) {
  if (!port || !receive)
    return -EINVAL;
  int error = owner_check(t);
  if (error)
    return error;
  for (size_t i = 0; i < t->capacity; ++i)
    if (t->entries[i].receive && t->entries[i].port == port)
      return -EADDRINUSE;
  for (size_t i = 0; i < t->capacity; ++i)
    if (!t->entries[i].receive) {
      if (t->next_generation == UINT64_MAX)
        return -EOVERFLOW;
      uint64_t generation = t->next_generation + 1;
      t->entries[i] = (struct ker_udp_endpoint){
          .port = port, .receive = receive, .arg = arg,
          .generation = generation, .incarnation = generation};
      t->next_generation = generation;
      ++t->count;
      if (handle)
        *handle = (struct ker_udp_endpoint_handle){t, i, generation};
      return 0;
    }
  return -ENOSPC;
}
int ker_udp_endpoint_bind_ex(struct ker_udp_endpoint_table *t, __be16 port,
                             ker_udp_endpoint_receive_fn receive, void *arg,
                             struct ker_udp_endpoint_handle *handle) {
  if (!handle)
    return -EINVAL;
  return bind_common(t, port, receive, arg, handle);
}
int ker_udp_endpoint_bind(struct ker_udp_endpoint_table *t, __be16 port,
                          ker_udp_endpoint_receive_fn receive, void *arg) {
  return bind_common(t, port, receive, arg, NULL);
}
static int handle_entry(struct ker_udp_endpoint_table *t,
                        struct ker_udp_endpoint_handle handle,
                        struct ker_udp_endpoint **out) {
  if (!t || !t->receiver || handle.table != t ||
      handle.slot >= t->capacity || !handle.generation)
    return -ESTALE;
  struct ker_udp_endpoint *entry = &t->entries[handle.slot];
  if (!entry->receive || entry->generation != handle.generation)
    return -ESTALE;
  *out = entry;
  return 0;
}
static int valid_peer(struct ker_udp_endpoint_table *t, __be32 peer) {
  uint32_t host = ntohl(peer);
  if ((host >> 24) == 0 || (host >> 24) == 127 || (host >> 28) >= 14)
    return 0;
  struct in_ifaddr *ifa = t->icmpv4->monitor->table->address->native->ifa_list;
  if (ifa->ifa_prefixlen < 31) {
    uint32_t mask = ifa->ifa_prefixlen
                        ? UINT32_MAX << (32 - ifa->ifa_prefixlen)
                        : 0;
    if ((host & mask) == (ntohl(ifa->ifa_local) & mask) &&
        (host & ~mask) == ~mask)
      return 0;
  }
  return 1;
}
int ker_udp_endpoint_connect(struct ker_udp_endpoint_table *t,
                             struct ker_udp_endpoint_handle handle,
                             __be32 peer_address, __be16 peer_port) {
  if (!peer_port)
    return -EINVAL;
  if (t && !t->receiver)
    return -ESTALE;
  int error = owner_check(t);
  if (error)
    return error;
  struct ker_udp_endpoint *entry;
  error = handle_entry(t, handle, &entry);
  if (error)
    return error;
  if (!valid_peer(t, peer_address))
    return -EINVAL;
  if (t->next_generation == UINT64_MAX)
    return -EOVERFLOW;
  uint64_t incarnation = t->next_generation + 1;
  entry->peer_address = peer_address;
  entry->peer_port = peer_port;
  entry->connected = true;
  entry->incarnation = incarnation;
  t->next_generation = incarnation;
  return 0;
}
int ker_udp_endpoint_disconnect(struct ker_udp_endpoint_table *t,
                                struct ker_udp_endpoint_handle handle) {
  if (t && !t->receiver)
    return -ESTALE;
  int error = owner_check(t);
  if (error)
    return error;
  struct ker_udp_endpoint *entry;
  error = handle_entry(t, handle, &entry);
  if (error)
    return error;
  if (!entry->connected)
    return -ENOTCONN;
  if (t->next_generation == UINT64_MAX)
    return -EOVERFLOW;
  uint64_t incarnation = t->next_generation + 1;
  entry->peer_address = 0;
  entry->peer_port = 0;
  entry->connected = false;
  entry->incarnation = incarnation;
  t->next_generation = incarnation;
  return 0;
}
int ker_udp_endpoint_close(struct ker_udp_endpoint_table *t,
                           struct ker_udp_endpoint_handle handle) {
  if (t && !t->receiver)
    return -ESTALE;
  int error = owner_check(t);
  if (error)
    return error;
  struct ker_udp_endpoint *entry;
  error = handle_entry(t, handle, &entry);
  if (error)
    return error;
  *entry = (struct ker_udp_endpoint){0};
  --t->count;
  return 0;
}
int ker_udp_endpoint_snapshot(const struct ker_udp_endpoint_table *table,
                              struct ker_udp_endpoint_handle handle,
                              struct ker_udp_endpoint_snapshot *out) {
  if (!out)
    return -EINVAL;
  int error = owner_check(table);
  if (error)
    return error;
  struct ker_udp_endpoint *entry;
  error = handle_entry((struct ker_udp_endpoint_table *)table, handle, &entry);
  if (error)
    return error;
  struct ker_udp_endpoint_snapshot snapshot = {
      .local_port = entry->port,
      .peer_port = entry->peer_port,
      .peer_address = entry->peer_address,
      .incarnation = entry->incarnation,
      .connected = entry->connected};
  *out = snapshot;
  return 0;
}
int ker_udp_endpoint_unbind(struct ker_udp_endpoint_table *t, __be16 port) {
  if (!port)
    return -EINVAL;
  int error = owner_check(t);
  if (error)
    return error;
  for (size_t i = 0; i < t->capacity; ++i)
    if (t->entries[i].receive && t->entries[i].port == port) {
      struct ker_udp_endpoint_handle handle = {
          .table = t, .slot = i, .generation = t->entries[i].generation};
      return ker_udp_endpoint_close(t, handle);
    }
  return -ENOENT;
}
