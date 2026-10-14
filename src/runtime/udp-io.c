#include "runtime/udp-io.h"
#include "runtime/neighbor-timer.h"
#include "runtime/tx-export.h"
#include "runtime/ipv4-address.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/irqflags.h>
#include <linux/neighbour.h>
#include <rte_lcore.h>
#include <string.h>

static int io_check(const struct ker_udp_io *io) {
  if (!io || !io->receiver || !io->icmpv4 || !io->endpoints)
    return -EINVAL;
  if (rte_lcore_id() != io->owner_lcore)
    return -EXDEV;
  struct ker_receive_runtime *runtime = io->receiver->handler.runtime;
  struct ker_neighbor_monitor *control = io->icmpv4->monitor;
  if (!control || !control->timer.runtime || !control->resolution_tx ||
      !control->resolution_tx->queue.context)
    return -EINVAL;
  if (!runtime || runtime->dispatching || io->busy || io->endpoints->busy ||
      io->icmpv4->busy || control->busy || control->timer.running ||
      control->timer.scoping || control->timer.runtime->polling ||
      control->resolution_tx->polling || ker_local_irq_disabled())
    return -EBUSY;
  if (io->receiver->udp_endpoint_table != io->endpoints ||
      io->endpoints->receiver != io->receiver ||
      io->endpoints->icmpv4 != io->icmpv4)
    return -ESTALE;
  return 0;
}

static size_t ring_index(const struct ker_udp_channel *channel, size_t offset) {
  size_t remaining = channel->capacity - channel->head;
  return offset >= remaining ? offset - remaining : channel->head + offset;
}

static int valid_peer_address(struct ker_neighbor_monitor *monitor,
                              __be32 address) {
  uint32_t host = ntohl(address);
  if ((host >> 24) == 0 || (host >> 24) == 127 || (host >> 28) >= 14)
    return 0;
  struct in_ifaddr *ifa = monitor->table->address->native->ifa_list;
  if (!ifa)
    return 0;
  if (ifa->ifa_prefixlen < 31) {
    uint32_t mask = ifa->ifa_prefixlen
                        ? UINT32_MAX << (32U - ifa->ifa_prefixlen)
                        : 0;
    if ((host & mask) == (ntohl(ifa->ifa_local) & mask) &&
        (host & ~mask) == ~mask)
      return 0;
  }
  return 1;
}

static int channel_check(struct ker_udp_channel *channel) {
  if (!channel || !channel->open || !channel->io)
    return -EINVAL;
  int error = io_check(channel->io);
  if (error)
    return error;
  if (channel->busy)
    return -EBUSY;
  return 0;
}

static __be32 ipv4_address(const struct ker_transport_message *message,
                           size_t offset) {
  __be32 address;
  memcpy(&address, message->ipv4.header + offset, sizeof(address));
  return address;
}

static int channel_receive(const struct ker_transport_message *message,
                           void *opaque) {
  struct ker_udp_channel *channel = opaque;
  if (!channel || !channel->open || !channel->io || !message ||
      message->protocol != KER_TRANSPORT_UDP)
    return NET_RX_DROP;
  channel->busy = true;
  if (channel->count == channel->capacity) {
    ++channel->dropped_full;
    channel->busy = false;
    return NET_RX_DROP;
  }
  size_t copied = message->packet.udp.payload_length;
  if (copied > channel->max_datagram)
    copied = channel->max_datagram;
  if (copied > channel->byte_limit - channel->bytes) {
    ++channel->dropped_full;
    channel->busy = false;
    return NET_RX_DROP;
  }
  size_t index = ring_index(channel, channel->count);
  struct ker_udp_channel_slot slot = {0};
  slot.info.local_address = ipv4_address(message, 16);
  slot.info.peer_address = ipv4_address(message, 12);
  slot.info.local_port = message->packet.udp.destination_port;
  slot.info.peer_port = message->packet.udp.source_port;
  slot.info.original_length = message->packet.udp.payload_length;
  slot.info.copied_length = copied;
  slot.info.truncated = copied != slot.info.original_length;
  slot.length = copied;
  if (copied)
    memcpy(channel->payloads + index * channel->max_datagram,
           message->packet.udp.payload, copied);
  channel->slots[index] = slot;
  ++channel->count;
  channel->bytes += copied;
  channel->busy = false;
  return NET_RX_SUCCESS;
}

int ker_udp_io_init(struct ker_udp_io *io,
                    struct ker_transport_receiver *receiver,
                    struct ker_icmpv4_service *icmpv4,
                    struct ker_udp_endpoint_table *endpoints,
                    struct ker_udp_io_peer *peers, size_t peer_capacity,
                    uint8_t ttl) {
  if (!io || !receiver || !icmpv4 || !endpoints || !peers ||
      !peer_capacity || !ttl || peer_capacity > SIZE_MAX / sizeof(*peers))
    return -EINVAL;
  if (io->receiver || io->icmpv4 || io->endpoints || io->peers ||
      io->peer_capacity || io->peer_count || io->open_channels || io->owner_lcore ||
      io->ttl || io->busy)
    return -EALREADY;
  if (!receiver->handler.registered || !receiver->handler.runtime ||
      !receiver->handler.device || !icmpv4->receiver ||
      icmpv4->receiver != receiver || receiver->icmpv4_service != icmpv4 ||
      receiver->udp_endpoint_table != endpoints ||
      endpoints->receiver != receiver || endpoints->icmpv4 != icmpv4 ||
      !endpoints->entries || !endpoints->capacity)
    return -EINVAL;
  if (rte_lcore_id() != receiver->handler.runtime->lcore)
    return -EXDEV;
  if (receiver->handler.runtime->dispatching || endpoints->busy ||
      icmpv4->busy || ker_local_irq_disabled())
    return -EBUSY;
  if (endpoints->io_refs == UINT_MAX)
    return -EOVERFLOW;
  for (size_t i = 0; i < peer_capacity; ++i)
    if (peers[i].monitor)
      return -EINVAL;
  struct ker_udp_io candidate = {
      .receiver = receiver,
      .icmpv4 = icmpv4,
      .endpoints = endpoints,
      .peers = peers,
      .peer_capacity = peer_capacity,
      .owner_lcore = receiver->handler.runtime->lcore,
      .ttl = ttl};
  *io = candidate;
  ++endpoints->io_refs;
  return 0;
}

int ker_udp_io_cleanup(struct ker_udp_io *io) {
  int error = io_check(io);
  if (error)
    return error;
  if (io->peer_count || io->open_channels)
    return -EBUSY;
  if (!io->endpoints->io_refs)
    return -EINVAL;
  --io->endpoints->io_refs;
  *io = (struct ker_udp_io){0};
  return 0;
}

int ker_udp_io_register_peer(struct ker_udp_io *io,
                             struct ker_neighbor_monitor *monitor) {
  int error = io_check(io);
  if (error)
    return error;
  if (!monitor || !monitor->entry || !monitor->table ||
      !monitor->resolution_enabled || !monitor->resolution_tx ||
      !monitor->timer.runtime || !monitor->resolution_tx->queue.context ||
      !monitor->table->address || !monitor->table->address->native ||
      !monitor->table->address->device)
    return -EINVAL;
  if (monitor->table->lcore != io->owner_lcore ||
      monitor->table->address->device != io->receiver->handler.device ||
      monitor->resolution_tx->queue.context !=
          io->receiver->handler.device->context)
    return -EXDEV;
  if (monitor->busy || monitor->timer.running || monitor->timer.scoping ||
      monitor->timer.runtime->polling || monitor->resolution_tx->polling)
    return -EBUSY;
  __be32 address;
  memcpy(&address, monitor->entry->primary_key, sizeof(address));
  if (!valid_peer_address(monitor, address) ||
      ker_ipv4_address_is_local(monitor->table->address, address) != 0)
    return -EHOSTUNREACH;
  if (monitor->udp_adapter_refs == UINT_MAX)
    return -EOVERFLOW;
  for (size_t i = 0; i < io->peer_capacity; ++i) {
    struct ker_neighbor_monitor *existing = io->peers[i].monitor;
    if (!existing)
      continue;
    if (existing == monitor)
      return -EALREADY;
    if (existing->entry && !memcmp(existing->entry->primary_key, &address,
                                    sizeof(address)))
      return -EADDRINUSE;
  }
  for (size_t i = 0; i < io->peer_capacity; ++i)
    if (!io->peers[i].monitor) {
      io->peers[i].monitor = monitor;
      ++io->peer_count;
      ++monitor->udp_adapter_refs;
      return 0;
    }
  return -ENOSPC;
}

int ker_udp_io_unregister_peer(struct ker_udp_io *io,
                               struct ker_neighbor_monitor *monitor) {
  int error = io_check(io);
  if (error)
    return error;
  if (!monitor)
    return -EINVAL;
  for (size_t i = 0; i < io->peer_capacity; ++i)
    if (io->peers[i].monitor == monitor) {
      if (monitor->busy || !monitor->timer.runtime ||
          monitor->timer.running || monitor->timer.scoping ||
          monitor->timer.runtime->polling ||
          (monitor->resolution_tx && monitor->resolution_tx->polling))
        return -EBUSY;
      if (!monitor->udp_adapter_refs)
        return -EINVAL;
      io->peers[i].monitor = NULL;
      --io->peer_count;
      --monitor->udp_adapter_refs;
      return 0;
    }
  return -ENOENT;
}

int ker_udp_channel_open(struct ker_udp_channel *channel,
                         struct ker_udp_io *io, __be16 local_port,
                         struct ker_udp_channel_slot *slots,
                         unsigned char *payloads, size_t capacity,
                         size_t max_datagram, size_t byte_limit,
                         struct ker_udp_endpoint_handle *out_handle) {
  int error = io_check(io);
  if (error)
    return error;
  if (!channel || !local_port || !slots || !payloads || !capacity ||
      !max_datagram || !byte_limit || !out_handle)
    return -EINVAL;
  if (channel->open || channel->io || channel->slots)
    return -EALREADY;
  if (capacity > SIZE_MAX / max_datagram ||
      capacity > SIZE_MAX / sizeof(*slots))
    return -EOVERFLOW;
  size_t slab_size = capacity * max_datagram;
  if (max_datagram > UINT16_MAX - 28U || byte_limit > slab_size)
    return -EOVERFLOW;
  if (io->open_channels == UINT_MAX)
    return -EOVERFLOW;
  for (size_t i = 0; i < capacity; ++i) {
    const struct ker_udp_channel_slot *slot = &slots[i];
    if (slot->length || slot->info.local_address || slot->info.peer_address ||
        slot->info.local_port || slot->info.peer_port ||
        slot->info.original_length || slot->info.copied_length ||
        slot->info.truncated)
      return -EINVAL;
  }
  struct ker_udp_endpoint_handle handle = {0};
  error = ker_udp_endpoint_bind_ex(io->endpoints, local_port, channel_receive,
                                   channel, &handle);
  if (error)
    return error;
  *channel = (struct ker_udp_channel){
      .io = io,
      .endpoint = handle,
      .slots = slots,
      .payloads = payloads,
      .capacity = capacity,
      .max_datagram = max_datagram,
      .byte_limit = byte_limit,
      .open = true};
  ++io->open_channels;
  *out_handle = handle;
  return 0;
}

int ker_udp_channel_close(struct ker_udp_channel *channel) {
  if (!channel || !channel->open || !channel->io)
    return -EINVAL;
  int error = io_check(channel->io);
  if (error)
    return error;
  if (channel->busy)
    return -EBUSY;
  error = ker_udp_endpoint_close(channel->io->endpoints, channel->endpoint);
  if (error && error != -ESTALE && error != -ENOENT)
    return error;
  if (!channel->io->open_channels)
    return -EINVAL;
  --channel->io->open_channels;
  memset(channel->slots, 0, channel->capacity * sizeof(*channel->slots));
  *channel = (struct ker_udp_channel){0};
  return 0;
}

int ker_udp_channel_recv(struct ker_udp_channel *channel, void *buffer,
                         size_t buffer_length, unsigned int flags,
                         struct ker_udp_datagram_info *out_info) {
  int error = channel_check(channel);
  if (error)
    return error;
  if ((!buffer && buffer_length) || !out_info ||
      (flags & ~KER_UDP_RECV_PEEK))
    return -EINVAL;
  if (!channel->count)
    return 0;
  struct ker_udp_channel_slot *slot = &channel->slots[channel->head];
  size_t copied = slot->length < buffer_length ? slot->length : buffer_length;
  if (copied)
    memcpy(buffer, channel->payloads + channel->head * channel->max_datagram,
           copied);
  struct ker_udp_datagram_info info = slot->info;
  info.copied_length = copied;
  info.truncated = copied != info.original_length;
  *out_info = info;
  if (!(flags & KER_UDP_RECV_PEEK)) {
    channel->bytes -= slot->length;
    *slot = (struct ker_udp_channel_slot){0};
    channel->head = (channel->head + 1) % channel->capacity;
    --channel->count;
  }
  return 1;
}

static int find_peer(struct ker_udp_io *io, __be32 address,
                     struct ker_neighbor_monitor **out) {
  for (size_t i = 0; i < io->peer_capacity; ++i) {
    struct ker_neighbor_monitor *monitor = io->peers[i].monitor;
    if (!monitor || !monitor->entry)
      continue;
    if (!memcmp(monitor->entry->primary_key, &address, sizeof(address))) {
      *out = monitor;
      return 0;
    }
  }
  return -EHOSTUNREACH;
}

static int channel_send(struct ker_udp_channel *channel, __be16 source_port,
                        __be32 address, __be16 port, const void *payload,
                        size_t length) {
  if (!port || (!payload && length))
    return -EINVAL;
  if (length > UINT16_MAX - 28U)
    return -EMSGSIZE;
  channel->busy = true;
  channel->io->busy = true;
  channel->io->endpoints->busy = true;
  int error;
  struct ker_neighbor_monitor *monitor = NULL;
  error = find_peer(channel->io, address, &monitor);
  if (error)
    goto out;
  if (monitor->busy || monitor->timer.runtime->polling ||
      monitor->resolution_tx->polling) {
    error = -EBUSY;
    goto out;
  }
  struct ker_neighbor_event snapshot;
  error = ker_neighbor_monitor_snapshot(monitor, &snapshot);
  if (error)
    goto out;
  struct ker_eth_device *device = channel->io->receiver->handler.device;
  struct ker_ipv4_address *local = monitor->table->address;
  struct in_ifaddr *ifa = local->native->ifa_list;
  if (!ifa) {
    error = -EINVAL;
    goto out;
  }
  uint32_t mtu = device->native->mtu;
  if (monitor->output_mtu) {
    uint32_t path_mtu = 0;
    error = monitor->output_mtu(monitor->output_mtu_ctx, &path_mtu);
    if (error) {
      if (error > 0)
        error = -EPROTO;
      goto out;
    }
    if (path_mtu < 68 || path_mtu > mtu) {
      error = -EINVAL;
      goto out;
    }
    mtu = path_mtu;
  } else if (monitor->output_mtu_ctx) {
    error = -EINVAL;
    goto out;
  }
  if (20U + 8U + length > mtu) {
    error = -EMSGSIZE;
    goto out;
  }
  struct ker_ipv4_header_fields fields = {
      .frag_off = htons(0x4000U)};
  struct sk_buff *skb = NULL;
  error = ker_udp_ipv4_create_fields(device->context,
      device->native->dev_addr, snapshot.mac, ifa->ifa_local, address,
      source_port, port,
      channel->io->ttl, &fields, NULL, 0, payload, (unsigned int)length, &skb);
  if (error)
    goto out;
  error = monitor->resolution_enabled
      ? ker_neighbor_monitor_resolve_output(monitor, &skb)
      : ker_neighbor_monitor_output(monitor, monitor->resolution_tx, &skb);
  if (skb) {
    int free_error = ker_skb_free(skb);
    if (!error)
      error = free_error ? free_error : -EPROTO;
  } else if (error > 0) {
    error = -EPROTO;
  }
out:
  if (error > 0)
    error = -EPROTO;
  channel->io->endpoints->busy = false;
  channel->io->busy = false;
  channel->busy = false;
  return error;
}

int ker_udp_send(struct ker_udp_channel *channel, const void *payload,
                 size_t length) {
  int error = channel_check(channel);
  if (error)
    return error;
  struct ker_udp_endpoint_snapshot snapshot;
  error = ker_udp_endpoint_snapshot(channel->io->endpoints,
                                    channel->endpoint, &snapshot);
  if (error)
    return error;
  if (!snapshot.connected)
    return -ENOTCONN;
  return channel_send(channel, snapshot.local_port, snapshot.peer_address,
                      snapshot.peer_port, payload, length);
}

int ker_udp_sendto(struct ker_udp_channel *channel, __be32 address,
                   __be16 port, const void *payload, size_t length) {
  int error = channel_check(channel);
  if (error)
    return error;
  struct ker_udp_endpoint_snapshot snapshot;
  error = ker_udp_endpoint_snapshot(channel->io->endpoints,
                                    channel->endpoint, &snapshot);
  if (error)
    return error;
  if (!address || !port)
    return -EINVAL;
  return channel_send(channel, snapshot.local_port, address, port, payload,
                      length);
}
