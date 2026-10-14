#ifndef KER_RUNTIME_UDP_IO_H
#define KER_RUNTIME_UDP_IO_H
#include "runtime/udp-endpoint.h"
#include "runtime/udp-create.h"

struct ker_udp_io_peer {
  struct ker_neighbor_monitor *monitor;
};

struct ker_udp_io {
  struct ker_transport_receiver *receiver;
  struct ker_icmpv4_service *icmpv4;
  struct ker_udp_endpoint_table *endpoints;
  struct ker_udp_io_peer *peers;
  size_t peer_capacity, peer_count;
  unsigned int open_channels;
  unsigned int owner_lcore;
  uint8_t ttl;
  bool busy;
};

struct ker_udp_datagram_info {
  __be32 local_address, peer_address;
  __be16 local_port, peer_port;
  size_t original_length, copied_length;
  bool truncated;
};

struct ker_udp_channel_slot {
  struct ker_udp_datagram_info info;
  size_t length;
};

struct ker_udp_channel {
  struct ker_udp_io *io;
  struct ker_udp_endpoint_handle endpoint;
  struct ker_udp_channel_slot *slots;
  unsigned char *payloads;
  size_t capacity, max_datagram, byte_limit, bytes;
  size_t head, count;
  uint64_t dropped_full;
  bool busy, open;
};

enum ker_udp_recv_flags { KER_UDP_RECV_PEEK = 1U };

/* Storage is caller owned and remains stable until cleanup/close. The peer
 * registry bounds the exact IPv4 monitors available to sendto. The caller may
 * keep a channel open while changing its connected peer through its endpoint
 * handle. */
int ker_udp_io_init(struct ker_udp_io *, struct ker_transport_receiver *,
                    struct ker_icmpv4_service *, struct ker_udp_endpoint_table *,
                    struct ker_udp_io_peer *, size_t, uint8_t);
int ker_udp_io_cleanup(struct ker_udp_io *);
int ker_udp_io_register_peer(struct ker_udp_io *, struct ker_neighbor_monitor *);
int ker_udp_io_unregister_peer(struct ker_udp_io *, struct ker_neighbor_monitor *);

/* payloads is capacity consecutive slots of max_datagram bytes. Each received
 * payload is copied before the borrowed transport callback returns. A payload
 * larger than max_datagram is admitted as its prefix and marked truncated; a
 * full packet or byte budget drops the datagram and increments dropped_full. */
int ker_udp_channel_open(struct ker_udp_channel *, struct ker_udp_io *, __be16,
                         struct ker_udp_channel_slot *, unsigned char *payloads,
                         size_t capacity, size_t max_datagram, size_t byte_limit,
                         struct ker_udp_endpoint_handle *);
int ker_udp_channel_close(struct ker_udp_channel *);
/* Returns 1 for a datagram, 0 when empty, or a negative errno. A short buffer
 * consumes one datagram and reports its original/copied lengths. PEEK retains it. */
int ker_udp_channel_recv(struct ker_udp_channel *, void *, size_t, unsigned int,
                         struct ker_udp_datagram_info *);
/* Payload is borrowed only for the call and copied into a newly constructed
 * Ethernet/IPv4/UDP skb before neighbor output. Success means accepted by the
 * local bounded transmit path. send requires connect(); sendto uses the
 * explicit destination even on a connected channel. */
int ker_udp_send(struct ker_udp_channel *, const void *, size_t);
int ker_udp_sendto(struct ker_udp_channel *, __be32, __be16, const void *, size_t);

#endif
