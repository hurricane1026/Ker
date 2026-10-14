#ifndef KER_RUNTIME_UDP_FLOW_H
#define KER_RUNTIME_UDP_FLOW_H
#include "runtime/udp-io.h"
#include "runtime/flow.h"

struct ker_udp_flow_open_config {
    uint64_t domain;
    __be32 peer_address;
    __be16 peer_port;
    uint16_t first_port, last_port; /* inclusive, host byte order */
    struct ker_udp_channel_slot *slots;
    unsigned char *payloads;
    size_t capacity, max_datagram, byte_limit;
};

/* Open and connect an upstream channel on the first available local port whose
 * complete UDP tuple resolves to this context's worker, including special-map
 * overrides. The fabric must remain unchanged for the channel lifetime. The
 * same domain and ingress direction must be used for return traffic. No online
 * map update or migration is performed. Ownership is established only for the
 * configured peer tuple: do not retarget this channel with connect/sendto;
 * close it and open_owned again for a different peer. Generic endpoint/I/O
 * APIs do not retain the flow context or enforce this composition contract.
 * Both objects must use the same owner
 * and packet pool. EADDRNOTAVAIL means no tuple in the range maps to this owner;
 * EADDRINUSE means all owner-matching ports are bound. Other admission errors
 * are returned immediately. On failure, channel/output storage is unchanged
 * except that an attempted bind/connect can consume an endpoint generation.
 * Storage and channel-zeroing requirements are those of channel_open. */
int ker_udp_channel_open_owned(struct ker_udp_channel *, struct ker_udp_io *,
    const struct ker_flow_context *, const struct ker_udp_flow_open_config *,
    struct ker_udp_endpoint_handle *);
#endif
