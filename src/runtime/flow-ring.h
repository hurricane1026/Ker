#ifndef KER_RUNTIME_FLOW_RING_H
#define KER_RUNTIME_FLOW_RING_H
#include "runtime/flow.h"
#include "runtime/tx-ring.h"

struct ker_flow_ring {
    struct ker_tx_ring *ring;
    struct ker_flow_context *context;
    struct rte_mbuf *pending;
    uint64_t domain;
    enum ker_flow_direction direction;
    unsigned int owner_lcore;
    unsigned int last_completed;
    unsigned int last_dropped;
    int last_error;
    bool polling;
};

/* Caller-owned, stable, zero-initialized storage. Setup/cleanup require external
 * producer quiescence and must run outside worker polling. An attachment pins
 * the source ring and flow context; multiple sources may pin one context.
 * The source contains complete, valid, freeable mbuf chains. Attach as its sole
 * consumer on the flow context lcore. Domain and direction are fixed for the
 * lifetime of the adapter. Polling retries a pending chain before dequeuing
 * later chains; -ENOBUFS and -ESHUTDOWN preserve it. FIFO is source admission
 * order, not a global order across distinct source rings. At most the source
 * capacity plus one pending chain is held here, in addition to flow inboxes. */
int ker_flow_ring_init(struct ker_flow_ring *, struct ker_tx_ring *,
    struct ker_flow_context *, uint64_t domain, enum ker_flow_direction direction);
/* Worker RX/service callback. Completed count includes accepted submissions and
 * consumed packet drops. With progress return the count; otherwise return the
 * operational error. last_error also reports errors after partial progress.
 * Zero budget leaves diagnostics unchanged. The adapter allocates no buffers;
 * a synchronous local receive callback may allocate. */
int ker_flow_ring_poll(void *, unsigned int budget);
/* Return 1 and transfer only the pending chain; 0 leaves *out untouched.
 * Requires the owner lcore and no active delivery/poll of this adapter. */
int ker_flow_ring_cancel(struct ker_flow_ring *, struct rte_mbuf **out);
/* Empty-pending only. Unread source entries stay owned by the source ring. */
int ker_flow_ring_cleanup(struct ker_flow_ring *);
#endif
