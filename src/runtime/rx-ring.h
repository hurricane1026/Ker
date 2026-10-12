#ifndef KER_RUNTIME_RX_RING_H
#define KER_RUNTIME_RX_RING_H
#include "runtime/receive.h"
#include "runtime/tx-ring.h"

struct ker_rx_ring {
    struct ker_tx_ring *ring;
    struct ker_eth_device *device;
    struct ker_receive_runtime *runtime;
    struct rte_mbuf *pending;
    unsigned int owner_lcore;
    unsigned int headroom;
    unsigned int last_completed;
    unsigned int last_dropped;
    int last_error;
    bool polling;
};

/* Stable zero-initialized storage. Attaches as the sole consumer and pins the
 * ring, device, and runtime until cleanup. headroom must be even and fit the
 * packet backing data room. Manual ring_take is blocked while attached. */
int ker_rx_ring_init(struct ker_rx_ring *, struct ker_tx_ring *,
    struct ker_eth_device *, struct ker_receive_runtime *, unsigned int headroom);
/* Worker RX callback: positive count includes consumed drops; last_dropped
 * and last_error report outcomes. ENOMEM retains the pending chain for retry.
 * A zero budget returns zero without changing the prior diagnostics. */
int ker_rx_ring_poll(void *, unsigned int budget);
/* Return only the pending chain; an empty result leaves *out unchanged. */
int ker_rx_ring_cancel(struct ker_rx_ring *, struct rte_mbuf **out);
/* Requires no pending chain and owner-lcore quiescence; leaves ring contents. */
int ker_rx_ring_cleanup(struct ker_rx_ring *);

#endif
