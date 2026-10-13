#ifndef KER_RUNTIME_TX_RING_H
#define KER_RUNTIME_TX_RING_H
#include "runtime/tx-export.h"

struct rte_ring;

struct ker_tx_ring {
    struct rte_ring *ring;
    unsigned int owner_lcore;
    unsigned int consumers;
};

/* Initialize ring to zero. Capacity is exact and bounded to 1..65535. The
 * creating EAL lcore is its sole producer; its attached RX or flow-ring consumer may be a
 * different worker. Producer, consumer, and lifecycle operations require
 * external quiescence before detach/cleanup. Same-process SP/SC only; no
 * multiprocess guarantee. Duplicate/native DPDK errors are returned as
 * negative errno values without changing the adapter. */
int ker_tx_ring_init(struct ker_tx_ring *, const char *name,
    unsigned int capacity, int socket_id);
/* Compatible with ker_tx_export_sink_fn: zero transfers the whole chain;
 * a full ring returns -EAGAIN and accepts nothing. */
int ker_tx_ring_sink(struct rte_mbuf *, void *);
/* A single consumer may call take, sequentially, from any thread while no RX
 * adapter is attached. Returns one with ownership, zero when empty; all other
 * results preserve *result. */
int ker_tx_ring_take(struct ker_tx_ring *, struct rte_mbuf **result);
/* Owner-lcore only. Producer, consumer, and sink borrowers must be quiescent;
 * attached RX and flow-ring adapters block cleanup. Cleanup requires an empty ring and
 * never discards queued chains. */
int ker_tx_ring_cleanup(struct ker_tx_ring *);

#endif
