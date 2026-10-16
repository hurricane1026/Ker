#ifndef KER_RUNTIME_ETHDEV_TX_H
#define KER_RUNTIME_ETHDEV_TX_H
#include "runtime/tx-export.h"

/* Borrows a caller-configured, started ethdev TX queue. The caller must keep
 * the port and queue alive and quiesce them before cleanup. */
struct ker_ethdev_tx {
    struct ker_tx_export exporter;
    uint16_t port_id;
    uint16_t queue_id;
    uint16_t max_segments;
    unsigned int owner_lcore;
    int last_cleanup_error;
    bool polling;
    bool initialized;
};

/* Internal seam used to exercise deferred-release behavior independently of
 * PMDs such as net_ring that do not implement tx_done_cleanup. */
typedef int (*ker_ethdev_tx_reclaim_fn)(uint16_t, uint16_t, uint32_t, void *);

/* Initialize tx to {0}. Port/queue setup, start, stop and removal stay with
 * the caller. The port must enable TX multisegment support. */
int ker_ethdev_tx_init(struct ker_ethdev_tx *, struct ker_skb_context *,
    uint16_t port_id, uint16_t queue_id, unsigned int packet_limit,
    size_t byte_limit, unsigned int segment_payload_limit);
/* Worker TX callback; delegates to the bounded copied-packet exporter. */
int ker_ethdev_tx_poll(void *, unsigned int budget);
int ker_ethdev_tx_poll_with_reclaim(struct ker_ethdev_tx *, unsigned int budget,
    ker_ethdev_tx_reclaim_fn, void *);
int ker_ethdev_tx_cleanup(struct ker_ethdev_tx *);
#endif
