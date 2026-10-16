#ifndef KER_RUNTIME_ETHDEV_RX_H
#define KER_RUNTIME_ETHDEV_RX_H
#include "runtime/receive.h"

/* Borrows one caller-configured, started ethdev RX queue. The caller keeps the
 * device and queue alive, grants this adapter exclusive access to that queue,
 * and quiesces all accesses before adapter cleanup. */
struct ker_ethdev_rx {
    struct ker_eth_device *device;
    struct ker_receive_runtime *runtime;
    struct rte_mbuf *pending;
    uint16_t port_id;
    uint16_t queue_id;
    unsigned int owner_lcore;
    unsigned int headroom;
    unsigned int last_completed;
    unsigned int last_dropped;
    int last_error;
    bool polling;
    bool initialized;
};

/* Stable zero-initialized storage. Queue setup/start and port lifecycle remain
 * caller-owned. Only the configured RX queue is borrowed. */
int ker_ethdev_rx_init(struct ker_ethdev_rx *, struct ker_eth_device *,
    struct ker_receive_runtime *, uint16_t port_id, uint16_t queue_id,
    unsigned int headroom);
/* Worker RX callback. One packet is fetched per burst; allocation ENOMEM keeps
 * that owned chain pending and retries it before polling the queue again. */
int ker_ethdev_rx_poll(void *, unsigned int budget);
/* Transfer the pending mbuf chain to the caller; empty leaves *out unchanged. */
int ker_ethdev_rx_cancel(struct ker_ethdev_rx *, struct rte_mbuf **out);
/* Requires no pending chain and owner-lcore quiescence. */
int ker_ethdev_rx_cleanup(struct ker_ethdev_rx *);

#endif
