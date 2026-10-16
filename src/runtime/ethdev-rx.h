#ifndef KER_RUNTIME_ETHDEV_RX_H
#define KER_RUNTIME_ETHDEV_RX_H
#include "runtime/receive.h"

enum ker_ethdev_rx_copy_profile {
    KER_ETHDEV_RX_COPY_UNIQUE = 0,
    KER_ETHDEV_RX_COPY_IMMUTABLE_BORROWED = 1,
    /* Copies valid native external attachments. Caller guarantees buf_len
     * bounds actual storage and keeps input immutable through consumption. */
    KER_ETHDEV_RX_COPY_IMMUTABLE_EXTERNAL = 2
};

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
    enum ker_ethdev_rx_copy_profile copy_profile;
};

/* Stable zero-initialized storage. Queue setup/start and port lifecycle remain
 * caller-owned. Only the configured RX queue is borrowed. */
int ker_ethdev_rx_init(struct ker_ethdev_rx *, struct ker_eth_device *,
    struct ker_receive_runtime *, uint16_t port_id, uint16_t queue_id,
    unsigned int headroom);
/* Explicit opt-in for a caller-retained immutable mbuf chain. In addition to
 * owning the received chain reference, the adapter relies on the caller to keep
 * its descriptors, topology and backing bytes immutable through consume/cancel.
 * Any independent backing references needed by the caller must remain live. */
int ker_ethdev_rx_init_profile(struct ker_ethdev_rx *, struct ker_eth_device *,
    struct ker_receive_runtime *, uint16_t port_id, uint16_t queue_id,
    unsigned int headroom, enum ker_ethdev_rx_copy_profile);
/* Worker RX callback. One packet is fetched per burst; allocation ENOMEM keeps
 * that owned chain pending and retries it before polling the queue again. */
int ker_ethdev_rx_poll(void *, unsigned int budget);
/* Transfer the pending mbuf chain to the caller; empty leaves *out unchanged. */
int ker_ethdev_rx_cancel(struct ker_ethdev_rx *, struct rte_mbuf **out);
/* Requires no pending chain and owner-lcore quiescence. */
int ker_ethdev_rx_cleanup(struct ker_ethdev_rx *);

#endif
