#ifndef KER_RUNTIME_TX_EXPORT_H
#define KER_RUNTIME_TX_EXPORT_H
#include "runtime/skb-queue.h"
#include "runtime/worker.h"

/* The sink accepts the copied mbuf only when it returns zero. Any nonzero
 * result means it accepted nothing; positive results are protocol errors. */
typedef int (*ker_tx_export_sink_fn)(struct rte_mbuf *, void *);
struct ker_tx_export {
    struct ker_skb_queue queue;
    struct sk_buff *pending;
    size_t pending_charge;
    size_t bytes;
    size_t byte_limit;
    unsigned int packets;
    unsigned int packet_limit;
    unsigned int last_completed;
    int last_error;
    bool polling;
    ker_tx_export_sink_fn sink;
    void *sink_arg;
};
/* Initialize tx to {0}. All operations are confined to the skb context's
 * owner worker. The sink owns only an accepted mbuf copy (return 0); every
 * other return accepts nothing. */
int ker_tx_export_init(struct ker_tx_export *, struct ker_skb_context *,
    unsigned int packet_limit, size_t byte_limit, ker_tx_export_sink_fn, void *);
int ker_tx_export_enqueue(struct ker_tx_export *, struct sk_buff **);
/* Worker TX callback. Accepted copies are irreversible; failures after a
 * successful prefix return that count and expose the error in last_error. */
int ker_tx_export_poll(void *, unsigned int budget);
/* Return pending first, otherwise the FIFO head. */
int ker_tx_export_cancel(struct ker_tx_export *, struct sk_buff **);
/* Empty-only; never silently discards owned packets. */
int ker_tx_export_cleanup(struct ker_tx_export *);
#endif
