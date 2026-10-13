#ifndef KER_RUNTIME_FLOW_RECEIVE_H
#define KER_RUNTIME_FLOW_RECEIVE_H
#include "runtime/flow.h"
#include "runtime/rx-ring.h"

struct ker_flow_receive_config {
    const char *name;
    unsigned int capacity;
    int socket_id;
    unsigned int headroom;
};

/* Caller-owned stable zero-initialized storage. The adapter owns a flow
 * context, local SP/SC packet queue, and RX copy/dispatch adapter. Initialize
 * and clean up with producers quiesced on the owner lcore. The worker, device,
 * runtime, and their packet pool must share one owner context. Configure
 * ker_flow_receive_poll as worker service work so pending ENOMEM is retried
 * even while worker RX admission is paused. Packets are queued after steering;
 * flow keys are not retained. */
struct ker_flow_receive {
    struct ker_flow_context context;
    struct ker_tx_ring queue;
    struct ker_rx_ring rx;
    uint64_t overflow_dropped;
    int last_enqueue_error;
    unsigned int owner_lcore;
    bool initialized;
};

int ker_flow_receive_init(struct ker_flow_receive *, struct ker_flow_fabric *,
    struct ker_worker *, unsigned int worker_id, struct ker_eth_device *,
    struct ker_receive_runtime *, const struct ker_flow_receive_config *);
/* Borrowed attached context for producers such as ker_flow_ring. Do not detach
 * it or operate on the adapter's embedded queue/RX adapter directly. */
struct ker_flow_context *ker_flow_receive_context(struct ker_flow_receive *);
/* Worker service callback. RX diagnostics are available through receive->rx.
 * The queue holds capacity chains plus one pending chain retained on ENOMEM;
 * a new chain that cannot enter the full queue is explicitly freed and counted. */
int ker_flow_receive_poll(void *, unsigned int budget);
/* Return 1 and transfer only the pending chain; empty leaves *out unchanged.
 * The queued FIFO is unaffected. Requires owner-lcore quiescence. */
int ker_flow_receive_cancel(struct ker_flow_receive *, struct rte_mbuf **out);
/* Requires empty inbox, queue, and pending state with all borrowers quiescent.
 * No queued or pending packets are silently discarded during cleanup. */
int ker_flow_receive_cleanup(struct ker_flow_receive *);
#endif
