#ifndef KER_RUNTIME_WORKER_H
#define KER_RUNTIME_WORKER_H
#include "runtime/timer.h"
#include "runtime/buffer.h"
struct ker_flow_context;

/* Private poll-loop substrate. Callbacks run synchronously on the owning
 * initialized EAL worker and must not block, reenter, unregister it, or
 * close/reinitialize the borrowed pool or memory context.
 * Return a count <= budget, or a negative errno. TX retries/completions are
 * supplied by the adapter; no ethdev, NAPI or socket implementation is implied. */
typedef int (*ker_worker_io)(void *arg, unsigned int budget);
struct ker_worker_config {
    unsigned int timer_budget;
    unsigned int service_budget; /* queued application/protocol work, even while RX pauses */
    unsigned int tx_budget;
    unsigned int handoff_budget; /* bounded flow inbox work before service; zero when unattached */
    unsigned int rx_budget;
    unsigned int packet_low; /* pause RX at or below this accessible free count */
    unsigned int packet_high; /* resume at or above this; zero disables hysteresis */
    unsigned int rx_margin; /* advisory headroom, not a physically reserved pool */
};
struct ker_worker_ops { ker_worker_io service; ker_worker_io tx; ker_worker_io rx; void *arg; };
struct ker_worker_result {
    unsigned int timers;
    unsigned int service;
    unsigned int tx;
    unsigned int handoff;
    unsigned int rx;
    unsigned int rx_budget;
    unsigned int packet_available;
    unsigned int pressure; /* memory domains bits 0..2; packet pressure bit 3 */
};
#define KER_WORKER_PACKET_PRESSURE (1U << 3)
/* Initialize to {0}. Do not move/copy while active. Pool and callback argument
 * storage must outlive the worker; all operations belong to its lcore. */
struct ker_worker {
    struct ker_runtime timers;
    struct ker_packet_pool *packets;
    struct rte_mempool *backing_pool;
    struct ker_worker_config config;
    struct ker_worker_ops ops;
    struct ker_flow_context *flow;
    unsigned int lcore;
    bool initialized;
    bool polling;
    bool packet_pressure;
};
int ker_worker_init(struct ker_worker *worker, struct ker_packet_pool *packets,
    const struct ker_worker_config *config, const struct ker_worker_ops *ops);
/* Advances timers, attached flow handoff, service work, then TX before RX admission. On callback
 * failure, returns errno and reports successful completed stages in result;
 * side effects of a failed callback cannot be rolled back by the worker.
 * Validation/reentry failures leave result untouched. */
int ker_worker_poll(struct ker_worker *worker, int64_t now_ns, struct ker_worker_result *result);
int ker_worker_cleanup(struct ker_worker *worker);
#endif
