#ifndef KER_RUNTIME_FLOW_H
#define KER_RUNTIME_FLOW_H
#include "runtime/buffer.h"
#include <rte_ring.h>
#include <stdatomic.h>

#define KER_FLOW_BUCKETS 256U
#define KER_FLOW_MAX_WORKERS 64U
#define KER_FLOW_MAX_SPECIAL 256U

enum ker_flow_direction { KER_FLOW_INGRESS, KER_FLOW_EGRESS };
struct ker_flow_key {
    uint64_t domain;
    uint8_t family; /* 4 or 6 */
    uint8_t protocol; /* TCP=6 or UDP=17 */
    uint8_t local[16];
    uint8_t remote[16];
    uint16_t local_port; /* host byte order */
    uint16_t remote_port;
};
struct ker_flow_special { struct ker_flow_key key; uint16_t owner; };
struct ker_flow_config {
    unsigned int worker_count;
    const uint16_t *bucket_owner; /* KER_FLOW_BUCKETS entries */
    uint64_t seed;
    const struct ker_flow_special *special;
    unsigned int special_count;
    unsigned int inbox_capacity; /* DPDK ring capacity request */
    const char *name;
    int socket_id;
};
/* Caller-owned, stable zero-initialized storage. Do not mutate fields directly.
 * Config arrays are borrowed only for init; the fabric copies them and must
 * outlive all attached contexts. Cleanup requires externally quiesced producers. */
struct ker_flow_fabric {
    unsigned int worker_count;
    struct rte_ring **inbox;
    atomic_bool *attached;
    uint16_t bucket_owner[KER_FLOW_BUCKETS];
    struct ker_flow_special *special;
    unsigned int special_count;
    uint64_t seed;
    bool initialized;
};
struct ker_worker;
typedef void (*ker_flow_receive_fn)(void *arg, const struct ker_flow_key *key,
    struct rte_mbuf *packet);
/* Context storage is caller-owned, stable and zero-initialized. The receive
 * callback owns one mbuf reference; key is borrowed for the call. It must not
 * detach this context, clean up its worker, or destroy callback argument data. */
struct ker_flow_context {
    struct ker_flow_fabric *fabric;
    struct ker_worker *worker;
    struct rte_ring *inbox;
    uint16_t bucket_owner[KER_FLOW_BUCKETS];
    struct ker_flow_special *special;
    unsigned int special_count;
    uint64_t seed;
    unsigned int worker_id;
    unsigned int lcore;
    ker_flow_receive_fn receive;
    void *arg;
    bool delivering;
    bool attached;
};

int ker_flow_parse(const struct rte_mbuf *packet, uint64_t domain,
    enum ker_flow_direction direction, struct ker_flow_key *key);
int ker_flow_hash(const struct ker_flow_key *key, uint64_t seed, uint32_t *hash);
int ker_flow_fabric_init(struct ker_flow_fabric *fabric, const struct ker_flow_config *config);
int ker_flow_fabric_cleanup(struct ker_flow_fabric *fabric);
/* Attach/detach only during a quiescent setup/shutdown phase. Attach calls are
 * externally serialized. Each context and worker is pinned to its lcore. */
int ker_flow_attach(struct ker_flow_context *context, struct ker_flow_fabric *fabric,
    struct ker_worker *worker, unsigned int worker_id,
    ker_flow_receive_fn receive, void *arg);
int ker_flow_detach(struct ker_flow_context *context);
int ker_flow_owner(const struct ker_flow_context *context, const struct ker_flow_key *key,
    unsigned int *owner);
/* Success transfers exactly one mbuf reference, locally or into the bounded
 * target inbox, and clears *packet. Errors preserve caller ownership. */
int ker_flow_submit(struct ker_flow_context *context, uint64_t domain,
    enum ker_flow_direction direction, struct rte_mbuf **packet);
int ker_flow_poll(struct ker_flow_context *context, unsigned int budget);
#endif
