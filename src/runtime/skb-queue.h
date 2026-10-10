#ifndef KER_RUNTIME_SKB_QUEUE_H
#define KER_RUNTIME_SKB_QUEUE_H
#include "ker/linux_neighbor.h"
#include "runtime/skb.h"
/* A private worker-owned FIFO built from the original sk_buff_head/list helpers.
 * Stable zero-initialized storage. Initialized queue pins its context, even
 * when empty. Native links/accounting are implementation-owned. */
struct ker_skb_queue {
    struct sk_buff_head native;
    struct ker_skb_context *context;
    size_t bytes;
    size_t byte_limit;
    unsigned int packet_limit;
    bool purging;
};
/* packet_limit and byte_limit must be nonzero. bytes counts a frozen truesize
 * per queued descriptor, not payload length or an extra DPDK budget charge.
 * Shared backing can be conservatively counted once per descriptor. */
int ker_skb_queue_init(struct ker_skb_queue *, struct ker_skb_context *,
    unsigned int packet_limit, size_t byte_limit);
/* Success transfers the unique descriptor reference and clears *packet.
 * Failure, including full queue, preserves caller ownership and queue state.
 * No allocation, eviction, fallback, or cloning occurs in push/pop. */
int ker_skb_queue_push(struct ker_skb_queue *, struct sk_buff **packet);
/* Returns 1 with one caller-owned unlinked skb, 0 when empty; errors and empty
 * leave output unchanged. Dequeued packet can be mutated/exported/freed. */
int ker_skb_queue_pop(struct ker_skb_queue *, struct sk_buff **packet);
/* Frees up to budget descriptors, returns count. Non-reentrant; a destructor
 * may inspect/drain unrelated queues but may not mutate this queue. */
int ker_skb_queue_purge(struct ker_skb_queue *, unsigned int budget);
/* Requires an empty queue; does not silently drain or discard TX ownership. */
int ker_skb_queue_cleanup(struct ker_skb_queue *);
#endif
