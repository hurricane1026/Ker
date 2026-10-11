#ifndef KER_RUNTIME_SKB_H
#define KER_RUNTIME_SKB_H
#include "ker/linux_skb.h"
#include "runtime/buffer.h"
#include <linux/slab.h>

/* Private linear skb bridge. Context/pool objects must be zero initialized,
 * remain at stable addresses and outlive all their descriptors. Only the
 * owning EAL worker may access this context and its skb objects. */
struct ker_skb_context {
    struct kmem_cache *descriptors;
    struct ker_packet_pool *packets;
    unsigned int lcore;
    size_t live;
    unsigned int address_live; /* IPv4 address views pin the context */
    unsigned int queue_live; /* initialized bounded queues pin the context */
    unsigned int receive_live; /* protocol runtimes pin the context */
};
int ker_skb_context_init(struct ker_skb_context *ctx, struct ker_packet_pool *packets, const char *name);
int ker_skb_context_cleanup(struct ker_skb_context *ctx);
/* Allocations stay in the fixed DPDK pools; errors leave *result unchanged. */
int ker_skb_alloc(struct ker_skb_context *ctx, unsigned int payload_capacity,
    unsigned int headroom, struct sk_buff **result);
/* Adopts a unique direct single-segment mbuf only on success. Its tail must
 * leave room for skb_shared_info; failure retains caller's mbuf ownership. */
int ker_skb_from_mbuf(struct ker_skb_context *ctx, struct rte_mbuf *packet, struct sk_buff **result);
/* Copy a validated direct, uniquely owned multi-segment mbuf chain into a
 * linear skb. The source chain remains caller-owned and unchanged on every
 * return. Indirect/shared/extbuf chains are not supported. RX metadata is
 * interpreted on the head mbuf only, as defined by DPDK. */
int ker_skb_copy_from_mbuf_chain(struct ker_skb_context *ctx,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result);
/* Validate a bridge skb and its owning context without taking a reference. */
int ker_skb_validate(struct sk_buff *skb, struct ker_skb_context *ctx);
/* Queued descriptors reject validate/get/free/clone/export and mutation with
 * EBUSY until dequeued. Raw native fields must not be changed while queued. */
int ker_skb_get(struct sk_buff *skb);
int ker_skb_free(struct sk_buff *skb);
int ker_skb_clone(struct sk_buff *skb, struct sk_buff **result);
/* COW preserves Linux dataref/headerless semantics; unique descriptor needed. */
int ker_skb_make_writable(struct sk_buff *skb, unsigned int headroom, unsigned int tailroom);
/* Always copies; caller owns returned mbuf. No native offload claims are set. */
int ker_skb_to_mbuf(struct sk_buff *skb, struct rte_mbuf **result);
/* Complete a linear CHECKSUM_PARTIAL skb in a private copied mbuf using Linux
 * Internet-checksum semantics. Source bytes/metadata remain unchanged; no TX
 * offload metadata is set. CRC32C, GSO and unsupported skb layouts are rejected. */
int ker_skb_to_mbuf_software_checksum(struct sk_buff *skb, struct rte_mbuf **result);
int ker_skb_put(struct sk_buff *skb, unsigned int length, uint8_t **data);
int ker_skb_push(struct sk_buff *skb, unsigned int length, uint8_t **data);
int ker_skb_pull(struct sk_buff *skb, unsigned int length);
int ker_skb_trim(struct sk_buff *skb, unsigned int length);
size_t ker_skb_shared_info_size(void);

void ker_linux_skb_finalize(struct sk_buff *skb, void *data, unsigned int size);
struct sk_buff *ker_linux_skb_clone_into(struct sk_buff *dst, struct sk_buff *src);
#endif
