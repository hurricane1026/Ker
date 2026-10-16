#ifndef KER_RUNTIME_SKB_H
#define KER_RUNTIME_SKB_H
#include "ker/linux_skb.h"
#include "runtime/buffer.h"
#include <linux/slab.h>

/* Private linear skb bridge. Context/pool objects must be zero initialized,
 * remain at stable addresses and outlive all their descriptors. Only the
 * owning EAL worker may access this context and its skb objects. The identity
 * counter is per-context; cleanup is blocked while descriptors or protocol
 * users can retain identity-bearing pointers. */
struct ker_skb_context {
    struct kmem_cache *descriptors;
    struct ker_packet_pool *packets;
    unsigned int lcore;
    size_t live;
    uint64_t next_identity;
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
/* Copy a validated direct, uniquely owned one-or-more-segment mbuf chain into
 * a linear skb. The source chain remains caller-owned and unchanged on every
 * return. Indirect/shared/extbuf chains are not supported. RX metadata is
 * interpreted on the head mbuf only, as defined by DPDK. */
int ker_skb_copy_from_mbuf_chain(struct ker_skb_context *ctx,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result);
/* Explicit borrowed-input copy profile. The input must be a valid DPDK mbuf
 * chain owned by the caller through this call. The caller guarantees immutable
 * bytes, descriptors and topology. Direct shared refs and DPDK indirect clones are accepted;
 * external buffers and transformed RX metadata remain unsupported. */
int ker_skb_copy_from_mbuf_chain_borrowed(struct ker_skb_context *ctx,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result);
/* Validate a bridge skb and its owning context without taking a reference. */
int ker_skb_validate(struct sk_buff *skb, struct ker_skb_context *ctx);
/* Stable identity for a live Ker descriptor, including while queued. This
 * accessor cannot validate arbitrary or freed pointers. Zero means no
 * identity was assigned. */
uint64_t ker_skb_identity(const struct sk_buff *skb);
/* Queued descriptors reject validate/get/free/clone/export and mutation with
 * EBUSY until dequeued. Raw native fields must not be changed while queued. */
int ker_skb_get(struct sk_buff *skb);
int ker_skb_free(struct sk_buff *skb);
int ker_skb_clone(struct sk_buff *skb, struct sk_buff **result);
/* COW preserves Linux dataref/headerless semantics; unique descriptor needed. */
int ker_skb_make_writable(struct sk_buff *skb, unsigned int headroom, unsigned int tailroom);
/* Always copies; caller owns returned mbuf. No native offload claims are set. */
int ker_skb_to_mbuf(struct sk_buff *skb, struct rte_mbuf **result);
/* Copy a supported owned linear skb into a caller-owned direct DPDK chain.
 * The source is unchanged and remains caller-owned on every return. The first
 * segment preserves skb headroom; later segments use DPDK default headroom.
 * A nonzero limit <= UINT16_MAX bounds each segment's payload and is capped
 * by actual tailroom. Empty input yields one empty segment. CHECKSUM_PARTIAL,
 * GSO, nonlinear/queued layouts and unsupported ownership remain rejected;
 * no offload flags are set and this does not implement Linux nonlinear skb. */
int ker_skb_to_mbuf_chain_copy(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result);
/* Complete an Internet CHECKSUM_PARTIAL linear skb with the same seeded
 * csum_partial/fold semantics as ker_skb_to_mbuf_software_checksum, then
 * copy into independently owned direct mbuf segments. The checksum field may
 * cross a segment boundary. Source bytes/metadata remain unchanged and output
 * is assigned only on success. GSO, nonlinear/queued/shared/CRC32C layouts
 * remain rejected; no TX offload flags or nonlinear Linux skb are implied. */
int ker_skb_to_mbuf_chain_software_checksum(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result);
/* Exact-fold variant: a folded zero remains zero. The caller is responsible
 * for any protocol-specific zero mangling policy. */
int ker_skb_to_mbuf_chain_software_checksum_exact(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result);
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
