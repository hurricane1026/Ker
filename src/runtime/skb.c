#include "runtime/skb.h"
#include "runtime/skb-queue-internal.h"
#include <rte_lcore.h>
#include <errno.h>
#include <string.h>

/* Backend bookkeeping is outside the unchanged upstream skb layout and cb. */
struct skb_envelope {
    struct sk_buff skb;
    struct ker_skb_context *owner;
    struct rte_mbuf *backing;
    const struct ker_skb_queue *queue;
    unsigned int queued_charge;
};
static struct skb_envelope *envelope(struct sk_buff *skb)
{
    return container_of(skb, struct skb_envelope, skb);
}
static bool owner_active(struct ker_skb_context *ctx)
{
    return ctx && ctx->descriptors && ctx->packets && ctx->packets->mbufs &&
        rte_lcore_id() == ctx->lcore;
}
static bool context_owned(struct ker_skb_context *ctx)
{
    return ctx && ctx->descriptors && rte_lcore_id() == ctx->lcore;
}
static int supported(struct sk_buff *skb)
{
    if (!skb || !context_owned(envelope(skb)->owner))
        return -EXDEV;
    if (envelope(skb)->queue) return -EBUSY;
    struct skb_shared_info *info = skb_shinfo(skb);
    if (skb->data_len || info->nr_frags || info->frag_list || info->flags ||
        info->destructor_arg || skb->_skb_refdst || skb->head_frag || skb->pp_recycle || skb->fclone)
        return -ENOTSUP;
    return 0;
}
size_t ker_skb_shared_info_size(void)
{
    return SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
}
static unsigned int backing_size(const struct rte_mbuf *packet)
{
    return RTE_ALIGN_FLOOR((unsigned int)packet->buf_len, SMP_CACHE_BYTES);
}
static int rx_metadata_supported(const struct rte_mbuf *packet)
{
    const uint64_t transformed = RTE_MBUF_F_RX_VLAN_STRIPPED |
        RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_LRO |
        RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;
    if ((packet->ol_flags & transformed) ||
        (packet->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_NONE ||
        (packet->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_L4_CKSUM_NONE)
        return -ENOTSUP;
    return 0;
}
static int packet_geometry(const struct rte_mbuf *packet, unsigned int *size)
{
    if (!packet || RTE_MBUF_HAS_EXTBUF(packet) || packet->nb_segs != 1 || packet->next ||
        !RTE_MBUF_DIRECT(packet) ||
        packet->pkt_len != packet->data_len)
        return -ENOTSUP;
    if (rx_metadata_supported(packet))
        return -ENOTSUP;
    if (rte_mbuf_refcnt_read(packet) != 1)
        return -EBUSY;
    if ((uintptr_t)packet->buf_addr % SMP_CACHE_BYTES)
        return -EINVAL;
    *size = backing_size(packet);
    if (*size <= ker_skb_shared_info_size() ||
        (uint32_t)packet->data_off + packet->data_len > *size - ker_skb_shared_info_size())
        return -ENOSPC;
    return 0;
}
static int mbuf_chain_geometry(const struct rte_mbuf *head, uint32_t *length)
{
    if (!head || !length)
        return -EINVAL;
    uint16_t count = head->nb_segs;
    if (!count)
        return -EINVAL;
    if (count == 1)
        return head->next ? -EINVAL : -ENOTSUP;
    if (rx_metadata_supported(head))
        return -ENOTSUP;
    const struct rte_mbuf *segment = head;
    uint64_t total = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (!segment)
            return -EINVAL;
        if (i == 0 && segment->nb_segs != count)
            return -EINVAL;
        if (!segment->buf_addr || RTE_MBUF_HAS_EXTBUF(segment) || !RTE_MBUF_DIRECT(segment))
            return -ENOTSUP;
        if (rte_mbuf_refcnt_read(segment) != 1)
            return -EBUSY;
        if ((uint64_t)segment->data_off + segment->data_len > segment->buf_len)
            return -EINVAL;
        total += segment->data_len;
        if (total > UINT32_MAX)
            return -EOVERFLOW;
        segment = segment->next;
    }
    if (segment || total != head->pkt_len)
        return -EINVAL;
    *length = (uint32_t)total;
    return 0;
}
static void finalize(struct skb_envelope *desc, struct rte_mbuf *packet, unsigned int size)
{
    /* Reset the entire reserved region on pool reuse, including fragment slots
     * and destructor_arg which upstream's fast initializer does not clear. */
    memset((uint8_t *)packet->buf_addr + size - ker_skb_shared_info_size(),
        0, ker_skb_shared_info_size());
    ker_linux_skb_finalize(&desc->skb, packet->buf_addr, size);
    desc->backing = packet;
}
int ker_skb_context_init(struct ker_skb_context *ctx, struct ker_packet_pool *packets, const char *name)
{
    if (!ctx || ctx->descriptors || !packets || !packets->mbufs || !name || rte_lcore_id() == LCORE_ID_ANY)
        return -EINVAL;
    struct kmem_cache *cache = kmem_cache_create(name, sizeof(struct skb_envelope), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!cache)
        return -ENOMEM;
    *ctx = (struct ker_skb_context){.descriptors = cache, .packets = packets, .lcore = rte_lcore_id()};
    return 0;
}
int ker_skb_context_cleanup(struct ker_skb_context *ctx)
{
    if (!ctx)
        return -EINVAL;
    if (!ctx->descriptors)
        return 0;
    if (!context_owned(ctx))
        return -EXDEV;
    if (ctx->live || ctx->receive_live || ctx->address_live || ctx->queue_live)
        return -EBUSY;
    kmem_cache_destroy(ctx->descriptors);
    *ctx = (struct ker_skb_context){0};
    return 0;
}
int ker_skb_from_mbuf(struct ker_skb_context *ctx, struct rte_mbuf *packet, struct sk_buff **result)
{
    unsigned int size;
    if (!result || !packet)
        return -EINVAL;
    if (!owner_active(ctx))
        return -EXDEV;
    int error = packet_geometry(packet, &size);
    if (error)
        return error;
    struct skb_envelope *desc = kmem_cache_zalloc(ctx->descriptors, GFP_ATOMIC);
    if (!desc)
        return -ENOMEM;
    desc->owner = ctx;
    finalize(desc, packet, size);
    skb_reserve(&desc->skb, packet->data_off);
    skb_put(&desc->skb, packet->data_len);
    ++ctx->live;
    *result = &desc->skb;
    return 0;
}
int ker_skb_copy_from_mbuf_chain(struct ker_skb_context *ctx,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result)
{
    uint32_t length;
    if (!result)
        return -EINVAL;
    if (!owner_active(ctx))
        return -EXDEV;
    int error = mbuf_chain_geometry(chain, &length);
    if (error)
        return error;
    if ((uint64_t)headroom + length > UINT_MAX)
        return -EOVERFLOW;
    struct sk_buff *skb = NULL;
    error = ker_skb_alloc(ctx, length, headroom, &skb);
    if (error)
        return error;
    uint8_t *destination;
    error = ker_skb_put(skb, length, &destination);
    if (error) {
        ker_skb_free(skb);
        return error;
    }
    const struct rte_mbuf *segment = chain;
    for (uint16_t i = 0; i < chain->nb_segs; ++i) {
        if (segment->data_len)
            memcpy(destination, rte_pktmbuf_mtod(segment, const void *), segment->data_len);
        destination += segment->data_len;
        segment = segment->next;
    }
    *result = skb;
    return 0;
}
int ker_skb_alloc(struct ker_skb_context *ctx, unsigned int payload_capacity,
    unsigned int headroom, struct sk_buff **result)
{
    if (!result)
        return -EINVAL;
    if (!owner_active(ctx))
        return -EXDEV;
    struct rte_mbuf *packet = ker_packet_alloc(ctx->packets);
    if (!packet)
        return -ENOMEM;
    unsigned int size = backing_size(packet);
    if (size <= ker_skb_shared_info_size() || headroom > size - ker_skb_shared_info_size() ||
        payload_capacity > size - ker_skb_shared_info_size() - headroom) {
        ker_packet_free(packet);
        return -ENOSPC;
    }
    packet->data_off = (uint16_t)headroom;
    int error = ker_skb_from_mbuf(ctx, packet, result);
    if (error)
        ker_packet_free(packet);
    return error;
}
int ker_skb_validate(struct sk_buff *skb, struct ker_skb_context *ctx)
{
    int error = supported(skb);
    if (error) return error;
    if (envelope(skb)->owner != ctx) return -EXDEV;
    if (refcount_read(&skb->users) == 0 ||
        (uintptr_t)skb->data < (uintptr_t)skb->head ||
        skb_headroom(skb) > skb_end_offset(skb) ||
        skb->len > skb_end_offset(skb) - skb_headroom(skb) ||
        skb_tail_pointer(skb) != skb->data + skb->len) return -EINVAL;
    return 0;
}
int ker_skb_get(struct sk_buff *skb)
{
    int error = supported(skb);
    if (error)
        return error;
    skb_get(skb);
    return 0;
}
int ker_skb_free(struct sk_buff *skb)
{
    if (!skb)
        return 0;
    int error = supported(skb);
    if (error)
        return error;
    if (!skb_unref(skb))
        return 0;
    struct skb_envelope *desc = envelope(skb);
    struct ker_skb_context *owner = desc->owner;
    if (skb->destructor)
        skb->destructor(skb);
    if (skb_data_unref(skb, skb_shinfo(skb)))
        ker_packet_free(desc->backing);
    --owner->live;
    kmem_cache_free(owner->descriptors, desc);
    return 0;
}
int ker_skb_clone(struct sk_buff *skb, struct sk_buff **result)
{
    if (!result)
        return -EINVAL;
    int error = supported(skb);
    if (error)
        return error;
    if ((atomic_read(&skb_shinfo(skb)->dataref) & SKB_DATAREF_MASK) == SKB_DATAREF_MASK)
        return -EOVERFLOW;
    struct skb_envelope *src = envelope(skb);
    struct skb_envelope *dst = kmem_cache_zalloc(src->owner->descriptors, GFP_ATOMIC);
    if (!dst)
        return -ENOMEM;
    dst->owner = src->owner;
    dst->backing = src->backing;
    *result = ker_linux_skb_clone_into(&dst->skb, skb);
    ++src->owner->live;
    return 0;
}
int ker_skb_make_writable(struct sk_buff *skb, unsigned int headroom, unsigned int tailroom)
{
    int error = supported(skb);
    if (error)
        return error;
    if (skb_shared(skb))
        return -EBUSY;
    unsigned int head = headroom > skb_headroom(skb) ? headroom : skb_headroom(skb);
    unsigned int tail = tailroom;
    if (!skb_cloned(skb) && !skb->nohdr && head == skb_headroom(skb) && tail <= (unsigned int)skb_tailroom(skb))
        return 0;
    struct skb_envelope *desc = envelope(skb);
    struct rte_mbuf *packet = ker_packet_alloc(desc->owner->packets);
    if (!packet)
        return -ENOMEM;
    unsigned int size = backing_size(packet);
    if (size <= ker_skb_shared_info_size() ||
        (uint64_t)head + skb->len + tail > size - ker_skb_shared_info_size()) {
        ker_packet_free(packet);
        return -ENOSPC;
    }
    unsigned int delta = head - skb_headroom(skb);
    struct skb_shared_info *new_info = (void *)((uint8_t *)packet->buf_addr + size - ker_skb_shared_info_size());
    memset(new_info, 0, ker_skb_shared_info_size());
    memcpy(new_info, skb_shinfo(skb), sizeof(*new_info));
    atomic_set(&new_info->dataref, 1);
    memcpy((uint8_t *)packet->buf_addr + delta, skb->head, skb_headroom(skb) + skb->len);
    if (skb_data_unref(skb, skb_shinfo(skb)))
        ker_packet_free(desc->backing);
    skb->head = packet->buf_addr;
    skb->data = skb->head + head;
    skb_set_end_offset(skb, size - ker_skb_shared_info_size());
    skb_set_tail_pointer(skb, skb->len);
    skb_headers_offset_update(skb, (int)delta);
    skb->cloned = 0;
    skb->nohdr = 0;
    skb->hdr_len = 0;
    skb->truesize = SKB_TRUESIZE(skb->end);
    desc->backing = packet;
    return 0;
}
int ker_skb_to_mbuf(struct sk_buff *skb, struct rte_mbuf **result)
{
    if (!result)
        return -EINVAL;
    int error = supported(skb);
    if (error)
        return error;
    if (skb->ip_summed == CHECKSUM_PARTIAL || skb_shinfo(skb)->gso_size || skb_shinfo(skb)->gso_type)
        return -ENOTSUP;
    struct rte_mbuf *packet = ker_packet_alloc(envelope(skb)->owner->packets);
    if (!packet)
        return -ENOMEM;
    if ((uint64_t)skb_headroom(skb) + skb->len > packet->buf_len) {
        ker_packet_free(packet);
        return -ENOSPC;
    }
    packet->data_off = (uint16_t)skb_headroom(skb);
    void *data = rte_pktmbuf_append(packet, skb->len);
    if (!data) { ker_packet_free(packet); return -ENOSPC; }
    memcpy(data, skb->data, skb->len);
    packet->ol_flags = 0;
    *result = packet;
    return 0;
}
static int writable(struct sk_buff *skb)
{
    int error = supported(skb);
    if (error)
        return error;
    return skb_shared(skb) || skb_cloned(skb) || skb->nohdr ? -EBUSY : 0;
}
int ker_skb_put(struct sk_buff *skb, unsigned int length, uint8_t **data)
{
    if (!data)
        return -EINVAL;
    int error = writable(skb);
    if (error)
        return error;
    if (length > (unsigned int)skb_tailroom(skb))
        return -ENOSPC;
    *data = skb_put(skb, length);
    return 0;
}
int ker_skb_push(struct sk_buff *skb, unsigned int length, uint8_t **data)
{
    if (!data)
        return -EINVAL;
    int error = writable(skb);
    if (error)
        return error;
    if (length > skb_headroom(skb))
        return -ENOSPC;
    *data = skb_push(skb, length);
    return 0;
}
int ker_skb_pull(struct sk_buff *skb, unsigned int length)
{
    int error = supported(skb);
    if (error)
        return error;
    if (skb_shared(skb))
        return -EBUSY;
    return skb_pull(skb, length) ? 0 : -EINVAL;
}
int ker_skb_trim(struct sk_buff *skb, unsigned int length)
{
    int error = supported(skb);
    if (error)
        return error;
    if (skb_shared(skb))
        return -EBUSY;
    if (length > skb->len)
        return -EINVAL;
    skb_trim(skb, length);
    return 0;
}

/* Queue bookkeeping is private to the envelope; native cb and packet bytes
 * remain untouched. Callers below are the validated synchronous queue adapter. */
void ker_skb_queue_claim(struct sk_buff *skb, const struct ker_skb_queue *queue)
{
    BUG_ON(!queue || supported(skb) || skb_shared(skb) || skb->next || skb->prev || !skb->truesize);
    envelope(skb)->queue = queue;
    envelope(skb)->queued_charge = skb->truesize;
}
unsigned int ker_skb_queue_release(struct sk_buff *skb, const struct ker_skb_queue *queue)
{
    struct skb_envelope *desc = envelope(skb);
    BUG_ON(!context_owned(desc->owner) || desc->queue != queue || skb->next || skb->prev);
    unsigned int charge = desc->queued_charge;
    desc->queue = NULL; desc->queued_charge = 0;
    return charge;
}
