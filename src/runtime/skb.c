#include "runtime/skb.h"
#include "runtime/skb-queue-internal.h"
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/checksum.h>

/* Backend bookkeeping is outside the unchanged upstream skb layout and cb. */
struct skb_envelope {
    struct sk_buff skb;
    struct ker_skb_context *owner;
    struct rte_mbuf *backing;
    uint64_t identity;
    const void *queue;
    unsigned int queued_charge;
};
static struct skb_envelope *envelope(struct sk_buff *skb)
{
    return container_of(skb, struct skb_envelope, skb);
}
uint64_t ker_skb_identity(const struct sk_buff *skb)
{
    if (!skb) return 0;
    const struct skb_envelope *desc = container_of(skb, struct skb_envelope, skb);
    return desc->identity;
}
static int assign_identity(struct skb_envelope *desc)
{
    if (desc->owner->next_identity == UINT64_MAX) return -EOVERFLOW;
    desc->identity = ++desc->owner->next_identity;
    return 0;
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
static int mbuf_chain_geometry(const struct rte_mbuf *head, uint32_t *length,
    bool allow_shared)
{
    if (!head || !length)
        return -EINVAL;
    uint16_t count = head->nb_segs;
    if (!count)
        return -EINVAL;
    if (rx_metadata_supported(head))
        return -ENOTSUP;
    const struct rte_mbuf *segment = head;
    uint64_t total = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (!segment)
            return -EINVAL;
        if (i == 0 && segment->nb_segs != count)
            return -EINVAL;
        if (!segment->buf_addr || RTE_MBUF_HAS_EXTBUF(segment))
            return -ENOTSUP;
        if (RTE_MBUF_DIRECT(segment)) {
            if (!allow_shared && rte_mbuf_refcnt_read(segment) != 1)
                return -EBUSY;
            if (allow_shared && !rte_mbuf_refcnt_read(segment))
                return -EINVAL;
        } else {
            if (!allow_shared || !RTE_MBUF_CLONED(segment) ||
                !rte_mbuf_refcnt_read(segment))
                return -ENOTSUP;
            struct rte_mbuf *parent = rte_mbuf_from_indirect(
                (struct rte_mbuf *)segment);
            if (!parent || !RTE_MBUF_DIRECT(parent) ||
                RTE_MBUF_HAS_EXTBUF(parent) || !rte_mbuf_refcnt_read(parent) ||
                segment->buf_addr != parent->buf_addr ||
                segment->buf_len > parent->buf_len ||
                (uint64_t)segment->data_off + segment->data_len > parent->buf_len)
                return -EINVAL;
        }
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
    error = assign_identity(desc);
    if (error) { kmem_cache_free(ctx->descriptors, desc); return error; }
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
    int error = mbuf_chain_geometry(chain, &length, false);
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
int ker_skb_copy_from_mbuf_chain_borrowed(struct ker_skb_context *ctx,
    const struct rte_mbuf *chain, unsigned int headroom, struct sk_buff **result)
{
    uint32_t length;
    if (!result)
        return -EINVAL;
    if (!owner_active(ctx))
        return -EXDEV;
    int error = mbuf_chain_geometry(chain, &length, true);
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
            memcpy(destination, rte_pktmbuf_mtod(segment, const void *),
                segment->data_len);
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
    error = assign_identity(dst);
    if (error) { kmem_cache_free(src->owner->descriptors, dst); return error; }
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
static int skb_to_mbuf_copy(struct sk_buff *skb, struct rte_mbuf **result,
    bool allow_partial_checksum)
{
    if (!result)
        return -EINVAL;
    int error = supported(skb);
    if (error)
        return error;
    if ((!allow_partial_checksum && skb->ip_summed == CHECKSUM_PARTIAL) ||
        skb_shinfo(skb)->gso_size || skb_shinfo(skb)->gso_type)
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
int ker_skb_to_mbuf(struct sk_buff *skb, struct rte_mbuf **result)
{
    return skb_to_mbuf_copy(skb, result, false);
}
static int skb_to_mbuf_chain_copy(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result, bool allow_partial)
{
    if (!result || !segment_payload_limit)
        return -EINVAL;
    if (segment_payload_limit > UINT16_MAX)
        return -EOVERFLOW;
    int error = ker_skb_validate(skb, skb ? envelope(skb)->owner : NULL);
    if (error)
        return error;
    if ((allow_partial ? skb->ip_summed != CHECKSUM_PARTIAL :
        skb->ip_summed == CHECKSUM_PARTIAL) || skb_shinfo(skb)->gso_size ||
        skb_shinfo(skb)->gso_type)
        return -ENOTSUP;

    struct ker_packet_pool *pool = envelope(skb)->owner->packets;
    uint32_t room = rte_pktmbuf_data_room_size(pool->mbufs);
    uint32_t first_headroom = skb_headroom(skb);
    uint32_t following_headroom = RTE_MIN((uint32_t)RTE_PKTMBUF_HEADROOM, room);
    if (first_headroom > room || first_headroom > UINT16_MAX)
        return -ENOSPC;
    uint32_t first_capacity = RTE_MIN(segment_payload_limit, room - first_headroom);
    uint32_t following_capacity = room - following_headroom;
    following_capacity = RTE_MIN(segment_payload_limit, following_capacity);
    if (skb->len && !first_capacity)
        return -ENOSPC;
    uint64_t segments = 1;
    if (skb->len > first_capacity) {
        if (!following_capacity)
            return -ENOSPC;
        uint32_t remainder = skb->len - first_capacity;
        segments += ((uint64_t)remainder + following_capacity - 1) / following_capacity;
    }
    if (segments > UINT16_MAX)
        return -EOVERFLOW;

    struct rte_mbuf *chain = NULL;
    struct rte_mbuf *tail = NULL;
    const uint8_t *source = skb->data;
    uint32_t remaining = skb->len;
    for (uint64_t i = 0; i < segments; ++i) {
        struct rte_mbuf *segment = ker_packet_alloc(pool);
        if (!segment) {
            ker_packet_free(chain);
            return -ENOMEM;
        }
        if (!i)
            segment->data_off = (uint16_t)first_headroom;
        uint32_t capacity = i ? following_capacity : first_capacity;
        uint16_t length = (uint16_t)RTE_MIN(remaining, capacity);
        void *destination = rte_pktmbuf_append(segment, length);
        if (!destination) {
            ker_packet_free(segment);
            ker_packet_free(chain);
            return -ENOSPC;
        }
        if (length)
            memcpy(destination, source, length);
        source += length;
        remaining -= length;
        segment->ol_flags = 0;
        if (!chain) {
            chain = tail = segment;
        } else {
            if ((uint32_t)chain->nb_segs + 1U > UINT16_MAX ||
                (uint64_t)chain->pkt_len + segment->data_len > UINT32_MAX) {
                ker_packet_free(segment);
                ker_packet_free(chain);
                return -EOVERFLOW;
            }
            tail->next = segment;
            tail = segment;
            chain->nb_segs++;
            chain->pkt_len += segment->data_len;
        }
    }
    *result = chain;
    return 0;
}
int ker_skb_to_mbuf_chain_copy(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result)
{
    return skb_to_mbuf_chain_copy(skb, segment_payload_limit, result, false);
}

static int chain_write(struct rte_mbuf *chain, uint32_t offset,
    const uint8_t *bytes, size_t length)
{
    struct rte_mbuf *segment = chain;
    uint16_t count = chain->nb_segs;
    for (uint16_t i = 0; i < count && segment; ++i, segment = segment->next) {
        if (offset >= segment->data_len) {
            offset -= segment->data_len;
            continue;
        }
        size_t available = segment->data_len - offset;
        size_t copy = length < available ? length : available;
        memcpy((uint8_t *)rte_pktmbuf_mtod(segment, void *) + offset, bytes, copy);
        bytes += copy;
        length -= copy;
        offset = 0;
        if (!length)
            return 0;
    }
    return -EINVAL;
}

static int skb_to_mbuf_chain_software_checksum(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result, bool mangle_zero)
{
    if (!result || !segment_payload_limit)
        return -EINVAL;
    if (segment_payload_limit > UINT16_MAX)
        return -EOVERFLOW;
    int error = supported(skb);
    if (error)
        return error;
    error = ker_skb_validate(skb, envelope(skb)->owner);
    if (error)
        return error;
    if (skb->ip_summed != CHECKSUM_PARTIAL)
        return -EINVAL;
    if (skb_shared(skb) || skb_cloned(skb) || skb->nohdr ||
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
        skb->csum_not_inet ||
#endif
        skb_shinfo(skb)->gso_size || skb_shinfo(skb)->gso_type)
        return -ENOTSUP;

    /* Keep start/field checks identical to the single-mbuf completion path. */
    int start = (int)skb->csum_start - (int)skb_headroom(skb);
    if (start < 0 || (unsigned int)start >= skb->len)
        return -EINVAL;
    uint64_t field = (uint64_t)(unsigned int)start + skb->csum_offset;
    if (field > skb->len || skb->len - (unsigned int)field < sizeof(__sum16))
        return -EINVAL;
    if (skb->len - (unsigned int)start > INT_MAX)
        return -EOVERFLOW;

    __sum16 checksum = csum_fold(csum_partial(skb->data + start,
        (int)(skb->len - (unsigned int)start), 0));
    if (mangle_zero && !checksum)
        checksum = CSUM_MANGLED_0;
    struct rte_mbuf *chain = NULL;
    error = skb_to_mbuf_chain_copy(skb, segment_payload_limit, &chain, true);
    if (error)
        return error;
    error = chain_write(chain, (uint32_t)field, (const uint8_t *)&checksum, sizeof(checksum));
    if (error) {
        ker_packet_free(chain);
        return error;
    }
    *result = chain;
    return 0;
}
int ker_skb_to_mbuf_chain_software_checksum(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result)
{
    return skb_to_mbuf_chain_software_checksum(skb, segment_payload_limit, result, true);
}
int ker_skb_to_mbuf_chain_software_checksum_exact(struct sk_buff *skb,
    unsigned int segment_payload_limit, struct rte_mbuf **result)
{
    return skb_to_mbuf_chain_software_checksum(skb, segment_payload_limit, result, false);
}
int ker_skb_to_mbuf_software_checksum(struct sk_buff *skb, struct rte_mbuf **result)
{
    if (!result)
        return -EINVAL;
    int error = supported(skb);
    if (error)
        return error;
    if (skb->ip_summed != CHECKSUM_PARTIAL)
        return -EINVAL;
    if (skb_shared(skb) || skb_cloned(skb) || skb->nohdr ||
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
        skb->csum_not_inet ||
#endif
        skb_shinfo(skb)->gso_size || skb_shinfo(skb)->gso_type)
        return -ENOTSUP;

    /* Match skb_checksum_help's data-relative start and field bounds before
     * allocating. Use wide arithmetic so malformed u16 offsets cannot wrap. */
    /* Exact Linux skb_checksum_start_offset() expression from pinned
     * include/linux/skbuff.h; this compatibility header omits that helper. */
    int start = (int)skb->csum_start - (int)skb_headroom(skb);
    if (start < 0 || (unsigned int)start >= skb->len)
        return -EINVAL;
    uint64_t field = (uint64_t)(unsigned int)start + skb->csum_offset;
    if (field > skb->len || skb->len - (unsigned int)field < sizeof(__sum16))
        return -EINVAL;
    if (skb->len - (unsigned int)start > INT_MAX)
        return -EOVERFLOW;

    struct rte_mbuf *packet = NULL;
    error = skb_to_mbuf_copy(skb, &packet, true);
    if (error)
        return error;
    __wsum sum = csum_partial((uint8_t *)rte_pktmbuf_mtod(packet, void *) + start,
        (int)(skb->len - (unsigned int)start), 0);
    __sum16 checksum = csum_fold(sum);
    if (!checksum)
        checksum = CSUM_MANGLED_0;
    /* Linux stores __sum16 directly; memcpy also handles a valid odd offset. */
    memcpy((uint8_t *)rte_pktmbuf_mtod(packet, void *) + field, &checksum, sizeof(checksum));
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
void ker_skb_native_queue_claim(struct sk_buff *skb, const void *queue)
{
    BUG_ON(!queue || !skb || !context_owned(envelope(skb)->owner) ||
        envelope(skb)->queue || skb_shared(skb) || skb->next || skb->prev || !skb->truesize);
    envelope(skb)->queue = queue;
    envelope(skb)->queued_charge = skb->truesize;
}
unsigned int ker_skb_native_queue_release(struct sk_buff *skb, const void *queue)
{
    struct skb_envelope *desc = envelope(skb);
    BUG_ON(!context_owned(desc->owner) || desc->queue != queue || skb->next || skb->prev);
    unsigned int charge = desc->queued_charge;
    desc->queue = NULL; desc->queued_charge = 0;
    return charge;
}
int ker_skb_native_queue_clone(struct sk_buff *skb, const void *queue, struct sk_buff **result)
{
    if (!result || !skb || !queue || !context_owned(envelope(skb)->owner)) return -EINVAL;
    struct skb_envelope *src = envelope(skb);
    if (src->queue != queue || !skb->next || !skb->prev) return -EPERM;
    if ((atomic_read(&skb_shinfo(skb)->dataref) & SKB_DATAREF_MASK) == SKB_DATAREF_MASK) return -EOVERFLOW;
    struct skb_envelope *dst = kmem_cache_zalloc(src->owner->descriptors, GFP_ATOMIC);
    if (!dst) return -ENOMEM;
    dst->owner = src->owner; dst->backing = src->backing;
    int error = assign_identity(dst);
    if (error) { kmem_cache_free(src->owner->descriptors, dst); return error; }
    *result = ker_linux_skb_clone_into(&dst->skb, skb);
    ++src->owner->live;
    return 0;
}
