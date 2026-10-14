#include "check.h"
#include "eal.h"
#include "runtime/skb.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>
#include <rte_malloc.h>

static struct ker_packet_pool pool;
static struct ker_skb_context ctx;
static unsigned int extbuf_frees;
static void extbuf_free(void *addr, void *opaque)
{
    (void)opaque;
    ++extbuf_frees;
    rte_free(addr);
}
static void check_reserved_tail(const struct rte_mbuf *packet, const void *buffer, uint8_t value)
{
    unsigned int start = RTE_ALIGN_FLOOR(packet->buf_len, SMP_CACHE_BYTES) -
        ker_skb_shared_info_size();
    const uint8_t *tail = (const uint8_t *)buffer + start;
    for (size_t i = 0; i < ker_skb_shared_info_size(); ++i)
        CHECK(tail[i] == value);
}
static void check_pool(unsigned int available)
{
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
}
static void test_geometry_and_operations(void)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 32, &skb) == 0);
    CHECK(refcount_read(&skb->users) == 1);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 1);
    CHECK((uintptr_t)skb_shinfo(skb) % SMP_CACHE_BYTES == 0);
    CHECK(skb_headroom(skb) == 32);
    CHECK(skb_tailroom(skb) == (int)skb->end - 32);
    uint8_t *data = NULL;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    CHECK(ker_skb_push(skb, 4, &data) == 0);
    memcpy(data, "HEAD", 4);
    CHECK(skb->len == 9 && memcmp(skb->data, "HEADhello", 9) == 0);
    CHECK(ker_skb_pull(skb, 4) == 0);
    CHECK(skb->len == 5 && memcmp(skb->data, "hello", 5) == 0);
    CHECK(memcmp(skb->data - 4, "HEAD", 4) == 0);
    CHECK(ker_skb_pull(skb, 6) == -EINVAL && skb->len == 5);
    CHECK(ker_skb_trim(skb, 6) == -EINVAL && skb->len == 5);
    uint8_t *unchanged = data;
    CHECK(ker_skb_put(skb, UINT_MAX, &data) == -ENOSPC && data == unchanged);
    CHECK(ker_skb_push(skb, UINT_MAX, &data) == -ENOSPC && data == unchanged);
    CHECK(ker_skb_trim(skb, 3) == 0 && skb->len == 3);
    CHECK(skb_tail_pointer(skb) == skb->data + 3);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(ctx.live == 0);
    check_pool(31);
}
static int destructor_count;
static void destructor(struct sk_buff *skb)
{
    CHECK(skb->cb[0] == 'x');
    ++destructor_count;
}
static void test_clone_and_descriptor_refs(void)
{
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 4, 64, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 4, &data) == 0);
    memcpy(data, "data", 4);
    skb->cb[0] = 'x';
    skb->priority = 77;
    skb->mark = 42;
    skb->tstamp = 101;
    skb->destructor = destructor;
    CHECK(ker_skb_get(skb) == 0 && refcount_read(&skb->users) == 2);
    CHECK(ker_skb_put(skb, 1, &data) == -EBUSY);
    CHECK(ker_skb_pull(skb, 1) == -EBUSY);
    CHECK(ker_skb_make_writable(skb, 0, 0) == -EBUSY);
    CHECK(ker_skb_free(skb) == 0 && refcount_read(&skb->users) == 1);
    CHECK(destructor_count == 0);
    CHECK(ker_skb_clone(skb, &clone) == 0);
    CHECK(clone != skb && clone->data == skb->data);
    CHECK(clone->cb[0] == 'x' && clone->priority == 77 && clone->mark == 42 && clone->tstamp == 101);
    CHECK(clone->destructor == NULL && clone->sk == NULL);
    CHECK(refcount_read(&clone->users) == 1 && atomic_read(&skb_shinfo(skb)->dataref) == 2);
    CHECK(skb_cloned(skb) && skb_cloned(clone));
    CHECK(ker_skb_put(clone, 1, &data) == -EBUSY);
    CHECK(ker_skb_push(clone, 1, &data) == -EBUSY);
    CHECK(ker_skb_pull(clone, 1) == 0 && clone->len == 3 && skb->len == 4);
    CHECK(ker_skb_context_cleanup(&ctx) == -EBUSY);
    CHECK(ker_skb_free(skb) == 0 && destructor_count == 1);
    CHECK(memcmp(clone->data, "ata", 3) == 0);
    CHECK(!skb_cloned(clone));
    check_pool(30);
    CHECK(ker_skb_free(clone) == 0 && destructor_count == 1);
    check_pool(31);
    struct sk_buff *identity_source = NULL;
    CHECK(ker_skb_alloc(&ctx, 8, 0, &identity_source) == 0);
    uint64_t saved_identity = ctx.next_identity;
    ctx.next_identity = UINT64_MAX;
    struct sk_buff *identity_result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_clone(identity_source, &identity_result) == -EOVERFLOW);
    CHECK(identity_result == (struct sk_buff *)(uintptr_t)1);
    ctx.next_identity = saved_identity;
    CHECK(ker_skb_free(identity_source) == 0);
    struct rte_mbuf *identity_packet = ker_packet_alloc(&pool);
    CHECK(identity_packet);
    struct sk_buff *adopt_result = (struct sk_buff *)(uintptr_t)1;
    size_t live_before_identity_overflow = ctx.live;
    saved_identity = ctx.next_identity;
    ctx.next_identity = UINT64_MAX;
    CHECK(ker_skb_from_mbuf(&ctx, identity_packet, &adopt_result) == -EOVERFLOW);
    CHECK(adopt_result == (struct sk_buff *)(uintptr_t)1 &&
          ctx.live == live_before_identity_overflow &&
          rte_mbuf_refcnt_read(identity_packet) == 1);
    ctx.next_identity = saved_identity;
    ker_packet_free(identity_packet);
    check_pool(31);
}
static void test_headerless_references(void)
{
    struct sk_buff *skb = NULL, *a = NULL, *b = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 64, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    __skb_header_release(skb);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 0x10001);
    CHECK(ker_skb_clone(skb, &a) == 0);
    CHECK(a->nohdr == 0 && a->hdr_len == 64);
    CHECK(!skb_header_cloned(a) && skb_cloned(a));
    CHECK(ker_skb_clone(skb, &b) == 0);
    CHECK(skb_header_cloned(a) && skb_header_cloned(b));
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 0x10003);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 2);
    CHECK(ker_skb_make_writable(a, 0, 0) == 0);
    CHECK(a->head != b->head && atomic_read(&skb_shinfo(a)->dataref) == 1);
    CHECK(atomic_read(&skb_shinfo(b)->dataref) == 1);
    a->data[0] = 'H';
    CHECK(b->data[0] == 'h');
    CHECK(ker_skb_free(a) == 0);
    CHECK(ker_skb_free(b) == 0);
    /* COW of the payload-only owner must drop its high-word bias as well. */
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skb) == 0);
    __skb_header_release(skb);
    CHECK(ker_skb_clone(skb, &a) == 0);
    CHECK(atomic_read(&skb_shinfo(a)->dataref) == 0x10002);
    CHECK(ker_skb_make_writable(skb, 0, 0) == 0);
    CHECK(skb->nohdr == 0 && atomic_read(&skb_shinfo(skb)->dataref) == 1);
    CHECK(a->head != skb->head && atomic_read(&skb_shinfo(a)->dataref) == 1);
    CHECK(ker_skb_free(skb) == 0 && ker_skb_free(a) == 0);
    check_pool(31);
}
static void test_cow_and_export(void)
{
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 5, 32, &skb) == 0);
    uint8_t *data;
    CHECK(ker_skb_put(skb, 5, &data) == 0);
    memcpy(data, "hello", 5);
    memcpy(skb->data - 4, "HEAD", 4);
    skb->network_header = 32;
    skb->transport_header = 34;
    skb->mac_header = 28;
    skb->mark = 19;
    CHECK(ker_skb_clone(skb, &clone) == 0);
    unsigned char *head = clone->head;
    CHECK(ker_skb_make_writable(clone, UINT_MAX, 0) == -ENOSPC && clone->head == head);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    CHECK(ker_skb_make_writable(clone, 64, 12) == 0);
    CHECK(clone->head != skb->head && skb_headroom(clone) == 64 && skb_tailroom(clone) >= 12);
    CHECK(clone->network_header == 64 && clone->transport_header == 66 && clone->mac_header == 60);
    CHECK(clone->mark == 19 && memcmp(clone->data - 4, "HEAD", 4) == 0);
    clone->data[0] = 'H';
    CHECK(skb->data[0] == 'h');
    struct rte_mbuf *packet = NULL;
    CHECK(ker_skb_to_mbuf(clone, &packet) == 0);
    CHECK(packet->data_len == 5 && packet->pkt_len == 5 && packet->ol_flags == 0);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, void *), "Hello", 5) == 0);
    CHECK(rte_pktmbuf_mtod(packet, void *) != clone->data);
    ker_packet_free(packet);
    clone->ip_summed = CHECKSUM_PARTIAL;
    packet = NULL;
    CHECK(ker_skb_to_mbuf(clone, &packet) == -ENOTSUP && packet == NULL);
    clone->ip_summed = CHECKSUM_NONE;
    skb_shinfo(clone)->gso_size = 1448;
    CHECK(ker_skb_to_mbuf(clone, &packet) == -ENOTSUP && packet == NULL);
    skb_shinfo(clone)->gso_size = 0;
    CHECK(ker_skb_free(clone) == 0 && ker_skb_free(skb) == 0);
    check_pool(31);
}
static void test_exhaustion_and_rollback(void)
{
    struct sk_buff *skbs[7];
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skbs[0]) == 0);
    for (int i = 1; i < 7; ++i)
        CHECK(ker_skb_clone(skbs[0], &skbs[i]) == 0);
    struct sk_buff *unchanged = skbs[0];
    CHECK(ker_skb_clone(skbs[0], &unchanged) == -ENOMEM && unchanged == skbs[0]);
    CHECK(atomic_read(&skb_shinfo(skbs[0])->dataref) == 7);
    for (int i = 0; i < 7; ++i)
        CHECK(ker_skb_free(skbs[i]) == 0);
    check_pool(31);
    ker_memory_fail_after(0);
    unchanged = NULL;
    CHECK(ker_skb_alloc(&ctx, 1, 64, &unchanged) == -ENOMEM && unchanged == NULL);
    check_pool(31);
    struct rte_mbuf *raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    memset(raw->buf_addr, 0xa5, raw->buf_len);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &unchanged) == -ENOMEM);
    CHECK(((uint8_t *)raw->buf_addr)[raw->buf_len - 1] == 0xa5);
    ker_packet_free(raw);
    ker_memory_fail_after(-1);
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_skb_alloc(&ctx, 1, 64, &skb) == 0 && ker_skb_clone(skb, &clone) == 0);
    struct rte_mbuf *held[30];
    for (int i = 0; i < 30; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i] != NULL); }
    unsigned char *old_head = clone->head;
    CHECK(ker_skb_make_writable(clone, 0, 0) == -ENOMEM && clone->head == old_head);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    raw = NULL;
    CHECK(ker_skb_to_mbuf(skb, &raw) == -ENOMEM && raw == NULL);
    for (int i = 0; i < 30; ++i)
        ker_packet_free(held[i]);
    CHECK(ker_skb_free(clone) == 0 && ker_skb_free(skb) == 0);
    check_pool(31);
}
static void *wrong_worker(void *skb)
{
    CHECK(ker_skb_get(skb) == -EXDEV);
    CHECK(ker_skb_free(skb) == -EXDEV);
    return NULL;
}
static void test_rx_and_rejection(void)
{
    struct rte_mbuf *raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, 3) != NULL);
    memcpy(rte_pktmbuf_mtod(raw, void *), "udp", 3);
    struct sk_buff *skb = NULL;
    rte_mbuf_refcnt_update(raw, 1);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == -EBUSY && skb == NULL);
    ker_packet_free(raw);
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == 0);
    CHECK(skb->len == 3 && memcmp(skb->data, "udp", 3) == 0);
    struct sk_buff *observer = NULL;
    CHECK(ker_skb_clone(skb, &observer) == 0);
    CHECK(atomic_read(&skb_shinfo(skb)->dataref) == 2);
    /* Read-only inspection while skb owns the backing: no extra mbuf ref. */
    CHECK(rte_mbuf_refcnt_read(raw) == 1);
    CHECK(ker_skb_free(observer) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wrong_worker, skb) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(refcount_read(&skb->users) == 1);
    skb->_skb_refdst = 1;
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(skb, &clone) == -ENOTSUP && clone == NULL);
    skb->_skb_refdst = 0;
    CHECK(ker_skb_free(skb) == 0);
    raw = ker_packet_alloc(&pool);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, raw->buf_len - raw->data_off) != NULL);
    skb = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == -ENOSPC && skb == NULL);
    ker_packet_free(raw);
    raw = ker_packet_alloc(&pool);
    struct rte_mbuf *indirect = ker_packet_clone(&pool, raw);
    CHECK(indirect != NULL);
    CHECK(ker_skb_from_mbuf(&ctx, indirect, &skb) == -ENOTSUP && skb == NULL);
    ker_packet_free(indirect);
    ker_packet_free(raw);
    check_pool(31);
}
static void test_foreign_backing(void)
{
    struct ker_packet_pool foreign = {0};
    CHECK(ker_packet_pool_init(&foreign, "ker_skb_foreign", 7, 0, 2048, SOCKET_ID_ANY) == 0);
    struct rte_mbuf *raw = ker_packet_alloc(&foreign);
    CHECK(raw != NULL);
    CHECK(rte_pktmbuf_append(raw, 4) != NULL);
    memcpy(rte_pktmbuf_mtod(raw, void *), "data", 4);
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, raw, &skb) == 0);
    CHECK(ker_packet_pool_cleanup(&foreign) == -EBUSY);
    /* Closing an unused export pool must not prevent releasing foreign data. */
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(rte_mempool_avail_count(foreign.mbufs) == 7);
    CHECK(ker_packet_pool_cleanup(&foreign) == 0);
}
static struct rte_mbuf *external_packet(void **buffer_out)
{
    const uint16_t buffer_len = 2048;
    void *buffer = rte_malloc(NULL, buffer_len, RTE_CACHE_LINE_SIZE);
    CHECK(buffer != NULL);
    memset(buffer, 0xa5, buffer_len);
    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    uint16_t usable_len = buffer_len;
    struct rte_mbuf_ext_shared_info *shinfo = rte_pktmbuf_ext_shinfo_init_helper(
        buffer, &usable_len, extbuf_free, NULL);
    CHECK(shinfo != NULL);
    rte_pktmbuf_attach_extbuf(packet, buffer, RTE_BAD_IOVA, usable_len, shinfo);
    rte_pktmbuf_reset_headroom(packet);
    CHECK(rte_pktmbuf_append(packet, 4) != NULL);
    memcpy(rte_pktmbuf_mtod(packet, void *), "ext!", 4);
    unsigned int tail_offset = RTE_ALIGN_FLOOR(usable_len, SMP_CACHE_BYTES) -
        ker_skb_shared_info_size();
    memset((uint8_t *)buffer + tail_offset, 0x5a, ker_skb_shared_info_size());
    CHECK(RTE_MBUF_HAS_EXTBUF(packet));
    *buffer_out = buffer;
    return packet;
}
static void test_external_backing_rejection(void)
{
    void *buffer = NULL;
    struct rte_mbuf *packet = external_packet(&buffer);
    struct rte_mbuf_ext_shared_info *shinfo = packet->shinfo;
    struct rte_mbuf *shared = rte_pktmbuf_clone(packet, pool.mbufs);
    CHECK(shared != NULL && rte_mbuf_refcnt_read(packet) == 1);
    CHECK(rte_mbuf_ext_refcnt_read(shinfo) == 2);
    unsigned int live = ctx.live;
    uint16_t data_off = packet->data_off, data_len = packet->data_len;
    uint32_t pkt_len = packet->pkt_len;
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_from_mbuf(&ctx, packet, &result) == -ENOTSUP);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && ctx.live == live);
    CHECK(packet->buf_addr == buffer && packet->shinfo == shinfo);
    CHECK(packet->data_off == data_off && packet->data_len == data_len && packet->pkt_len == pkt_len);
    CHECK(rte_mbuf_refcnt_read(packet) == 1 && rte_mbuf_ext_refcnt_read(shinfo) == 2);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, void *), "ext!", 4) == 0);
    check_reserved_tail(packet, buffer, 0x5a);
    ker_packet_free(shared);
    CHECK(rte_mbuf_ext_refcnt_read(shinfo) == 1);
    CHECK(extbuf_frees == 0);
    result = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, packet, &result) == -ENOTSUP && result == NULL);
    CHECK(ctx.live == live && packet->buf_addr == buffer && packet->shinfo == shinfo);
    CHECK(rte_mbuf_refcnt_read(packet) == 1 && rte_mbuf_ext_refcnt_read(shinfo) == 1);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, void *), "ext!", 4) == 0);
    check_reserved_tail(packet, buffer, 0x5a);
    ker_packet_free(packet);
    CHECK(extbuf_frees == 1);
}
static void check_rx_flag_rejected(uint64_t flags)
{
    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    CHECK(packet != NULL);
    CHECK(rte_pktmbuf_append(packet, 4) != NULL);
    memcpy(rte_pktmbuf_mtod(packet, void *), "rx!!", 4);
    packet->ol_flags = flags;
    packet->vlan_tci = 0x123;
    packet->vlan_tci_outer = 0x456;
    packet->tso_segsz = 128;
    unsigned int tail_offset = RTE_ALIGN_FLOOR(packet->buf_len, SMP_CACHE_BYTES) -
        ker_skb_shared_info_size();
    memset((uint8_t *)packet->buf_addr + tail_offset, 0x6b, ker_skb_shared_info_size());

    void *buffer = packet->buf_addr;
    uint16_t data_off = packet->data_off, data_len = packet->data_len;
    uint16_t vlan_tci = packet->vlan_tci, vlan_tci_outer = packet->vlan_tci_outer;
    uint16_t tso_segsz = packet->tso_segsz;
    uint32_t pkt_len = packet->pkt_len;
    unsigned int live = ctx.live;
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_from_mbuf(&ctx, packet, &result) == -ENOTSUP);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && ctx.live == live);
    CHECK(packet->buf_addr == buffer && packet->ol_flags == flags);
    CHECK(packet->data_off == data_off && packet->data_len == data_len && packet->pkt_len == pkt_len);
    CHECK(packet->vlan_tci == vlan_tci && packet->vlan_tci_outer == vlan_tci_outer);
    CHECK(packet->tso_segsz == tso_segsz && rte_mbuf_refcnt_read(packet) == 1);
    CHECK(memcmp(rte_pktmbuf_mtod(packet, void *), "rx!!", 4) == 0);
    check_reserved_tail(packet, buffer, 0x6b);
    ker_packet_free(packet);
}
static void test_rx_metadata_boundary(void)
{
    const uint64_t rejected[] = {
        RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED,
        RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_QINQ | RTE_MBUF_F_RX_QINQ_STRIPPED,
        RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED |
            RTE_MBUF_F_RX_QINQ | RTE_MBUF_F_RX_QINQ_STRIPPED,
        RTE_MBUF_F_RX_LRO,
        RTE_MBUF_F_RX_SEC_OFFLOAD,
        RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED,
        RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_IP_CKSUM_NONE,
        RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_L4_CKSUM_NONE,
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
        check_rx_flag_rejected(rejected[i]);
    check_pool(31);

    struct rte_mbuf *packet = ker_packet_alloc(&pool);
    const uint8_t frame[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x88, 0xa8, 0x04, 0x56, 0x81, 0x00, 0x01, 0x23, 0x08, 0x00, 's', 'a', 'f', 'e',
    };
    CHECK(packet != NULL && rte_pktmbuf_append(packet, sizeof(frame)) != NULL);
    memcpy(rte_pktmbuf_mtod(packet, void *), frame, sizeof(frame));
    packet->ol_flags = RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_QINQ |
        RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD;
    packet->vlan_tci = 0x123;
    packet->vlan_tci_outer = 0x456;
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_from_mbuf(&ctx, packet, &skb) == 0);
    CHECK(skb->len == sizeof(frame) && memcmp(skb->data, frame, sizeof(frame)) == 0);
    CHECK(skb->ip_summed == CHECKSUM_NONE);
    CHECK(skb->hash == 0);
    CHECK(ker_skb_free(skb) == 0);
    check_pool(31);
}
static struct rte_mbuf *make_chain_pair(struct rte_mbuf **tail_out)
{
    struct rte_mbuf *head = ker_packet_alloc(&pool), *tail = ker_packet_alloc(&pool);
    CHECK(head && tail);
    CHECK(rte_pktmbuf_append(head, 3) && rte_pktmbuf_append(tail, 2));
    memcpy(rte_pktmbuf_mtod(head, void *), "abc", 3);
    memcpy(rte_pktmbuf_mtod(tail, void *), "de", 2);
    CHECK(rte_pktmbuf_chain(head, tail) == 0);
    *tail_out = tail;
    return head;
}
static void expect_chain_copy_error(struct rte_mbuf *head, struct rte_mbuf *tail, int expected)
{
    uint16_t head_segs = head->nb_segs, head_data_off = head->data_off, head_data_len = head->data_len;
    uint32_t head_len = head->pkt_len;
    uint64_t head_flags = head->ol_flags, tail_flags = tail->ol_flags;
    struct rte_mbuf *head_next = head->next, *tail_next = tail->next;
    uint16_t tail_segs = tail->nb_segs, tail_data_off = tail->data_off, tail_data_len = tail->data_len;
    uint32_t tail_len = tail->pkt_len;
    void *head_buf = head->buf_addr, *tail_buf = tail->buf_addr;
    uint16_t head_refs = rte_mbuf_refcnt_read(head), tail_refs = rte_mbuf_refcnt_read(tail);
    unsigned int live = ctx.live, available = rte_mempool_avail_count(pool.mbufs);
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == expected);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && ctx.live == live);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
    CHECK(head->nb_segs == head_segs && head->pkt_len == head_len && head->data_off == head_data_off);
    CHECK(head->data_len == head_data_len && head->next == head_next && head->buf_addr == head_buf);
    CHECK(head->ol_flags == head_flags && tail->ol_flags == tail_flags);
    CHECK(tail->nb_segs == tail_segs && tail->pkt_len == tail_len && tail->data_off == tail_data_off);
    CHECK(tail->data_len == tail_data_len && tail->next == tail_next && tail->buf_addr == tail_buf);
    CHECK(rte_mbuf_refcnt_read(head) == head_refs && rte_mbuf_refcnt_read(tail) == tail_refs);
    CHECK(memcmp((uint8_t *)head_buf + head_data_off, "abc", 3) == 0);
    CHECK(memcmp((uint8_t *)tail_buf + RTE_PKTMBUF_HEADROOM, "de", 2) == 0);
}
struct foreign_chain_copy {
    struct rte_mbuf *chain;
    int error;
    bool output_unchanged;
};
static void *foreign_chain_copy_worker(void *opaque)
{
    struct foreign_chain_copy *request = opaque;
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    request->error = ker_skb_copy_from_mbuf_chain(&ctx, request->chain, 64, &result);
    request->output_unchanged = result == (struct sk_buff *)(uintptr_t)1;
    return NULL;
}
static void test_mbuf_chain_copy(void)
{
    struct rte_mbuf *tail;
    struct rte_mbuf *head = make_chain_pair(&tail);
    struct foreign_chain_copy request = {.chain = head};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_chain_copy_worker, &request) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(request.error == -EXDEV && request.output_unchanged);
    head->nb_segs = 3;
    expect_chain_copy_error(head, tail, -EINVAL);
    head->nb_segs = 2;
    ++head->pkt_len;
    expect_chain_copy_error(head, tail, -EINVAL);
    --head->pkt_len;
    head->next = NULL;
    expect_chain_copy_error(head, tail, -EINVAL);
    head->next = tail;
    tail->next = head;
    expect_chain_copy_error(head, tail, -EINVAL);
    tail->next = NULL;
    tail->data_off = tail->buf_len;
    expect_chain_copy_error(head, tail, -EINVAL);
    tail->data_off = RTE_PKTMBUF_HEADROOM;
    head->ol_flags = RTE_MBUF_F_RX_VLAN_STRIPPED;
    expect_chain_copy_error(head, tail, -ENOTSUP);
    head->ol_flags = 0;
    rte_mbuf_refcnt_update(tail, 1);
    expect_chain_copy_error(head, tail, -EBUSY);
    rte_mbuf_refcnt_update(tail, -1);
    struct sk_buff *result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, UINT_MAX, &result) == -EOVERFLOW);
    CHECK(result == (struct sk_buff *)(uintptr_t)1);
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 2000, &result) == -ENOSPC);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && head->next == tail && head->pkt_len == 5);
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, NULL) == -EINVAL);
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, NULL, 64, &result) == -EINVAL);
    void *saved_tail_buffer = tail->buf_addr;
    tail->buf_addr = NULL;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == -ENOTSUP);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && head->next == tail && ctx.live == 0);
    tail->buf_addr = saved_tail_buffer;
    ker_packet_free(head);
    check_pool(31);

    head = make_chain_pair(&tail);
    tail->ol_flags = RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_IP_CKSUM_NONE;
    result = NULL;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == 0);
    CHECK(result && result->len == 5 && memcmp(result->data, "abcde", 5) == 0);
    CHECK(tail->ol_flags == (RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_IP_CKSUM_NONE));
    CHECK(ker_skb_free(result) == 0);
    ker_packet_free(head);
    check_pool(31);

    /* Source-pool exhaustion fails atomically and can be retried in-place. */
    head = make_chain_pair(&tail);
    struct rte_mbuf *held[29];
    for (unsigned int i = 0; i < 29; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == -ENOMEM);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && ctx.live == 0);
    CHECK(head->next == tail && head->nb_segs == 2 && head->pkt_len == 5);
    CHECK(rte_mbuf_refcnt_read(head) == 1 && rte_mbuf_refcnt_read(tail) == 1);
    ker_packet_free(held[0]);
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == 0);
    CHECK(result->len == 5 && skb_headroom(result) == 64 && memcmp(result->data, "abcde", 5) == 0);
    for (unsigned int i = 1; i < 29; ++i) ker_packet_free(held[i]);
    ker_packet_free(head);
    CHECK(memcmp(result->data, "abcde", 5) == 0);
    CHECK(ker_skb_free(result) == 0);
    check_pool(31);

    struct rte_mbuf *backing = ker_packet_alloc(&pool), *indirect = NULL;
    head = ker_packet_alloc(&pool);
    CHECK(backing && head && rte_pktmbuf_append(backing, 2) && rte_pktmbuf_append(head, 3));
    memcpy(rte_pktmbuf_mtod(backing, void *), "de", 2);
    memcpy(rte_pktmbuf_mtod(head, void *), "abc", 3);
    indirect = rte_pktmbuf_clone(backing, pool.mbufs);
    CHECK(indirect && !RTE_MBUF_DIRECT(indirect));
    CHECK(rte_pktmbuf_chain(head, indirect) == 0);
    result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == -ENOTSUP);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && head->next == indirect && head->pkt_len == 5);
    CHECK(rte_mbuf_refcnt_read(backing) == 2 && rte_mbuf_refcnt_read(indirect) == 1);
    ker_packet_free(head);
    CHECK(rte_mbuf_refcnt_read(backing) == 1);
    ker_packet_free(backing);
    check_pool(31);

    head = ker_packet_alloc(&pool);
    CHECK(head && rte_pktmbuf_append(head, 3));
    memcpy(rte_pktmbuf_mtod(head, void *), "abc", 3);
    void *external_buffer = NULL;
    struct rte_mbuf *external = external_packet(&external_buffer);
    CHECK(rte_pktmbuf_chain(head, external) == 0);
    unsigned int frees_before = extbuf_frees;
    result = (struct sk_buff *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&ctx, head, 64, &result) == -ENOTSUP);
    CHECK(result == (struct sk_buff *)(uintptr_t)1 && head->next == external && head->pkt_len == 7);
    CHECK(RTE_MBUF_HAS_EXTBUF(external) && memcmp(rte_pktmbuf_mtod(external, const void *), "ext!", 4) == 0);
    ker_packet_free(head);
    CHECK(extbuf_frees == frees_before + 1);
    check_pool(31);
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_skb_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&ctx, &pool, "ker_skb_descriptors") == 0);
    test_geometry_and_operations();
    test_clone_and_descriptor_refs();
    test_headerless_references();
    test_cow_and_export();
    test_exhaustion_and_rollback();
    test_rx_and_rejection();
    test_external_backing_rejection();
    test_rx_metadata_boundary();
    test_mbuf_chain_copy();
    test_foreign_backing();
    CHECK(ctx.live == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_skb_context_cleanup(&ctx) == 0);
    CHECK(ker_memory_live_allocations() == 0 && ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("skb: native Linux layout, dataref/headerless refs, DPDK backing, COW and rollback passed");
    return 0;
}
