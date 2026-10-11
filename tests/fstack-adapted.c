/* Scenario adaptations from F-Stack tests at the revision recorded in
 * fstack-provenance.json. Ker-specific implementation and assertions; no ff_*
 * glue, FreeBSD implementation, mocks or upstream harness code are compiled. */
#include "check.h"
#include "eal.h"
#include "runtime/skb-queue.h"
#include "runtime/memory.h"
#include "runtime/timer.h"
#include "runtime/ethernet.h"
#include "runtime/receive.h"
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_skb_queue first, second;
static struct ker_eth_device ethernet_device;
static struct ker_receive_runtime ethernet_receiver;
static struct ker_protocol_handler ethernet_handler;
static unsigned int ethernet_deliveries;
static struct sk_buff *packet(unsigned int length)
{
    struct sk_buff *skb = NULL; unsigned char *bytes;
    CHECK(ker_skb_alloc(&context, length, 16, &skb) == 0);
    CHECK(ker_skb_put(skb, length, &bytes) == 0);
    for (unsigned int i = 0; i < length; ++i) bytes[i] = (unsigned char)(i * 17 + 3);
    return skb;
}
static void mbuf_release(void)
{
    unsigned int available = rte_mempool_avail_count(pool.mbufs);
    struct rte_mbuf *mbuf = ker_packet_alloc(&pool); CHECK(mbuf);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available - 1);
    ker_packet_free(mbuf);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
}
static void clock_monotonic(void)
{
    int64_t previous, now;
    CHECK(ker_monotonic_ns(&previous) == 0 && previous >= 0);
    for (unsigned int i = 0; i < 1000; ++i) {
        CHECK(ker_monotonic_ns(&now) == 0 && now >= previous);
        previous = now;
    }
}
static void empty_export(void)
{
    struct sk_buff *skb = packet(0); struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy && copy->pkt_len == 0 && copy->data_len == 0);
    CHECK(!copy->ol_flags && refcount_read(&skb->users) == 1 && context.live == 1);
    ker_packet_free(copy); CHECK(ker_skb_free(skb) == 0);
}
static void null_context(void)
{
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_skb_alloc(NULL, 0, 0, &skb) == -EXDEV && skb == (void *)(uintptr_t)1);
    CHECK(!context.live && rte_mempool_avail_count(pool.mbufs) == 31);
}
static void packet_export(void)
{
    struct sk_buff *skb = packet(64); struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy->pkt_len == 64);
    CHECK(!memcmp(rte_pktmbuf_mtod(copy, const void *), skb->data, 64));
    CHECK(!copy->ol_flags && refcount_read(&skb->users) == 1);
    CHECK(ker_skb_free(skb) == 0);
    /* Copy remains readable after the original backing is returned. */
    const unsigned char *bytes = rte_pktmbuf_mtod(copy, const unsigned char *);
    for (unsigned int i = 0; i < 64; ++i) CHECK(bytes[i] == (unsigned char)(i * 17 + 3));
    ker_packet_free(copy);
}
static void headroom_export(void)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&context, 96, 192, &skb) == 0);
    CHECK(skb_headroom(skb) == 192);
    uint8_t *bytes;
    CHECK(ker_skb_put(skb, 96, &bytes) == 0);
    for (unsigned int i = 0; i < 96; ++i) bytes[i] = (uint8_t)(255 - i);
    struct rte_mbuf *copy = NULL;
    CHECK(ker_skb_to_mbuf(skb, &copy) == 0 && copy);
    CHECK(copy->data_off == 192 && copy->data_len == 96 && copy->pkt_len == 96);
    CHECK(!memcmp(rte_pktmbuf_mtod(copy, const void *), skb->data, 96));
    CHECK(refcount_read(&skb->users) == 1 && context.live == 1);
    CHECK(ker_skb_free(skb) == 0);
    const uint8_t *exported = rte_pktmbuf_mtod(copy, const uint8_t *);
    for (unsigned int i = 0; i < 96; ++i) CHECK(exported[i] == (uint8_t)(255 - i));
    ker_packet_free(copy);
}
static void export_exhaustion_retry(void)
{
    struct sk_buff *skb = packet(64);
    struct rte_mbuf *held[30];
    for (unsigned int i = 0; i < 30; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    struct rte_mbuf *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOMEM && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    for (unsigned int i = 0; i < 64; ++i) CHECK(skb->data[i] == (unsigned char)(i * 17 + 3));
    ker_packet_free(held[0]);
    CHECK(ker_skb_to_mbuf(skb, &output) == 0 && output && output->pkt_len == 64);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), skb->data, 64));
    for (unsigned int i = 1; i < 30; ++i) ker_packet_free(held[i]);
    CHECK(ker_skb_free(skb) == 0);
    /* The remaining allocated copy is released by the caller. */
    CHECK(rte_mempool_avail_count(pool.mbufs) == 30);
    ker_packet_free(output);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
}
static void offload_metadata_rejection(void)
{
    struct sk_buff *skb = packet(64);
    struct rte_mbuf *output = (void *)(uintptr_t)1;
    skb->ip_summed = CHECKSUM_PARTIAL;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    skb->ip_summed = CHECKSUM_NONE;
    skb_shinfo(skb)->gso_size = 1448;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && refcount_read(&skb->users) == 1 && skb->len == 64);
    skb_shinfo(skb)->gso_size = 0;
    CHECK(ker_skb_to_mbuf(skb, &output) == 0 && output && output->pkt_len == 64);
    ker_packet_free(output);
    CHECK(ker_skb_free(skb) == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
}
static struct sk_buff *partial_checksum_packet(bool tcp, unsigned int headroom,
    unsigned char original[43], unsigned int *length)
{
    static const unsigned char udp[] = {
        0x12,0x34,0x56,0x78,0x00,0x0d,0x13,0xa3,0x61,0x62,0x63,0x64,0x65
    };
    static const unsigned char tcp_segment[] = {
        0x12,0x34,0x56,0x78,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
        0x50,0x10,0x00,0x10,0x13,0xa4,0x00,0x00,0x78,0x79,0x7a
    };
    *length = tcp ? 43 : 33;
    memset(original, 0, 43);
    const unsigned char ip[] = {
        0x45,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x40,0x00,0x8e,0x8d,
        0xc0,0x00,0x02,0x01,0xc6,0x33,0x64,0x09
    };
    memcpy(original, ip, sizeof(ip));
    original[2] = (unsigned char)(*length >> 8);
    original[3] = (unsigned char)*length;
    if (tcp) {
        original[9] = 6;
        original[10] = 0x8e; original[11] = 0x8e;
        memcpy(original + 20, tcp_segment, sizeof(tcp_segment));
    } else {
        original[9] = 17;
        memcpy(original + 20, udp, sizeof(udp));
    }
    struct sk_buff *skb = NULL;
    CHECK(ker_skb_alloc(&context, *length, headroom, &skb) == 0);
    unsigned char *data;
    CHECK(ker_skb_put(skb, *length, &data) == 0);
    memcpy(data, original, *length);
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = (uint16_t)(skb_headroom(skb) + 20);
    skb->csum_offset = tcp ? 16 : 6;
    return skb;
}
static void partial_checksum_software_completion(void)
{
    unsigned char original[43], expected[43];
    unsigned int length;
    struct sk_buff *skb = partial_checksum_packet(false, 17, original, &length);
    CHECK(length == 33 && skb->data == skb->head + 17 && ((uintptr_t)skb->data & 1));
    memcpy(expected, original, length);
    expected[26] = 0x59; expected[27] = 0xdc;
    struct rte_mbuf *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == 0);
    CHECK(output && output->pkt_len == length && output->data_len == length && output->data_off == 17);
    CHECK(output->ol_flags == 0 && !memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    CHECK(context.live == 1 && skb->ip_summed == CHECKSUM_PARTIAL &&
        skb->csum_start == 37 && skb->csum_offset == 6 && !memcmp(skb->data, original, length));
    CHECK(ker_skb_free(skb) == 0);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    ker_packet_free(output);

    skb = partial_checksum_packet(false, 16, original, &length);
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(skb, &clone) == 0 && clone);
    output = (void *)(uintptr_t)1;
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(context.live == 2 && skb->ip_summed == CHECKSUM_PARTIAL && !memcmp(skb->data, original, length));
    CHECK(ker_skb_free(clone) == 0);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == 0 && output);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    ker_packet_free(output);
    CHECK(ker_skb_free(skb) == 0);

    skb = partial_checksum_packet(false, 18, original, &length);
    unsigned int start = skb->csum_start, offset = skb->csum_offset;
    output = (void *)(uintptr_t)1;
    skb->csum_start = (uint16_t)(skb_headroom(skb) - 1);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -EINVAL && output == (void *)(uintptr_t)1);
    skb->csum_start = (uint16_t)(skb_headroom(skb) + skb->len);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -EINVAL && output == (void *)(uintptr_t)1);
    skb->csum_start = (uint16_t)start; skb->csum_offset = UINT16_MAX;
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -EINVAL && output == (void *)(uintptr_t)1);
    skb->csum_offset = (uint16_t)offset; skb_shinfo(skb)->gso_size = 1448;
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    skb_shinfo(skb)->gso_size = 0;
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
    skb->csum_not_inet = 1;
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    skb->csum_not_inet = 0;
#endif
    CHECK(context.live == 1 && skb->ip_summed == CHECKSUM_PARTIAL && skb->csum_start == start &&
        skb->csum_offset == offset && !memcmp(skb->data, original, length));
    struct rte_mbuf *held[30];
    for (unsigned int i = 0; i < 30; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == -ENOMEM && output == (void *)(uintptr_t)1);
    CHECK(context.live == 1 && skb->ip_summed == CHECKSUM_PARTIAL && !memcmp(skb->data, original, length));
    ker_packet_free(held[0]);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == 0 && output && output->pkt_len == length);
    for (unsigned int i = 1; i < 30; ++i) ker_packet_free(held[i]);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(output);

    skb = partial_checksum_packet(true, 18, original, &length);
    memcpy(expected, original, length);
    expected[36] = 0x41; expected[37] = 0x14;
    CHECK(length == 43 && skb->csum_start == 38 && skb->csum_offset == 16);
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == 0 && output && output->pkt_len == length);
    CHECK(output->ol_flags == 0 && !memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    CHECK(skb->ip_summed == CHECKSUM_PARTIAL && !memcmp(skb->data, original, length));
    ker_packet_free(output);
    CHECK(!memcmp(skb->data, original, length));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);

    /* This valid UDP seed/payload folds to zero; Linux maps that wire value
     * to CSUM_MANGLED_0 (0xffff) so the checksum is not mistaken for absent. */
    skb = partial_checksum_packet(false, 18, original, &length);
    skb->data[28] = original[28] = 0xbb;
    skb->data[29] = original[29] = 0x3e;
    memcpy(expected, original, length);
    expected[26] = 0xff; expected[27] = 0xff;
    CHECK(ker_skb_to_mbuf_software_checksum(skb, &output) == 0 && output);
    CHECK(!memcmp(rte_pktmbuf_mtod(output, const void *), expected, length));
    ker_packet_free(output);
    CHECK(!memcmp(skb->data, original, length) && skb->ip_summed == CHECKSUM_PARTIAL);
    CHECK(ker_skb_free(skb) == 0 && context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
}
static void multiseg_boundary(void)
{
    struct rte_mbuf *a = ker_packet_alloc(&pool), *b = ker_packet_alloc(&pool); CHECK(a && b);
    CHECK(rte_pktmbuf_append(a, 16) && rte_pktmbuf_append(b, 16));
    CHECK(rte_pktmbuf_chain(a, b) == 0);
    struct sk_buff *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_from_mbuf(&context, a, &output) == -ENOTSUP && output == (void *)(uintptr_t)1);
    CHECK(a->next == b && a->nb_segs == 2 && a->pkt_len == 32);
    CHECK(rte_mbuf_refcnt_read(a) == 1 && rte_mbuf_refcnt_read(b) == 1);
    ker_packet_free(a); /* Ker refuses adoption; caller still owns the chain. */
}
static void multiseg_copy(void)
{
    struct rte_mbuf *a = ker_packet_alloc(&pool), *b = ker_packet_alloc(&pool), *c = ker_packet_alloc(&pool);
    CHECK(a && b && c);
    CHECK(rte_pktmbuf_append(a, 5) && rte_pktmbuf_append(b, 0) && rte_pktmbuf_append(c, 7));
    memcpy(rte_pktmbuf_mtod(a, void *), "first", 5);
    memcpy(rte_pktmbuf_mtod(c, void *), "payload", 7);
    CHECK(rte_pktmbuf_chain(b, c) == 0 && rte_pktmbuf_chain(a, b) == 0);
    b->ol_flags = RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_IP_CKSUM_NONE;
    CHECK(a->nb_segs == 3 && a->pkt_len == 12 && a->next == b && b->nb_segs == 2 && b->next == c && !c->next);
    struct rte_mbuf *identity_b = a->next, *identity_c = b->next;
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_skb_copy_from_mbuf_chain(&context, a, 192, &skb) == 0 && skb != (void *)(uintptr_t)1);
    CHECK(skb->len == 12 && skb_headroom(skb) == 192 && !memcmp(skb->data, "firstpayload", 12));
    CHECK(a->nb_segs == 3 && a->pkt_len == 12 && a->next == identity_b && b->nb_segs == 2 && b->next == identity_c);
    CHECK(b->ol_flags == (RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_IP_CKSUM_NONE));
    CHECK(rte_mbuf_refcnt_read(a) == 1 && rte_mbuf_refcnt_read(b) == 1 && rte_mbuf_refcnt_read(c) == 1);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(a->next == identity_b && b->next == identity_c && a->pkt_len == 12);
    CHECK(!memcmp(rte_pktmbuf_mtod(a, const void *), "first", 5));
    CHECK(!memcmp(rte_pktmbuf_mtod(c, const void *), "payload", 7));
    skb = NULL;
    CHECK(ker_skb_copy_from_mbuf_chain(&context, a, 192, &skb) == 0 && skb);
    ker_packet_free(a);
    CHECK(!memcmp(skb->data, "firstpayload", 12));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31);
}
static struct rte_mbuf *ethernet_chain(const unsigned char destination[ETH_ALEN],
    uint16_t protocol, unsigned int frame_length, struct rte_mbuf *segments[6])
{
    static const unsigned int sizes[6] = {5, 0, 4, 3, 2, 4};
    unsigned char frame[ETH_HLEN + 4] = {0};
    CHECK(frame_length <= sizeof(frame));
    memcpy(frame, destination, ETH_ALEN);
    const unsigned char source[ETH_ALEN] = {2, 9, 8, 7, 6, 5};
    memcpy(frame + ETH_ALEN, source, ETH_ALEN);
    __be16 network_protocol = rte_cpu_to_be_16(protocol);
    memcpy(frame + 12, &network_protocol, sizeof(network_protocol));
    memset(frame + ETH_HLEN, 0x42, sizeof(frame) - ETH_HLEN);
    unsigned int offset = 0;
    for (unsigned int i = 0; i < 6; ++i) {
        segments[i] = ker_packet_alloc(&pool);
        CHECK(segments[i]);
        unsigned int length = sizes[i];
        if (offset + length > frame_length) length = frame_length - offset;
        unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(segments[i], length);
        CHECK(length == 0 || bytes);
        if (length) memcpy(bytes, frame + offset, length);
        offset += length;
    }
    CHECK(offset == frame_length);
    CHECK(rte_pktmbuf_chain(segments[4], segments[5]) == 0);
    CHECK(rte_pktmbuf_chain(segments[2], segments[3]) == 0);
    CHECK(rte_pktmbuf_chain(segments[0], segments[1]) == 0);
    CHECK(rte_pktmbuf_chain(segments[0], segments[2]) == 0);
    CHECK(rte_pktmbuf_chain(segments[0], segments[4]) == 0);
    return segments[0];
}
static void check_ethernet_chain(struct rte_mbuf *chain, unsigned int length,
    struct rte_mbuf *segments[6])
{
    CHECK(chain == segments[0] && chain->nb_segs == 6 && chain->pkt_len == length);
    CHECK(segments[0]->next == segments[1] && segments[1]->next == segments[2]);
    CHECK(segments[2]->next == segments[3] && segments[3]->next == segments[4]);
    CHECK(segments[4]->next == segments[5] && !segments[5]->next);
    for (unsigned int i = 0; i < 6; ++i) CHECK(rte_mbuf_refcnt_read(segments[i]) == 1);
}
static int ethernet_chain_receive(struct sk_buff *skb, struct ker_protocol_handler *handler,
    struct net_device *original, void *arg)
{
    (void)handler; (void)arg;
    CHECK(original == ethernet_device.native && skb->dev == original);
    CHECK(skb->protocol == rte_cpu_to_be_16(ETH_P_IP) && skb->pkt_type == PACKET_HOST);
    CHECK(skb->mac_len == ETH_HLEN && skb->len == 4);
    CHECK(skb_mac_header(skb) == skb->data - ETH_HLEN);
    CHECK(skb->head + skb->network_header == skb->data);
    CHECK(memcmp(skb->data, "BBBB", 4) == 0);
    ++ethernet_deliveries;
    CHECK(ker_skb_free(skb) == 0);
    return NET_RX_SUCCESS;
}
static void multiseg_ethernet_ingress(void)
{
    const unsigned char host[ETH_ALEN] = {2, 1, 2, 3, 4, 5};
    const unsigned char broadcast[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
    const unsigned char other[ETH_ALEN] = {2, 7, 8, 9, 10, 11};
    CHECK(ker_eth_device_init(&ethernet_device, &context, "eth-chain", 7, host) == 0);
    CHECK(ker_receive_runtime_init(&ethernet_receiver, &context) == 0);
    CHECK(ker_protocol_register(&ethernet_receiver, &ethernet_handler, &ethernet_device,
        rte_cpu_to_be_16(ETH_P_IP), ethernet_chain_receive, NULL) == 0);

    struct rte_mbuf *segments[6];
    struct rte_mbuf *chain = ethernet_chain(host, ETH_P_IP, ETH_HLEN + 4, segments);
    /* Source segment starts need not satisfy Linux's destination alignment. */
    for (unsigned int i = 0; i < 6; ++i) {
        unsigned char *data = rte_pktmbuf_mtod(segments[i], unsigned char *);
        memmove(data + 1, data, segments[i]->data_len);
        ++segments[i]->data_off;
        CHECK(((uintptr_t)rte_pktmbuf_mtod(segments[i], void *) & 1) == 1);
    }
    segments[2]->ol_flags = RTE_MBUF_F_RX_VLAN_STRIPPED;
    ++chain->pkt_len;
    struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -EINVAL);
    CHECK(skb == (void *)(uintptr_t)1 && context.live == 0);
    --chain->pkt_len;
    check_ethernet_chain(chain, ETH_HLEN + 4, segments);
    struct rte_mbuf *held[25];
    for (unsigned int i = 0; i < 25; ++i) { held[i] = ker_packet_alloc(&pool); CHECK(held[i]); }
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 193, &skb) == -EINVAL);
    CHECK(skb == (void *)(uintptr_t)1);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -ENOMEM);
    CHECK(skb == (void *)(uintptr_t)1 && context.live == 0);
    check_ethernet_chain(chain, ETH_HLEN + 4, segments);
    CHECK(segments[2]->ol_flags == RTE_MBUF_F_RX_VLAN_STRIPPED);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, NULL) == -EINVAL);
    struct ker_skb_context wrong_context = context;
    ++wrong_context.lcore;
    ethernet_device.context = &wrong_context;
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -EXDEV);
    ethernet_device.context = &context;
    unsigned int saved_addr_len = ethernet_device.native->addr_len;
    ethernet_device.native->addr_len = ETH_ALEN - 1;
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -ENOTSUP);
    ethernet_device.native->addr_len = saved_addr_len;
    CHECK(skb == (void *)(uintptr_t)1);
    ker_packet_free(held[0]);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == 0 && skb);
    CHECK(skb->dev == ethernet_device.native && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(skb->pkt_type == PACKET_HOST && skb->mac_len == ETH_HLEN && skb->len == 4);
    CHECK(skb_mac_header(skb) == skb->data - ETH_HLEN && skb->head + skb->network_header == skb->data);
    check_ethernet_chain(chain, ETH_HLEN + 4, segments);
    struct ker_receive_result dispatched;
    CHECK(ker_receive_dispatch(&ethernet_receiver, &ethernet_device, &skb, &dispatched) == 0);
    CHECK(!skb && dispatched.handlers == 1 && dispatched.status == NET_RX_SUCCESS && ethernet_deliveries == 1);
    check_ethernet_chain(chain, ETH_HLEN + 4, segments);
    unsigned char flattened[ETH_HLEN + 4];
    unsigned char expected_frame[ETH_HLEN + 4] = {0};
    memcpy(expected_frame, host, ETH_ALEN);
    const unsigned char expected_source[ETH_ALEN] = {2, 9, 8, 7, 6, 5};
    memcpy(expected_frame + ETH_ALEN, expected_source, ETH_ALEN);
    __be16 expected_ip = rte_cpu_to_be_16(ETH_P_IP);
    memcpy(expected_frame + 12, &expected_ip, sizeof(expected_ip));
    memset(expected_frame + ETH_HLEN, 0x42, sizeof(expected_frame) - ETH_HLEN);
    const void *frame_bytes = rte_pktmbuf_read(chain, 0, sizeof(flattened), flattened);
    CHECK(frame_bytes);
    if (frame_bytes != flattened) memcpy(flattened, frame_bytes, sizeof(flattened));
    CHECK(!memcmp(flattened, expected_frame, sizeof(expected_frame)));
    for (unsigned int i = 1; i < 25; ++i) ker_packet_free(held[i]);
    ker_packet_free(chain);

    /* Source release before skb inspection is independent of skb ownership. */
    chain = ethernet_chain(broadcast, ETH_P_ARP, ETH_HLEN + 4, segments);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == 0);
    CHECK(skb->pkt_type == PACKET_BROADCAST && skb->protocol == rte_cpu_to_be_16(ETH_P_ARP));
    ker_packet_free(chain);
    CHECK(skb->dev == ethernet_device.native && skb->len == 4 && skb->data[0] == 0x42);
    CHECK(ker_skb_free(skb) == 0);

    chain = ethernet_chain(host, ETH_P_IP, ETH_HLEN, segments);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == 0);
    CHECK(skb->pkt_type == PACKET_HOST && skb->protocol == rte_cpu_to_be_16(ETH_P_IP) && skb->len == 0);
    CHECK(skb->mac_len == ETH_HLEN && skb->head + skb->network_header == skb->data);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(chain);

    chain = ethernet_chain(other, ETH_P_IP, ETH_HLEN + 4, segments);
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == 0);
    CHECK(skb->pkt_type == PACKET_OTHERHOST && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(chain);

    chain = ethernet_chain(host, ETH_P_IP, ETH_HLEN - 1, segments);
    skb = (void *)(uintptr_t)1;
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -EMSGSIZE);
    CHECK(skb == (void *)(uintptr_t)1);
    check_ethernet_chain(chain, ETH_HLEN - 1, segments);
    ker_packet_free(chain);

    chain = ethernet_chain(host, ETH_P_IP, ETH_HLEN + 4, segments);
    segments[0]->ol_flags = RTE_MBUF_F_RX_VLAN_STRIPPED;
    skb = (void *)(uintptr_t)1;
    CHECK(ker_eth_receive_copy_chain(&ethernet_device, chain, 192, &skb) == -ENOTSUP);
    CHECK(skb == (void *)(uintptr_t)1);
    segments[0]->ol_flags = 0;
    check_ethernet_chain(chain, ETH_HLEN + 4, segments);
    ker_packet_free(chain);

    CHECK(ker_protocol_unregister(&ethernet_handler) == 0);
    CHECK(ker_receive_runtime_cleanup(&ethernet_receiver) == 0);
    CHECK(ker_eth_device_cleanup(&ethernet_device) == 0);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
}
static void queue_isolation(void)
{
    struct sk_buff *skb = packet(16), *identity = skb, *output = (void *)(uintptr_t)1;
    CHECK(ker_skb_queue_push(&first, &skb) == 0 && !skb);
    CHECK(first.native.qlen == 1 && !second.native.qlen);
    CHECK(ker_skb_queue_pop(&second, &output) == 0 && output == (void *)(uintptr_t)1);
    CHECK(first.native.qlen == 1 && context.live == 1);
    CHECK(ker_skb_queue_pop(&first, &output) == 1 && output == identity);
    CHECK(refcount_read(&output->users) == 1 && ker_skb_free(output) == 0);
}
static void queue_full_ownership(void)
{
    struct sk_buff *a = packet(16), *b = packet(16), *identity = b;
    CHECK(ker_skb_queue_push(&first, &a) == 0 && !a);
    unsigned int available = rte_mempool_avail_count(pool.mbufs);
    CHECK(ker_skb_queue_push(&first, &b) == -ENOSPC && b == identity);
    CHECK(first.native.qlen == 1 && refcount_read(&b->users) == 1);
    CHECK(rte_mempool_avail_count(pool.mbufs) == available);
    CHECK(ker_skb_free(b) == 0 && rte_mempool_avail_count(pool.mbufs) == available + 1);
    CHECK(ker_skb_queue_purge(&first, 1) == 1 && rte_mempool_avail_count(pool.mbufs) == 31);
}
int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        {"mbuf-release", mbuf_release}, {"clock-monotonic", clock_monotonic},
        {"empty-export", empty_export}, {"null-context", null_context},
        {"packet-export", packet_export}, {"multiseg-boundary", multiseg_boundary},
        {"queue-isolation", queue_isolation}, {"queue-full-ownership", queue_full_ownership},
        {"multiseg-copy", multiseg_copy},
        {"multiseg-ethernet-ingress", multiseg_ethernet_ingress},
        {"headroom-export", headroom_export},
        {"export-exhaustion-retry", export_exhaustion_retry},
        {"offload-metadata-rejection", offload_metadata_rejection},
        {"software-checksum-completion", partial_checksum_software_completion}
    };
    CHECK(argc == 2); void (*run)(void) = NULL;
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (!strcmp(argv[1], cases[i].name)) run = cases[i].run;
    CHECK(run);
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "fstack_adapted_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "fstack_adapted_skb") == 0);
    CHECK(ker_skb_queue_init(&first, &context, 1, SIZE_MAX) == 0);
    CHECK(ker_skb_queue_init(&second, &context, 1, SIZE_MAX) == 0);
    run();
    CHECK(!context.live && !first.bytes && !second.bytes && rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_skb_queue_cleanup(&first) == 0 && ker_skb_queue_cleanup(&second) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    printf("F-Stack scenario adapted to Ker: %s passed\n", argv[1]);
    return 0;
}
