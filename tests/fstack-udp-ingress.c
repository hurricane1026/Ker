#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/udp-packet-view.h"
#include "runtime/memory.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char host_mac[6] = {2, 0x21, 0x31, 0x41, 0x51, 0x61};
static const unsigned char source_ip[4] = {192, 0, 2, 1};
static const unsigned char destination_ip[4] = {198, 51, 100, 2};

static uint16_t reference_checksum(const unsigned char *data, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = (uint16_t)data[i] << 8;
        if (i + 1 < length) word |= data[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t reference_udp_checksum(const unsigned char *ip,
    const unsigned char *udp, unsigned int udp_length)
{
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = 17;
    pseudo[10] = (unsigned char)(udp_length >> 8); pseudo[11] = (unsigned char)udp_length;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
    for (unsigned int i = 0; i < udp_length; i += 2) {
        uint16_t word = (uint16_t)udp[i] << 8;
        if (i + 1 < udp_length) word |= udp[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t checksum = (uint16_t)~sum;
    return checksum ? checksum : UINT16_MAX;
}

static void repair_ip_checksum(unsigned char *ip, unsigned int ihl)
{
    ip[10] = 0; ip[11] = 0;
    uint16_t checksum = reference_checksum(ip, ihl * 4);
    ip[10] = (unsigned char)(checksum >> 8); ip[11] = (unsigned char)checksum;
}

static void build_frame(unsigned char frame[60], unsigned int udp_length,
    uint16_t destination_port, bool zero_checksum)
{
    memset(frame, 0, 60);
    memcpy(frame, host_mac, 6); memcpy(frame + 6, host_mac, 6);
    uint16_t type = rte_cpu_to_be_16(ETH_P_IP); memcpy(frame + 12, &type, 2);
    unsigned char *ip = frame + ETH_HLEN;
    unsigned int ihl = 6;
    unsigned int ip_length = ihl * 4 + udp_length;
    ip[0] = 0x46;
    ip[2] = (unsigned char)(ip_length >> 8); ip[3] = (unsigned char)ip_length;
    ip[6] = 0x40; /* DF is permitted; MF/offset are rejected by this profile. */
    ip[8] = 64; ip[9] = 17;
    memcpy(ip + 12, source_ip, sizeof(source_ip));
    memcpy(ip + 16, destination_ip, sizeof(destination_ip));
    ip[20] = 1; ip[21] = 1; ip[22] = 0; ip[23] = 0; /* NOP,NOP,EOL,pad */
    unsigned char *udp = ip + ihl * 4;
    udp[0] = 0x12; udp[1] = 0x34;
    udp[2] = (unsigned char)(destination_port >> 8); udp[3] = (unsigned char)destination_port;
    udp[4] = (unsigned char)(udp_length >> 8); udp[5] = (unsigned char)udp_length;
    if (udp_length > 8)
        for (unsigned int i = 8; i < udp_length; ++i) udp[i] = (unsigned char)(i * 13 + 7);
    if (!zero_checksum) {
        uint16_t checksum = reference_udp_checksum(ip, udp, udp_length);
        udp[6] = (unsigned char)(checksum >> 8); udp[7] = (unsigned char)checksum;
    }
    repair_ip_checksum(ip, ihl);
}

static struct rte_mbuf *make_chain(const unsigned char frame[60])
{
    const unsigned int chunks[] = {13, 2, 5, 1, 2, 37};
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0;
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool);
        CHECK(segment != NULL);
        if (chunks[i]) {
            unsigned char *out = (unsigned char *)rte_pktmbuf_append(segment, chunks[i]);
            CHECK(out != NULL);
            memcpy(out, frame + offset, chunks[i]);
        }
        offset += chunks[i];
        if (!head) head = segment;
        else CHECK(rte_pktmbuf_chain(head, segment) == 0);
    }
    CHECK(offset == 60 && head->pkt_len == 60 && head->nb_segs == 6);
    return head;
}

static struct sk_buff *classify_copy(struct rte_mbuf *chain)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, 128, &skb) == 0);
    CHECK(skb && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    return skb;
}

static void sentinel_check(const struct ker_udp_packet_view *view)
{
    CHECK(view->header == (const unsigned char *)(uintptr_t)1);
    CHECK(view->payload == (const unsigned char *)(uintptr_t)2);
    CHECK(view->source_port == 0x1234 && view->destination_port == 0x5678);
    CHECK(view->checksum == 0x9abc && view->udp_length == 0x1234 && view->payload_length == 0x5678);
}

static void reject_unchanged(struct ker_skb_context *owner, struct sk_buff *skb,
    int expected, const struct ker_udp_packet_view *sentinel)
{
    unsigned char before[64];
    CHECK(skb->len <= sizeof(before));
    memcpy(before, skb->data, skb->len);
    struct ker_udp_packet_view output = *sentinel;
    CHECK(ker_udp_packet_view_init(owner, skb, &output) == expected);
    sentinel_check(&output);
    CHECK(!memcmp(skb->data, before, skb->len));
}

static void valid_odd_checksum_and_lifetimes(void)
{
    unsigned char frame[60], expected[60];
    build_frame(frame, 9, 0x5678, false);
    memcpy(expected, frame, sizeof(expected));
    const unsigned int udp_offset = ETH_HLEN + 24;
    CHECK(frame[udp_offset + 6] || frame[udp_offset + 7]);
    const unsigned int checksum = ((unsigned int)frame[udp_offset + 6] << 8) | frame[udp_offset + 7];
    CHECK(checksum == 0x3bf8); /* Independent pseudoheader vector for this odd-length datagram. */
    struct rte_mbuf *chain = make_chain(frame);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_udp_packet_view view = {0};
    CHECK(ker_udp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.header == skb->data + 24 && view.payload == view.header + 8);
    CHECK(view.source_port == rte_cpu_to_be_16(0x1234));
    CHECK(view.destination_port == rte_cpu_to_be_16(0x5678));
    CHECK(view.checksum == rte_cpu_to_be_16(checksum));
    CHECK(view.udp_length == 9 && view.payload_length == 1 && view.payload[0] == expected[udp_offset + 8]);
    CHECK(skb->len == 46 && view.udp_length < skb->len - 24); /* Ethernet padding excluded. */
    ker_packet_free(chain);
    CHECK(!memcmp(view.header, expected + ETH_HLEN + 24, view.udp_length));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
}

static void checksum_omission_mangled_zero_and_failures(void)
{
    unsigned char frame[60], original_frame[60], saved[60], scratch[60];
    struct ker_udp_packet_view sentinel = {
        (const unsigned char *)(uintptr_t)1, (const unsigned char *)(uintptr_t)2,
        0x1234, 0x5678, 0x9abc, 0x1234, 0x5678
    };
    struct ker_udp_packet_view view;
    build_frame(frame, 9, 0x5678, true);
    memcpy(original_frame, frame, sizeof(frame));
    struct rte_mbuf *chain = make_chain(frame);
    struct sk_buff *skb = classify_copy(chain);
    view = sentinel;
    CHECK(ker_udp_packet_view_init(&context, skb, &view) == 0 && view.checksum == 0);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(rte_pktmbuf_read(chain, 0, sizeof(scratch), scratch) == scratch);
    CHECK(!memcmp(scratch, original_frame, sizeof(original_frame)));
    ker_packet_free(chain);

    build_frame(frame, 9, 0xa770, true);
    frame[ETH_HLEN + 24 + 8] = 0x5a;
    /* This independent pseudo-header vector folds to zero, encoded as 0xffff. */
    CHECK(reference_udp_checksum(frame + ETH_HLEN, frame + ETH_HLEN + 24, 9) == UINT16_MAX);
    frame[ETH_HLEN + 24 + 6] = 0xff; frame[ETH_HLEN + 24 + 7] = 0xff;
    chain = make_chain(frame); skb = classify_copy(chain);
    view = sentinel;
    CHECK(ker_udp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.checksum == UINT16_MAX && view.destination_port == rte_cpu_to_be_16(0xa770));
    CHECK(ker_skb_free(skb) == 0); ker_packet_free(chain);

    build_frame(frame, 9, 0x5678, false);
    memcpy(original_frame, frame, sizeof(frame));
    chain = make_chain(frame); skb = classify_copy(chain);
    memcpy(saved, skb->data, skb->len);
    view = sentinel;
    struct ker_skb_context foreign = {0};
    reject_unchanged(&foreign, skb, -EXDEV, &sentinel);
    CHECK(ker_skb_get(skb) == 0);
    reject_unchanged(&context, skb, -EBUSY, &sentinel);
    CHECK(ker_skb_free(skb) == 0);
    skb->data[24 + 8] ^= 1;
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* RX metadata never bypasses software verification. */
    reject_unchanged(&context, skb, -EBADMSG, &sentinel);
    skb->ip_summed = CHECKSUM_NONE;
    memcpy(skb->data, saved, skb->len);
    skb->data[12] ^= 1; /* Change IP pseudoheader source, then repair only IP header checksum. */
    repair_ip_checksum(skb->data, 6);
    view = sentinel;
    reject_unchanged(&context, skb, -EBADMSG, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[24 + 4] = 0; skb->data[24 + 5] = 7;
    view = sentinel;
    reject_unchanged(&context, skb, -EINVAL, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[24 + 4] = 0; skb->data[24 + 5] = 10;
    view = sentinel;
    reject_unchanged(&context, skb, -EINVAL, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[24 + 4] = 0; skb->data[24 + 5] = 8; /* Shorter than IP payload, but >= UDP header. */
    view = sentinel;
    reject_unchanged(&context, skb, -EINVAL, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[2] = 0; skb->data[3] = 31; repair_ip_checksum(skb->data, 6); /* IPv4 payload < UDP header. */
    view = sentinel;
    reject_unchanged(&context, skb, -EMSGSIZE, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[9] = 6; repair_ip_checksum(skb->data, 6);
    view = sentinel;
    reject_unchanged(&context, skb, -EPROTONOSUPPORT, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[6] = 0x60; skb->data[7] = 0; repair_ip_checksum(skb->data, 6); /* MF */
    view = sentinel;
    reject_unchanged(&context, skb, -ENOTSUP, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[6] = 0; skb->data[7] = 1; repair_ip_checksum(skb->data, 6); /* Nonzero offset */
    view = sentinel;
    reject_unchanged(&context, skb, -ENOTSUP, &sentinel);
    memcpy(skb->data, saved, skb->len);
    skb->data[6] = 0x40; skb->data[7] = 0; repair_ip_checksum(skb->data, 6); /* DF allowed */
    view = sentinel;
    CHECK(ker_udp_packet_view_init(&context, skb, &view) == 0);
    memcpy(scratch, skb->data, skb->len);
    CHECK(view.udp_length == 9);
    CHECK(!memcmp(skb->data, saved, skb->len));
    CHECK(rte_pktmbuf_read(chain, 0, sizeof(frame), scratch) == scratch);
    CHECK(!memcmp(scratch, original_frame, sizeof(original_frame)) && rte_mbuf_refcnt_read(chain) == 1);
    CHECK(ker_skb_free(skb) == 0); ker_packet_free(chain);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
    (void)scratch;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_udp_ingress", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ker_udp_ingress_desc") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, host_mac) == 0);
    valid_odd_checksum_and_lifetimes();
    checksum_omission_mangled_zero_and_failures();
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("UDP ingress view: segmented pseudo-header checksum and ownership boundaries passed");
    return 0;
}
