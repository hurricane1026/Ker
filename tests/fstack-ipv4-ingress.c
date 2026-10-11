#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/ipv4-packet-view.h"
#include "runtime/memory.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char host_mac[6] = {2, 0x10, 0x20, 0x30, 0x40, 0x50};

static void check_sentinel(const struct ker_ipv4_packet_view *view)
{
    CHECK(view->header == (const unsigned char *)(uintptr_t)1);
    CHECK(view->header_length == 11 && view->packet_length == 12 &&
        view->payload_length == 13 && view->frag_off == 14);
}

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

static void make_ipv4(unsigned char *ip, unsigned int ihl, unsigned int total)
{
    memset(ip, 0, total);
    ip[0] = (unsigned char)(0x40 | ihl);
    ip[2] = (unsigned char)(total >> 8); ip[3] = (unsigned char)total;
    ip[4] = 0x12; ip[5] = 0x34; ip[6] = 0x20; ip[7] = 0x01;
    ip[8] = 64; ip[9] = 17;
    ip[12] = 192; ip[13] = 0; ip[14] = 2; ip[15] = 1;
    ip[16] = 198; ip[17] = 51; ip[18] = 100; ip[19] = 2;
    if (ihl > 5) { ip[20] = 1; ip[21] = 1; ip[22] = 0; ip[23] = 0; }
    for (unsigned int i = ihl * 4; i < total; ++i) ip[i] = (unsigned char)(i * 7 + 3);
    uint16_t checksum = reference_checksum(ip, ihl * 4);
    ip[10] = (unsigned char)(checksum >> 8); ip[11] = (unsigned char)checksum;
}

static struct rte_mbuf *make_chain(const unsigned char *bytes, unsigned int length,
    const unsigned int *chunks, unsigned int count)
{
    struct rte_mbuf *head = NULL, *tail = NULL;
    unsigned int offset = 0;
    for (unsigned int i = 0; i < count; ++i) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool);
        CHECK(segment != NULL);
        if (chunks[i]) {
            unsigned char *dst = (unsigned char *)rte_pktmbuf_append(segment, chunks[i]);
            CHECK(dst != NULL);
            memcpy(dst, bytes + offset, chunks[i]);
        }
        offset += chunks[i];
        if (!head) head = segment;
        else CHECK(rte_pktmbuf_chain(head, segment) == 0);
        tail = segment;
    }
    (void)tail;
    CHECK(offset == length && head && head->pkt_len == length);
    return head;
}

static struct sk_buff *classify_copy(struct rte_mbuf *chain)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, 128, &skb) == 0);
    CHECK(skb && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    CHECK(skb->network_header == skb_headroom(skb) && skb->head + skb->network_header == skb->data);
    return skb;
}

static void valid_options_padding_and_fragments(void)
{
    unsigned char frame[64] = {0};
    memcpy(frame, host_mac, 6); memcpy(frame + 6, host_mac, 6);
    uint16_t type = rte_cpu_to_be_16(ETH_P_IP); memcpy(frame + 12, &type, 2);
    make_ipv4(frame + ETH_HLEN, 6, 33);
    const unsigned int chunks[] = {5, 8, 1, 6, 9, 2, 29};
    struct rte_mbuf *chain = make_chain(frame, 60, chunks, 7);
    unsigned int refs = rte_mbuf_refcnt_read(chain);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_ipv4_packet_view view = {0};
    CHECK(ker_ipv4_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.header == skb->data && view.header_length == 24);
    CHECK(view.packet_length == 33 && view.payload_length == 9);
    uint16_t frag; memcpy(&frag, skb->data + 6, sizeof(frag));
    CHECK(view.frag_off == frag && view.frag_off == rte_cpu_to_be_16(0x2001));
    CHECK(skb->len == 46 && skb->data[33] == 0); /* Ethernet padding remains present. */
    CHECK(rte_mbuf_refcnt_read(chain) == refs && chain->pkt_len == 60);
    unsigned char source_copy[60];
    CHECK(rte_pktmbuf_read(chain, 0, sizeof(source_copy), source_copy) == source_copy);
    CHECK(!memcmp(source_copy, frame, sizeof(source_copy)));
    ker_packet_free(chain);
    CHECK(view.header == skb->data && !memcmp(view.header, frame + ETH_HLEN, view.packet_length));
    CHECK(ker_skb_free(skb) == 0);
}

static void rejection_preserves_output_and_skb(void)
{
    unsigned char frame[60] = {0}, saved[60];
    memcpy(frame, host_mac, 6); memcpy(frame + 6, host_mac, 6);
    uint16_t type = rte_cpu_to_be_16(ETH_P_IP); memcpy(frame + 12, &type, 2);
    make_ipv4(frame + ETH_HLEN, 5, 28);
    const unsigned int chunks[] = {7, 13, 20, 20};
    struct rte_mbuf *chain = make_chain(frame, sizeof(frame), chunks, 4);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_ipv4_packet_view sentinel = {(const unsigned char *)(uintptr_t)1, 11, 12, 13, 14};
    struct ker_ipv4_packet_view output;

    memcpy(saved, skb->data, skb->len);
    skb->data[0] = (unsigned char)((skb->data[0] & 0x0f) | 0x60);
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EINVAL);
    check_sentinel(&output);
    skb->data[0] = saved[0];
    skb->data[0] = (unsigned char)((skb->data[0] & 0xf0) | 4);
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EINVAL);
    check_sentinel(&output);
    skb->data[0] = saved[0];
    skb->data[2] = 0; skb->data[3] = 19;
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EINVAL);
    check_sentinel(&output);
    skb->data[2] = 0; skb->data[3] = 47;
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EMSGSIZE);
    check_sentinel(&output);
    memcpy(skb->data, saved, skb->len);
    skb->data[8] ^= 1; /* Corrupt a checksummed header byte. */
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EBADMSG);
    check_sentinel(&output);
    memcpy(skb->data, saved, skb->len);
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == 0);
    CHECK(!memcmp(skb->data, saved, skb->len) && skb->len == sizeof(saved) - ETH_HLEN);
    CHECK(rte_mbuf_refcnt_read(chain) == 1 && chain->pkt_len == sizeof(frame));
    CHECK(ker_skb_get(skb) == 0);
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EBUSY);
    check_sentinel(&output);
    CHECK(!memcmp(skb->data, saved, skb->len) && ker_skb_free(skb) == 0);
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(skb, &clone) == 0 && clone);
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EBUSY);
    check_sentinel(&output);
    CHECK(ker_skb_free(clone) == 0);
    struct ker_skb_context foreign_context = {0};
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&foreign_context, skb, &output) == -EXDEV);
    check_sentinel(&output);
    uint16_t protocol = skb->protocol;
    skb->protocol = rte_cpu_to_be_16(ETH_P_ARP);
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EPROTONOSUPPORT);
    check_sentinel(&output);
    skb->protocol = protocol;
    uint16_t network_header = skb->network_header;
    skb->network_header++;
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EINVAL);
    check_sentinel(&output);
    skb->network_header = network_header;
    skb->data[0] = 0x4f; /* Claimed options exceed available IPv4 bytes. */
    output = sentinel;
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EMSGSIZE);
    check_sentinel(&output);
    memcpy(skb->data, saved, skb->len);
    CHECK(ker_ipv4_packet_view_init(NULL, skb, &output) == -EINVAL);
    CHECK(ker_ipv4_packet_view_init(&context, skb, NULL) == -EINVAL);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(chain);
}

static void truncated_base_header(void)
{
    unsigned char frame[ETH_HLEN + 19] = {0}, source[ETH_HLEN + 19];
    memcpy(frame, host_mac, 6); memcpy(frame + 6, host_mac, 6);
    uint16_t type = rte_cpu_to_be_16(ETH_P_IP); memcpy(frame + 12, &type, 2);
    frame[ETH_HLEN] = 0x45;
    frame[ETH_HLEN + 2] = 0; frame[ETH_HLEN + 3] = 19;
    const unsigned int chunks[] = {15, 9, 9};
    struct rte_mbuf *chain = make_chain(frame, sizeof(frame), chunks, 3);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_ipv4_packet_view sentinel = {(const unsigned char *)(uintptr_t)1, 11, 12, 13, 14};
    struct ker_ipv4_packet_view output = sentinel;
    CHECK(skb->len == 19);
    CHECK(ker_ipv4_packet_view_init(&context, skb, &output) == -EMSGSIZE);
    check_sentinel(&output);
    CHECK(rte_pktmbuf_read(chain, 0, sizeof(source), source) == source);
    CHECK(!memcmp(source, frame, sizeof(source)) && rte_mbuf_refcnt_read(chain) == 1);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(chain);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_ipv4_ingress", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ker_ipv4_ingress_desc") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, host_mac) == 0);
    valid_options_padding_and_fragments();
    rejection_preserves_output_and_skb();
    truncated_base_header();
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("IPv4 ingress view: segmented header validation, checksum and ownership boundaries passed");
    return 0;
}
