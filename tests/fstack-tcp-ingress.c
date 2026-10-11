#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/tcp-packet-view.h"
#include "runtime/memory.h"
#include <errno.h>
#include <string.h>

#define FRAME_LENGTH 128
#define IP_HEADER_LENGTH 24

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char host_mac[6] = {2, 0x21, 0x31, 0x41, 0x51, 0x61};
static const unsigned char source_ip[4] = {192, 0, 2, 1};
static const unsigned char destination_ip[4] = {198, 51, 100, 2};

static uint16_t reference_tcp_checksum(const unsigned char *ip,
    const unsigned char *tcp, unsigned int tcp_length)
{
    unsigned char pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10] = (unsigned char)(tcp_length >> 8);
    pseudo[11] = (unsigned char)tcp_length;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(pseudo); i += 2)
        sum += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
    for (unsigned int i = 0; i < tcp_length; i += 2) {
        uint16_t word = (uint16_t)tcp[i] << 8;
        if (i + 1 < tcp_length)
            word |= tcp[i + 1];
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void repair_ip_checksum(unsigned char *ip)
{
    ip[10] = 0;
    ip[11] = 0;
    uint32_t sum = 0;
    for (unsigned int i = 0; i < IP_HEADER_LENGTH; i += 2)
        sum += ((uint16_t)ip[i] << 8) | ip[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t checksum = (uint16_t)~sum;
    ip[10] = (unsigned char)(checksum >> 8);
    ip[11] = (unsigned char)checksum;
}

static uint16_t set_tcp_checksum(unsigned char *ip, unsigned int header_length,
    unsigned int tcp_length)
{
    unsigned char *tcp = ip + header_length;
    tcp[16] = 0;
    tcp[17] = 0;
    uint16_t checksum = reference_tcp_checksum(ip, tcp, tcp_length);
    tcp[16] = (unsigned char)(checksum >> 8);
    tcp[17] = (unsigned char)checksum;
    return checksum;
}

static void build_frame(unsigned char frame[FRAME_LENGTH], unsigned int tcp_header_length,
    unsigned int payload_length)
{
    memset(frame, 0, FRAME_LENGTH);
    memcpy(frame, host_mac, 6);
    memcpy(frame + 6, host_mac, 6);
    uint16_t type = rte_cpu_to_be_16(ETH_P_IP);
    memcpy(frame + 12, &type, sizeof(type));
    unsigned char *ip = frame + ETH_HLEN;
    unsigned int tcp_length = tcp_header_length + payload_length;
    unsigned int ip_length = IP_HEADER_LENGTH + tcp_length;
    ip[0] = 0x46;
    ip[2] = (unsigned char)(ip_length >> 8);
    ip[3] = (unsigned char)ip_length;
    ip[6] = 0x40; /* DF is allowed; fragment reassembly is outside this view. */
    ip[8] = 64;
    ip[9] = 6;
    memcpy(ip + 12, source_ip, sizeof(source_ip));
    memcpy(ip + 16, destination_ip, sizeof(destination_ip));
    ip[20] = 1; ip[21] = 1; ip[22] = 0; ip[23] = 0;

    unsigned char *tcp = ip + IP_HEADER_LENGTH;
    tcp[0] = 0x12; tcp[1] = 0x34;
    tcp[2] = 0x56; tcp[3] = 0x78;
    tcp[4] = 1; tcp[5] = 2; tcp[6] = 3; tcp[7] = 4;
    tcp[8] = 5; tcp[9] = 6; tcp[10] = 7; tcp[11] = 8;
    tcp[12] = (unsigned char)((tcp_header_length / 4) << 4) | 0x0b;
    tcp[13] = 0x18; /* Preserve flags; this view makes no connection-state claim. */
    tcp[14] = 0x40; tcp[15] = 0;
    tcp[18] = 0; tcp[19] = 0;
    for (unsigned int i = 20; i < tcp_header_length; ++i)
        tcp[i] = 1; /* Opaque NOP bytes; options are not parsed. */
    for (unsigned int i = 0; i < payload_length; ++i)
        tcp[tcp_header_length + i] = (unsigned char)(0x31 + 17 * i);
    (void)set_tcp_checksum(ip, IP_HEADER_LENGTH, tcp_length);
    repair_ip_checksum(ip);
}

static struct rte_mbuf *make_chain(const unsigned char frame[FRAME_LENGTH])
{
    const unsigned int chunks[] = {13, 2, 8, 3, 1, 7, 20, 19, 55};
    struct rte_mbuf *head = NULL;
    unsigned int offset = 0;
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool);
        CHECK(segment != NULL);
        unsigned char *data = (unsigned char *)rte_pktmbuf_append(segment, chunks[i]);
        CHECK(data != NULL);
        memcpy(data, frame + offset, chunks[i]);
        offset += chunks[i];
        if (!head)
            head = segment;
        else
            CHECK(rte_pktmbuf_chain(head, segment) == 0);
    }
    CHECK(offset == FRAME_LENGTH && head->pkt_len == FRAME_LENGTH && head->nb_segs == 9);
    return head;
}

static struct sk_buff *classify_copy(struct rte_mbuf *chain)
{
    struct sk_buff *skb = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, chain, 128, &skb) == 0);
    CHECK(skb && skb->protocol == rte_cpu_to_be_16(ETH_P_IP));
    return skb;
}

static void check_sentinel(const struct ker_tcp_packet_view *view)
{
    CHECK(view->header == (const unsigned char *)(uintptr_t)1);
    CHECK(view->payload == (const unsigned char *)(uintptr_t)2);
    CHECK(view->source_port == 0x1234 && view->destination_port == 0x5678);
    CHECK(view->checksum == 0x9abc && view->tcp_header_length == 21 &&
        view->segment_length == 22 && view->payload_length == 23);
}

static void reject_unchanged(struct ker_skb_context *owner, struct sk_buff *skb,
    int expected, const struct ker_tcp_packet_view *sentinel)
{
    unsigned char before[FRAME_LENGTH];
    CHECK(skb->len <= sizeof(before));
    memcpy(before, skb->data, skb->len);
    struct ker_tcp_packet_view output = *sentinel;
    CHECK(ker_tcp_packet_view_init(owner, skb, &output) == expected);
    check_sentinel(&output);
    CHECK(!memcmp(skb->data, before, skb->len));
}

static void valid_max_options_odd_payload_and_lifetimes(void)
{
    unsigned char frame[FRAME_LENGTH], expected[FRAME_LENGTH];
    build_frame(frame, 60, 3);
    const unsigned int tcp_offset = ETH_HLEN + IP_HEADER_LENGTH;
    const unsigned int tcp_length = 63;
    uint16_t checksum_sum = reference_tcp_checksum(frame + ETH_HLEN,
        frame + tcp_offset, tcp_length);
    CHECK(checksum_sum == 0); /* Included checksum field makes the pseudoheader sum validate. */
    uint16_t checksum;
    memcpy(&checksum, frame + tcp_offset + 16, sizeof(checksum));
    memcpy(expected, frame, sizeof(expected));
    struct rte_mbuf *chain = make_chain(frame);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_tcp_packet_view view = {0};
    CHECK(ker_tcp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.header == skb->data + IP_HEADER_LENGTH);
    CHECK(view.payload == view.header + 60);
    CHECK(view.source_port == rte_cpu_to_be_16(0x1234));
    CHECK(view.destination_port == rte_cpu_to_be_16(0x5678));
    CHECK(view.checksum == checksum);
    CHECK(view.tcp_header_length == 60 && view.segment_length == tcp_length &&
        view.payload_length == 3);
    CHECK(!memcmp(view.header + 20, expected + tcp_offset + 20, 40));
    CHECK(view.payload[0] == expected[tcp_offset + 60] &&
        view.payload[1] == expected[tcp_offset + 61] &&
        view.payload[2] == expected[tcp_offset + 62]);
    CHECK(skb->len == FRAME_LENGTH - ETH_HLEN && skb->len > IP_HEADER_LENGTH + tcp_length);
    ker_packet_free(chain);
    CHECK(!memcmp(view.header, expected + tcp_offset, tcp_length));
    CHECK(ker_skb_free(skb) == 0 && context.live == 0);
}

static void mathematically_valid_zero_checksum(void)
{
    unsigned char frame[FRAME_LENGTH];
    build_frame(frame, 20, 2);
    unsigned char *ip = frame + ETH_HLEN;
    unsigned char *tcp = ip + IP_HEADER_LENGTH;
    tcp[16] = 0; tcp[17] = 0;
    bool found = false;
    for (unsigned int value = 0; value <= UINT16_MAX; ++value) {
        tcp[20] = (unsigned char)(value >> 8);
        tcp[21] = (unsigned char)value;
        if (reference_tcp_checksum(ip, tcp, 22) == 0) {
            found = true;
            break;
        }
    }
    CHECK(found);
    repair_ip_checksum(ip);
    CHECK(tcp[16] == 0 && tcp[17] == 0);
    struct rte_mbuf *chain = make_chain(frame);
    struct sk_buff *skb = classify_copy(chain);
    struct ker_tcp_packet_view view = {0};
    CHECK(ker_tcp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.checksum == 0 && view.tcp_header_length == 20 && view.payload_length == 2);
    CHECK(view.payload[0] == tcp[20] && view.payload[1] == tcp[21]);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(rte_mbuf_refcnt_read(chain) == 1);
    ker_packet_free(chain);
    CHECK(context.live == 0);
}

static void validation_failures_preserve_view_and_packet(void)
{
    unsigned char frame[FRAME_LENGTH], saved[FRAME_LENGTH];
    const struct ker_tcp_packet_view sentinel = {
        (const unsigned char *)(uintptr_t)1, (const unsigned char *)(uintptr_t)2,
        0x1234, 0x5678, 0x9abc, 21, 22, 23
    };
    struct ker_tcp_packet_view output;
    build_frame(frame, 24, 5);
    struct rte_mbuf *chain = make_chain(frame);
    struct sk_buff *skb = classify_copy(chain);
    memcpy(saved, skb->data, skb->len);
    struct ker_skb_context foreign = {0};
    reject_unchanged(&foreign, skb, -EXDEV, &sentinel);
    CHECK(ker_skb_get(skb) == 0);
    reject_unchanged(&context, skb, -EBUSY, &sentinel);
    CHECK(ker_skb_free(skb) == 0);

    skb->data[IP_HEADER_LENGTH + 22] ^= 1;
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    reject_unchanged(&context, skb, -EBADMSG, &sentinel);
    skb->ip_summed = CHECKSUM_NONE;
    memcpy(skb->data, saved, skb->len);
    skb->data[12] ^= 1; /* Pseudoheader source change, repair only IP checksum. */
    repair_ip_checksum(skb->data);
    reject_unchanged(&context, skb, -EBADMSG, &sentinel);

    memcpy(skb->data, saved, skb->len);
    unsigned char *ip = skb->data;
    ip[9] = 17;
    repair_ip_checksum(ip);
    reject_unchanged(&context, skb, -EPROTONOSUPPORT, &sentinel);
    memcpy(skb->data, saved, skb->len);
    ip = skb->data;
    ip[6] = 0x60; ip[7] = 0;
    repair_ip_checksum(ip);
    reject_unchanged(&context, skb, -ENOTSUP, &sentinel);
    memcpy(skb->data, saved, skb->len);
    ip = skb->data;
    ip[6] = 0; ip[7] = 1;
    repair_ip_checksum(ip);
    reject_unchanged(&context, skb, -ENOTSUP, &sentinel);
    memcpy(skb->data, saved, skb->len);
    ip = skb->data;
    ip[2] = 0; ip[3] = 43; /* IPv4 TCP payload smaller than fixed TCP header. */
    repair_ip_checksum(ip);
    reject_unchanged(&context, skb, -EMSGSIZE, &sentinel);

    memcpy(skb->data, saved, skb->len);
    ip = skb->data;
    ip[2] = 0; ip[3] = 64; /* IPv4 payload 40 bytes, less than TCP data offset 15. */
    skb->data[IP_HEADER_LENGTH + 12] = 0xf0;
    repair_ip_checksum(ip);
    reject_unchanged(&context, skb, -EMSGSIZE, &sentinel);

    memcpy(skb->data, saved, skb->len);
    skb->data[IP_HEADER_LENGTH + 12] = 0x40; /* Invalid doff < 5. */
    ip = skb->data;
    set_tcp_checksum(ip, IP_HEADER_LENGTH, 29);
    repair_ip_checksum(ip);
    output = sentinel;
    reject_unchanged(&context, skb, -EINVAL, &sentinel);

    memcpy(skb->data, saved, skb->len);
    output = sentinel;
    CHECK(ker_tcp_packet_view_init(NULL, skb, &output) == -EINVAL);
    check_sentinel(&output);
    CHECK(ker_skb_free(skb) == 0);
    ker_packet_free(chain);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_tcp_ingress", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ker_tcp_ingress_desc") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, host_mac) == 0);
    valid_max_options_odd_payload_and_lifetimes();
    mathematically_valid_zero_checksum();
    validation_failures_preserve_view_and_packet();
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 31);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("TCP ingress view: segmented checksum and ownership boundaries passed");
    return 0;
}
