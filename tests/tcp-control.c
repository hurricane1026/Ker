#include "check.h"
#include "eal.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include "runtime/tcp-create.h"
#include "runtime/tcp-mss.h"
#include <errno.h>
#include <string.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char source_mac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char local_mac[6] = {2, 6, 7, 8, 9, 10};

static struct sk_buff *segment(const unsigned char *options, unsigned int length,
                               uint8_t flags, unsigned int payload_length)
{
    const unsigned char payload[3] = {0x00, 0x80, 0xff};
    struct sk_buff *out = NULL;
    CHECK(payload_length <= sizeof(payload));
    CHECK(ker_tcp_ipv4_create_options(&context, source_mac, local_mac,
        rte_cpu_to_be_32(0xc0000201), rte_cpu_to_be_32(0xc0000202),
        rte_cpu_to_be_16(12345), rte_cpu_to_be_16(80),
        rte_cpu_to_be_32(UINT32_MAX - 2), rte_cpu_to_be_32(0x89abcdef),
        rte_cpu_to_be_16(0x8123), flags, 64, options, length,
        payload, payload_length, &out) == 0);
    struct rte_mbuf *frame = ker_packet_alloc(&pool);
    CHECK(frame);
    unsigned char *bytes = (unsigned char *)rte_pktmbuf_append(frame, out->len);
    CHECK(bytes);
    memcpy(bytes, out->data, out->len);
    CHECK(ker_skb_free(out) == 0);
    out = NULL;
    CHECK(ker_eth_receive(&device, frame, &out) == 0);
    return out;
}

static void check_mss(const unsigned char *options, unsigned int length,
                      uint16_t cap, uint16_t expected)
{
    struct sk_buff *skb = segment(options, length, KER_TCP_SYN | KER_TCP_ACK, 0);
    unsigned char original[80];
    CHECK(skb->len <= sizeof(original));
    memcpy(original, skb->data, skb->len);
    uint16_t mss = 0xffff;
    CHECK(ker_tcp_syn_mss(&context, skb, cap, &mss) == 0 && mss == expected);
    CHECK(!memcmp(original, skb->data, skb->len));
    CHECK(context.live == 1 && ker_skb_free(skb) == 0);
}

/* Independent byte-wise checksum for a mutated segment. */
static void checksum_tcp(struct sk_buff *skb)
{
    unsigned char *ip = skb->data;
    unsigned char *tcp = ip + 20;
    unsigned int length = ((unsigned int)ip[2] << 8 | ip[3]) - 20;
    tcp[16] = tcp[17] = 0;
    uint32_t sum = 6 + length;
    for (unsigned int i = 12; i < 20; i += 2)
        sum += ((uint16_t)ip[i] << 8) | ip[i + 1];
    for (unsigned int i = 0; i < length; i += 2)
        sum += ((uint16_t)tcp[i] << 8) | (i + 1 < length ? tcp[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t check = (uint16_t)~sum;
    tcp[16] = (unsigned char)(check >> 8);
    tcp[17] = (unsigned char)check;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tcp_control", 127, 0, 4096, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tcp_control_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "tcp_ctrl0", 31, local_mac) == 0);

    struct sk_buff *skb = segment(NULL, 0, KER_TCP_SYN | KER_TCP_FIN | KER_TCP_ACK, 3);
    /* URG and AccECN are decoded from received bytes even though the legacy
     * constructor doesn't offer them. Recompute with the independent oracle. */
    skb->data[20 + 12] |= 1;
    skb->data[20 + 13] |= KER_TCP_URG;
    skb->data[20 + 18] = 0x12;
    skb->data[20 + 19] = 0x34;
    checksum_tcp(skb);
    struct ker_tcp_packet_view view;
    CHECK(ker_tcp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.sequence == UINT32_MAX - 2 && view.acknowledgment == 0x89abcdef);
    CHECK(view.end_sequence == 2 && view.window == 0x8123 && view.urgent_pointer == 0x1234);
    CHECK(view.flags == (KER_TCP_SYN | KER_TCP_FIN | KER_TCP_ACK | KER_TCP_URG | KER_TCP_AE));
    CHECK(view.source_port == rte_cpu_to_be_16(12345) && view.destination_port == rte_cpu_to_be_16(80));
    CHECK(view.payload_length == 3 && view.tcp_header_length == 20);
    CHECK(ker_skb_free(skb) == 0);
    skb = segment(NULL, 0, KER_TCP_ACK, 0);
    CHECK(ker_tcp_packet_view_init(&context, skb, &view) == 0);
    CHECK(view.end_sequence == view.sequence && view.flags == KER_TCP_ACK);
    uint16_t untouched = 321;
    CHECK(ker_tcp_syn_mss(&context, skb, 0, &untouched) == -EINVAL && untouched == 321);
    CHECK(ker_skb_free(skb) == 0);

    const unsigned char mss[] = {2, 4, 0x05, 0xb4};
    check_mss(mss, sizeof(mss), 0, 1460);
    check_mss(mss, sizeof(mss), 1200, 1200);
    check_mss(mss, sizeof(mss), 2000, 1460);
    check_mss(NULL, 0, 0, 0);
    const unsigned char zero[] = {2, 4, 0, 0};
    check_mss(zero, sizeof(zero), 0, 0);
    const unsigned char padded[] = {1, 1, 2, 4, 0x02, 0x18, 0, 0};
    check_mss(padded, sizeof(padded), 0, 536);
    const unsigned char duplicate[] = {2, 4, 0x05, 0xb4, 2, 4, 0x02, 0x18};
    check_mss(duplicate, sizeof(duplicate), 0, 536);
    const unsigned char zero_after[] = {2, 4, 0x05, 0xb4, 2, 4, 0, 0};
    check_mss(zero_after, sizeof(zero_after), 0, 1460);
    const unsigned char eol[] = {0, 2, 4, 0x05, 0xb4, 1, 1, 1};
    check_mss(eol, sizeof(eol), 0, 0);
    const unsigned char malformed[] = {30, 1, 2, 4, 0x05, 0xb4, 1, 1};
    check_mss(malformed, sizeof(malformed), 0, 0);
    const unsigned char partial[] = {2, 4, 0x05, 0xb4, 30, 5, 1, 1};
    check_mss(partial, sizeof(partial), 0, 1460);
    const unsigned char unknown[] = {30, 4, 0, 0, 2, 4, 0x05, 0xb4};
    check_mss(unknown, sizeof(unknown), 0, 1460);
    const unsigned char short_mss[] = {2, 3, 0x05, 1};
    check_mss(short_mss, sizeof(short_mss), 0, 0);
    const unsigned char last_kind[] = {1, 1, 1, 2};
    check_mss(last_kind, sizeof(last_kind), 0, 0);

    skb = segment(mss, sizeof(mss), KER_TCP_SYN, 0);
    CHECK(ker_tcp_syn_mss(&context, skb, 0, NULL) == -EINVAL);
    skb->data[20 + 16] ^= 1;
    memset(&view, 0xa5, sizeof(view));
    struct ker_tcp_packet_view saved;
    memcpy(&saved, &view, sizeof(saved));
    CHECK(ker_tcp_packet_view_init(&context, skb, &view) == -EBADMSG);
    CHECK(!memcmp(&view, &saved, sizeof(view)));
    CHECK(ker_tcp_syn_mss(&context, skb, 0, &untouched) == -EBADMSG && untouched == 321);
    CHECK(ker_skb_free(skb) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 127);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("TCP control fields and original Linux MSS parsing passed");
    return 0;
}
