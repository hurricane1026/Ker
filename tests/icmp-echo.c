#include "check.h"
#include "eal.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/icmp-echo-packet-view.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static const unsigned char smac[6] = {2, 1, 2, 3, 4, 5};
static const unsigned char dmac[6] = {2, 6, 7, 8, 9, 10};
static const unsigned char payload[] = {0x10, 0x21, 0x32, 0x43, 0x54};
static const unsigned char options[40] = {
    1,1,0,0, 0x82,4,0xaa,0xbb, 0x83,4,0xcc,0xdd,
    0x84,4,0xee,0xff, 0x85,4,0x11,0x22, 0x86,4,0x33,0x44,
    0x87,4,0x55,0x66, 0x88,4,0x77,0x88, 0x89,4,0x99,0xaa,
    0x8a,4,0xbb,0xcc
};
static __be32 source_ip;
static __be32 dest_ip;

static uint32_t sum_bytes(const unsigned char *p, unsigned int n)
{
    uint32_t sum = 0;
    for (unsigned int i = 0; i < n; i += 2)
        sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    return sum;
}

static uint16_t checksum(const unsigned char *p, unsigned int n)
{
    uint32_t sum = sum_bytes(p, n);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void verify_wire(const struct sk_buff *skb, uint8_t type,
    const void *opts, unsigned int opts_len, const void *data, unsigned int data_len,
    __be16 id, __be16 seq)
{
    const unsigned char *frame = skb->data;
    unsigned int ihl = 20 + opts_len;
    unsigned int icmp_len = 8 + data_len;
    CHECK(skb->len == ETH_HLEN + ihl + icmp_len);
    CHECK(skb_headroom(skb) == 128 && skb->mac_header == 128);
    CHECK(skb->network_header == 128 + ETH_HLEN);
    CHECK(skb->transport_header == 128 + ETH_HLEN + ihl);
    CHECK(!memcmp(frame, dmac, 6) && !memcmp(frame + 6, smac, 6));
    CHECK(frame[12] == 8 && frame[13] == 0);
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(ip[0] == (unsigned char)(0x40 | ihl / 4));
    CHECK(ip[2] == (unsigned char)((ihl + icmp_len) >> 8));
    CHECK(ip[3] == (unsigned char)(ihl + icmp_len));
    CHECK(ip[8] == 64 && ip[9] == 1 && ip[6] == 0 && ip[7] == 0);
    CHECK(!memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &dest_ip, 4));
    CHECK(checksum(ip, ihl) == 0);
    if (opts_len) CHECK(!memcmp(ip + 20, opts, opts_len));
    const unsigned char *icmp = ip + ihl;
    CHECK(icmp[0] == type && icmp[1] == 0);
    CHECK(!memcmp(icmp + 4, &id, 2) && !memcmp(icmp + 6, &seq, 2));
    CHECK(checksum(icmp, icmp_len) == 0);
    if (data_len) CHECK(!memcmp(icmp + 8, data, data_len));
}

static void constructor_vectors(void)
{
    struct sk_buff *skb = NULL;
    for (unsigned int opts_len = 0; opts_len <= 40; opts_len += opts_len ? 36 : 4) {
        for (unsigned int data_len = 0; data_len <= sizeof(payload); data_len += data_len ? 4 : 1) {
            uint8_t type = ((opts_len + data_len) & 1) ? 8 : 0;
            CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac,
                source_ip, dest_ip, rte_cpu_to_be_16(0x1234), rte_cpu_to_be_16(0x5678),
                type, 64, opts_len ? options : NULL, opts_len,
                data_len ? payload : NULL, data_len, &skb) == 0);
            verify_wire(skb, type, opts_len ? options : NULL, opts_len,
                data_len ? payload : NULL, data_len,
                rte_cpu_to_be_16(0x1234), rte_cpu_to_be_16(0x5678));
            /* Constructor copies both borrowed inputs. */
            if (opts_len) CHECK(!memcmp(skb->data + ETH_HLEN + 20, options, opts_len));
            if (opts_len == 40 && data_len == sizeof(payload)) {
                struct rte_mbuf *mbuf = NULL;
                CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
                CHECK(ker_skb_free(skb) == 0); skb = NULL;
                struct sk_buff *classified = NULL;
                CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
                ker_packet_free(mbuf);
                struct ker_icmp_echo_packet_view packet;
                CHECK(ker_icmp_echo_packet_view_init(&context, classified, &packet) == 0);
                CHECK(packet.icmp_length == 8 + sizeof(payload) && packet.payload_length == sizeof(payload));
                CHECK(!memcmp(packet.header + 8, payload, sizeof(payload)));
                CHECK(ker_skb_free(classified) == 0);
                continue;
            }
            CHECK(ker_skb_free(skb) == 0); skb = NULL;
        }
    }
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        rte_cpu_to_be_16(7), rte_cpu_to_be_16(9), 8, 64, payload,
        sizeof(payload), &skb) == 0);
    verify_wire(skb, 8, NULL, 0, payload, sizeof(payload),
        rte_cpu_to_be_16(7), rte_cpu_to_be_16(9));
    CHECK(ker_skb_free(skb) == 0);

    unsigned char options_copy[4] = {1, 1, 0, 0};
    unsigned char payload_copy[3] = {0xa1, 0xb2, 0xc3};
    const unsigned char expected_options[4] = {1, 1, 0, 0};
    const unsigned char expected_payload[3] = {0xa1, 0xb2, 0xc3};
    CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac,
        source_ip, dest_ip, 0, 0, 8, 64, options_copy, sizeof(options_copy),
        payload_copy, sizeof(payload_copy), &skb) == 0);
    memset(options_copy, 0xee, sizeof(options_copy));
    memset(payload_copy, 0xdd, sizeof(payload_copy));
    verify_wire(skb, 8, expected_options, sizeof(expected_options),
        expected_payload, sizeof(expected_payload), 0, 0);
    CHECK(ker_skb_free(skb) == 0);
}

static void checksum_zero_and_view(void)
{
    struct sk_buff *skb = NULL;
    bool found = false;
    /* For this five-byte payload, find a valid wire echo header whose computed
     * checksum is exactly zero; ICMPv4 must preserve it, unlike UDP. */
    for (unsigned int id = 0; id <= UINT16_MAX && !found; ++id) {
        CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
            rte_cpu_to_be_16((uint16_t)id), rte_cpu_to_be_16(0), 8, 64,
            payload, sizeof(payload), &skb) == 0);
        if (skb->data[ETH_HLEN + 20 + 2] == 0 && skb->data[ETH_HLEN + 20 + 3] == 0)
            found = true;
        if (!found) { CHECK(ker_skb_free(skb) == 0); skb = NULL; }
    }
    CHECK(found && skb);
    __be16 found_id;
    memcpy(&found_id, skb->data + ETH_HLEN + 20 + 4, sizeof(found_id));
    verify_wire(skb, 8, NULL, 0, payload, sizeof(payload),
        found_id, rte_cpu_to_be_16(0));
    struct rte_mbuf *mbuf = NULL;
    CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
    CHECK(ker_skb_free(skb) == 0);
    struct sk_buff *classified = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
    ker_packet_free(mbuf);
    struct ker_icmp_echo_packet_view view;
    memset(&view, 0xa5, sizeof(view));
    struct ker_icmp_echo_packet_view unchanged = view;
    struct ker_skb_context foreign = {0};
    CHECK(ker_icmp_echo_packet_view_init(&foreign, classified, &view) == -EXDEV);
    CHECK(!memcmp(&view, &unchanged, sizeof(view)));
    struct sk_buff *clone = NULL;
    CHECK(ker_skb_clone(classified, &clone) == 0 && clone);
    CHECK(ker_icmp_echo_packet_view_init(&context, classified, &view) == -EBUSY);
    CHECK(ker_skb_free(clone) == 0);
    CHECK(ker_icmp_echo_packet_view_init(&context, classified, &view) == 0);
    CHECK(view.type == 8 && view.code == 0 && view.icmp_length == 13 &&
        view.payload_length == sizeof(payload) && !memcmp(view.payload, payload, sizeof(payload)));
    CHECK(view.icmp_checksum == 0);
    struct ker_icmp_echo_packet_view saved = view;
    classified->data[20 + 2] ^= 1;
    CHECK(ker_icmp_echo_packet_view_init(&context, classified, &view) == -EBADMSG);
    CHECK(!memcmp(&view, &saved, sizeof(view)));
    CHECK(ker_skb_free(classified) == 0);
}

static void failures(void)
{
    unsigned char mutable_payload[3] = {1, 2, 3};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
#define REJECT(code, type, ttl, opts, olen, data, len) do { \
    CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac, source_ip, dest_ip, \
        0, 0, (type), (ttl), (opts), (olen), (data), (len), &sentinel) == (code)); \
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0); \
} while (0)
    REJECT(-EINVAL, 3, 64, NULL, 0, mutable_payload, 3);
    REJECT(-EINVAL, 8, 0, NULL, 0, mutable_payload, 3);
    REJECT(-EINVAL, 8, 64, NULL, 4, mutable_payload, 3);
    REJECT(-EINVAL, 8, 64, options, 2, mutable_payload, 3);
    REJECT(-EINVAL, 8, 64, options, 44, mutable_payload, 3);
    REJECT(-EMSGSIZE, 8, 64, options, 40, mutable_payload, UINT_MAX);
    REJECT(-EINVAL, 8, 64, NULL, 0, NULL, 1);
#undef REJECT
    CHECK(!memcmp(mutable_payload, (unsigned char[]){1,2,3}, sizeof(mutable_payload)));
    struct sk_buff *oversize = (void *)(uintptr_t)0x1234;
    unsigned char *max_payload = malloc(65468);
    CHECK(max_payload);
    memset(max_payload, 0x5a, 65468);
    CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, options, 40, max_payload, 65535 - 20 - 40 - 8, &oversize) == -ENOSPC);
    CHECK(oversize == (void *)(uintptr_t)0x1234 && context.live == 0);
    CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, options, 40, max_payload, 65535 - 20 - 40 - 8 + 1, &oversize) == -EMSGSIZE);
    CHECK(oversize == (void *)(uintptr_t)0x1234 && context.live == 0);
    free(max_payload);
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, payload, 1900, &oversize) == -ENOSPC);
    CHECK(oversize == (void *)(uintptr_t)0x1234 && context.live == 0);
    struct rte_mbuf *held[63]; unsigned int n = 0;
    while (n < 63 && (held[n] = ker_packet_alloc(&pool))) ++n;
    CHECK(n == 63);
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, payload, sizeof(payload), &oversize) == -ENOMEM);
    CHECK(oversize == (void *)(uintptr_t)0x1234 && context.live == 0);
    ker_packet_free(held[--n]);
    struct sk_buff *retry = NULL;
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, payload, sizeof(payload), &retry) == 0);
    CHECK(ker_skb_free(retry) == 0);
    while (n) ker_packet_free(held[--n]);
}

int main(void)
{
    ker_test_eal_init();
    source_ip = rte_cpu_to_be_32(0xc0000201);
    dest_ip = rte_cpu_to_be_32(0xc6336402);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "icmp_echo", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "icmp_echo_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "icmp0", 1, smac) == 0);
    constructor_vectors();
    checksum_zero_and_view();
    failures();
    CHECK(context.live == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("ICMP echo construction and validation passed");
    return 0;
}
