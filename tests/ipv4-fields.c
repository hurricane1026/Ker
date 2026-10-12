#include "check.h"
#include "eal.h"
#include "runtime/udp-create.h"
#include "runtime/tcp-create.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>
#include <limits.h>

#define HEADROOM 128U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static const uint8_t smac[ETH_ALEN] = {2, 0x11, 0x12, 0x13, 0x14, 0x15};
static const uint8_t dmac[ETH_ALEN] = {2, 0x21, 0x22, 0x23, 0x24, 0x25};
static __be32 sip, dip;
static __be16 sport, dport;

static uint16_t sum_bytes(const uint8_t *p, size_t n)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i += 2)
        sum += ((uint16_t)p[i] << 8) | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)sum;
}

static uint16_t checksum(const uint8_t *p, size_t n)
{
    return (uint16_t)~sum_bytes(p, n);
}

static void verify_ip(const struct sk_buff *skb,
    const struct ker_ipv4_header_fields *fields, const uint8_t *options,
    unsigned int options_length, unsigned int ip_length, uint8_t protocol)
{
    const uint8_t *ip = skb->data + ETH_HLEN;
    CHECK(skb->len == ETH_HLEN + ip_length && skb_headroom(skb) == HEADROOM);
    CHECK(skb->mac_header == HEADROOM && skb->network_header == HEADROOM + ETH_HLEN);
    CHECK(ip[0] == (uint8_t)(0x40U + (20U + options_length) / 4U));
    CHECK(ip[1] == fields->ds_field && ip[8] == 63 && ip[9] == protocol);
    CHECK(!memcmp(ip + 4, &fields->identification, 2));
    CHECK(!memcmp(ip + 6, &fields->frag_off, 2));
    CHECK(!memcmp(ip + 12, &sip, 4) && !memcmp(ip + 16, &dip, 4));
    CHECK(checksum(ip, 20U + options_length) == 0);
    if (options_length)
        CHECK(options && !memcmp(ip + 20, options, options_length));
    CHECK((((unsigned int)ip[2] << 8) | ip[3]) == ip_length);
}

static void verify_transport(const struct sk_buff *skb, uint8_t protocol,
    unsigned int options_length, unsigned int tcp_options_length,
    const uint8_t *payload, unsigned int payload_length)
{
    const uint8_t *ip = skb->data + ETH_HLEN;
    unsigned int ihl = 20 + options_length;
    unsigned int l4_length = skb->len - ETH_HLEN - ihl;
    if (protocol == IPPROTO_UDP) {
        const uint8_t *udp = ip + ihl;
        CHECK(!memcmp(udp, &sport, 2) && !memcmp(udp + 2, &dport, 2));
        CHECK((((unsigned int)udp[4] << 8) | udp[5]) == 8 + payload_length);
        if (payload_length) CHECK(!memcmp(udp + 8, payload, payload_length));
        uint8_t pseudo[12], all[12 + 8 + 64];
        memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = IPPROTO_UDP;
        pseudo[10] = (uint8_t)(l4_length >> 8); pseudo[11] = (uint8_t)l4_length;
        memcpy(all, pseudo, 12); memcpy(all + 12, udp, l4_length);
        CHECK(sum_bytes(all, 12 + l4_length) == 0xffffU);
    } else if (protocol == IPPROTO_TCP) {
        const uint8_t *tcp = ip + ihl;
        unsigned int thl = 20 + tcp_options_length;
        CHECK(!memcmp(tcp, &sport, 2) && !memcmp(tcp + 2, &dport, 2));
        CHECK((tcp[12] >> 4) * 4U == thl);
        if (payload_length) CHECK(!memcmp(tcp + thl, payload, payload_length));
        uint8_t pseudo[12], all[12 + 60 + 64];
        memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
        pseudo[10] = (uint8_t)(l4_length >> 8); pseudo[11] = (uint8_t)l4_length;
        memcpy(all, pseudo, 12); memcpy(all + 12, tcp, l4_length);
        CHECK(sum_bytes(all, 12 + l4_length) == 0xffffU);
    } else {
        const uint8_t *icmp = ip + ihl;
        CHECK(icmp[0] == 8 && icmp[1] == 0);
        if (payload_length) CHECK(!memcmp(icmp + 8, payload, payload_length));
        CHECK(sum_bytes(icmp, l4_length) == 0xffffU);
    }
}

static void check_equal(const struct sk_buff *a, const struct sk_buff *b)
{
    CHECK(a->len == b->len && skb_headroom(a) == skb_headroom(b) &&
        a->mac_header == b->mac_header && a->network_header == b->network_header &&
        a->transport_header == b->transport_header && a->mac_len == b->mac_len &&
        !memcmp(a->data, b->data, a->len));
}

static void vectors_and_legacy_equivalence(void)
{
    const uint8_t ip_options[40] = {
        1,1,0,0, 0x82,4,0xaa,0xbb, 0x83,4,0xcc,0xdd,
        0x84,4,0xee,0xff, 0x85,4,0x11,0x22, 0x86,4,0x33,0x44,
        0x87,4,0x55,0x66, 0x88,4,0x77,0x88, 0x89,4,0x99,0xaa,
        0x8a,4,0xbb,0xcc
    };
    const uint8_t tcp_options[40] = {
        1,1,0,0, 2,4,5,180, 3,3,7,0, 4,2,1,1, 8,10,0,0,
        0,1,0,2, 1,1,1,1, 2,4,4,176, 3,3,4,0, 0,0,0,0
    };
    uint8_t input_options[sizeof(ip_options)];
    memcpy(input_options, ip_options, sizeof(input_options));
    uint8_t payload[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    struct ker_ipv4_header_fields fields = {
        .ds_field = 0xff, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = 0
    };
    struct sk_buff *skb = NULL;
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &fields, input_options, sizeof(input_options), payload, sizeof(payload), &skb) == 0);
    verify_ip(skb, &fields, ip_options, 40, 20 + 40 + 8 + sizeof(payload), IPPROTO_UDP);
    verify_transport(skb, IPPROTO_UDP, 40, 0, payload, sizeof(payload));
    uint8_t frame_snapshot[2048];
    CHECK(skb->len <= sizeof(frame_snapshot));
    unsigned int frame_length = skb->len;
    memcpy(frame_snapshot, skb->data, frame_length);
    memset(payload, 0xee, sizeof(payload));
    memset(input_options, 0xdd, sizeof(input_options));
    fields.ds_field = 0;
    fields.identification = 0;
    fields.frag_off = rte_cpu_to_be_16(0x4000);
    CHECK(skb->len == frame_length && !memcmp(frame_snapshot, skb->data, frame_length));
    CHECK(ker_skb_free(skb) == 0);

    fields = (struct ker_ipv4_header_fields){0};
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &fields, NULL, 0, NULL, 0, &skb) == 0);
    verify_ip(skb, &fields, NULL, 0, 20 + 8, IPPROTO_UDP);
    verify_transport(skb, IPPROTO_UDP, 0, 0, NULL, 0);
    CHECK(ker_skb_free(skb) == 0);

    fields = (struct ker_ipv4_header_fields){
        .ds_field = 0xb8, .identification = rte_cpu_to_be_16(0xffff),
        .frag_off = rte_cpu_to_be_16(0x4000)
    };
    uint8_t tcp_payload[] = {1, 2, 3, 4, 5};
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        rte_cpu_to_be_32(0x10203040), rte_cpu_to_be_32(0x50607080),
        rte_cpu_to_be_16(4096), 0x18, 63, &fields, ip_options, 40,
        tcp_options, 40, tcp_payload, sizeof(tcp_payload), &skb) == 0);
    verify_ip(skb, &fields, ip_options, 40, 20 + 40 + 20 + 40 + sizeof(tcp_payload), IPPROTO_TCP);
    verify_transport(skb, IPPROTO_TCP, 40, 40, tcp_payload, sizeof(tcp_payload));
    CHECK(ker_skb_free(skb) == 0);

    uint8_t tcp_even[] = {9, 8, 7, 6};
    fields = (struct ker_ipv4_header_fields){
        .ds_field = 0x00, .identification = rte_cpu_to_be_16(0x1234), .frag_off = 0
    };
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(1), 0x10, 63, &fields, NULL, 0, NULL, 0,
        tcp_even, sizeof(tcp_even), &skb) == 0);
    verify_ip(skb, &fields, NULL, 0, 20 + 20 + sizeof(tcp_even), IPPROTO_TCP);
    verify_transport(skb, IPPROTO_TCP, 0, 0, tcp_even, sizeof(tcp_even));
    CHECK(ker_skb_free(skb) == 0);

    fields = (struct ker_ipv4_header_fields){
        .ds_field = 0x2e, .identification = 0, .frag_off = rte_cpu_to_be_16(0x4000)
    };
    uint8_t echo_payload[] = {0x91, 0x82, 0x73};
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip,
        rte_cpu_to_be_16(0xffff), rte_cpu_to_be_16(0x1234), 8, 63, &fields,
        ip_options, 4, echo_payload, sizeof(echo_payload), &skb) == 0);
    verify_ip(skb, &fields, ip_options, 4, 20 + 4 + 8 + sizeof(echo_payload), IPPROTO_ICMP);
    verify_transport(skb, IPPROTO_ICMP, 4, 0, echo_payload, sizeof(echo_payload));
    CHECK(ker_skb_free(skb) == 0);

    uint8_t echo_even[] = {0x11, 0x22, 0x33, 0x44};
    fields = (struct ker_ipv4_header_fields){
        .ds_field = 0xff, .identification = rte_cpu_to_be_16(0xffff),
        .frag_off = 0
    };
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 0, 1,
        8, 63, &fields, ip_options, 40, echo_even, sizeof(echo_even), &skb) == 0);
    verify_ip(skb, &fields, ip_options, 40, 20 + 40 + 8 + sizeof(echo_even), IPPROTO_ICMP);
    verify_transport(skb, IPPROTO_ICMP, 40, 0, echo_even, sizeof(echo_even));
    CHECK(ker_skb_free(skb) == 0);

    const struct ker_ipv4_header_fields zero = {0};
    struct sk_buff *legacy = NULL, *profiled = NULL;
    CHECK(ker_udp_ipv4_create_ip_options(&context, smac, dmac, sip, dip, sport, dport,
        63, ip_options, 4, echo_payload, sizeof(echo_payload), &legacy) == 0);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &zero, ip_options, 4, echo_payload, sizeof(echo_payload), &profiled) == 0);
    check_equal(legacy, profiled);
    CHECK(ker_skb_free(legacy) == 0 && ker_skb_free(profiled) == 0);
    CHECK(ker_tcp_ipv4_create_headers(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(4096), 0x18, 63, ip_options, 4, tcp_options, 4,
        echo_payload, sizeof(echo_payload), &legacy) == 0);
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(4096), 0x18, 63, &zero, ip_options, 4, tcp_options, 4,
        echo_payload, sizeof(echo_payload), &profiled) == 0);
    check_equal(legacy, profiled);
    CHECK(ker_skb_free(legacy) == 0 && ker_skb_free(profiled) == 0);
    CHECK(ker_icmp_echo_ipv4_create_ip_options(&context, smac, dmac, sip, dip, 1, 2,
        8, 63, ip_options, 4, echo_payload, sizeof(echo_payload), &legacy) == 0);
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 1, 2,
        8, 63, &zero, ip_options, 4, echo_payload, sizeof(echo_payload), &profiled) == 0);
    check_equal(legacy, profiled);
    CHECK(ker_skb_free(legacy) == 0 && ker_skb_free(profiled) == 0);
}

static void reject_profiles_transactionally(void)
{
    const __be16 invalid[] = {
        rte_cpu_to_be_16(0x2000), rte_cpu_to_be_16(1),
        rte_cpu_to_be_16(0x8000), rte_cpu_to_be_16(0x6000)
    };
    uint8_t payload[] = {1, 2, 3};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        struct ker_ipv4_header_fields fields = {.ds_field = 0x5a,
            .identification = rte_cpu_to_be_16(0x1234), .frag_off = invalid[i]};
        struct sk_buff *sentinel = (void *)(uintptr_t)1;
        CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
            63, &fields, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP &&
            sentinel == (void *)(uintptr_t)1);
        CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
            1, 2, rte_cpu_to_be_16(64), 0x18, 63, &fields, NULL, 0, NULL, 0,
            payload, sizeof(payload), &sentinel) == -ENOTSUP &&
            sentinel == (void *)(uintptr_t)1);
        CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 1, 2,
            8, 63, &fields, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP &&
            sentinel == (void *)(uintptr_t)1);
    }
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    struct ker_ipv4_header_fields wrong_order_df = {.frag_off = (__be16)0x4000};
    struct sk_buff *wrong_order_sentinel = (void *)(uintptr_t)1;
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &wrong_order_df, NULL, 0, payload, sizeof(payload), &wrong_order_sentinel) == -ENOTSUP &&
        wrong_order_sentinel == (void *)(uintptr_t)1);
#endif
    struct sk_buff *sentinel = (void *)(uintptr_t)1;
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, NULL, NULL, 0, payload, sizeof(payload), &sentinel) == -EINVAL &&
        sentinel == (void *)(uintptr_t)1);
    struct ker_ipv4_header_fields invalid_fields = {.frag_off = rte_cpu_to_be_16(0x2000)};
    ker_memory_fail_after(0);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &invalid_fields, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(64), 0x18, 63, &invalid_fields, NULL, 0, NULL, 0,
        payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 1, 2,
        8, 63, &invalid_fields, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    struct ker_ipv4_header_fields valid = {0};
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOMEM &&
        sentinel == (void *)(uintptr_t)1);
    ker_memory_fail_after(-1);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, UINT_MAX, &sentinel) == -EMSGSIZE &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, UINT16_MAX - 28U, &sentinel) == -ENOSPC &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(64), 0x18, 63, &valid, NULL, 0, NULL, 0,
        payload, UINT16_MAX - 40U, &sentinel) == -ENOSPC &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 1, 2,
        8, 63, &valid, NULL, 0, payload, UINT16_MAX - 28U, &sentinel) == -ENOSPC &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, UINT16_MAX - 27U, &sentinel) == -EMSGSIZE &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_icmp_echo_ipv4_create_fields(&context, smac, dmac, sip, dip, 1, 2,
        8, 63, &valid, NULL, 0, payload, UINT16_MAX - 27U, &sentinel) == -EMSGSIZE &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(ker_tcp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        1, 2, rte_cpu_to_be_16(64), 0x18, 63, &valid, NULL, 0, NULL, 0,
        payload, UINT16_MAX - 39U, &sentinel) == -EMSGSIZE &&
        sentinel == (void *)(uintptr_t)1);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == 63);

    struct rte_mbuf *held[63];
    unsigned int held_count = 0;
    while (held_count < 63 && (held[held_count] = ker_packet_alloc(&pool)) != NULL)
        held_count++;
    CHECK(held_count == 63 && rte_mempool_avail_count(pool.mbufs) == 0);
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, sizeof(payload), &sentinel) == -ENOMEM &&
        sentinel == (void *)(uintptr_t)1 && context.live == 0);
    ker_packet_free(held[--held_count]);
    struct sk_buff *retry = NULL;
    CHECK(ker_udp_ipv4_create_fields(&context, smac, dmac, sip, dip, sport, dport,
        63, &valid, NULL, 0, payload, sizeof(payload), &retry) == 0);
    CHECK(context.live == 1 && ker_skb_free(retry) == 0 && context.live == 0);
    while (held_count) ker_packet_free(held[--held_count]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
}

int main(void)
{
    ker_test_eal_init();
    sip = rte_cpu_to_be_32(0xc0000201);
    dip = rte_cpu_to_be_32(0xc6336402);
    sport = rte_cpu_to_be_16(0x1234);
    dport = rte_cpu_to_be_16(0x5678);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ipv4_fields", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "ipv4_fields_skb") == 0);
    vectors_and_legacy_equivalence();
    reject_profiles_transactionally();
    CHECK(context.live == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    return 0;
}
