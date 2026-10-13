#include "check.h"
#include "eal.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/icmp-echo-packet-view.h"
#include "runtime/icmpv4-packet-view.h"
#include "runtime/icmpv4-create.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>
#include <net/checksum.h>

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

static void refresh_linux_checksum(unsigned char *p, unsigned int n)
{
    p[2] = p[3] = 0;
    __sum16 sum = csum_fold(csum_partial(p, (int)n, 0));
    memcpy(p + 2, &sum, sizeof(sum));
}

static void quoted_ipv4_vectors(void)
{
    unsigned char quote[80] __attribute__((aligned(4))) = {0};
    quote[0] = 0x4f; /* IHL 60, including options. */
    quote[2] = 0x01; quote[3] = 0x00; /* Original packet continues past quote. */
    quote[8] = 64; quote[9] = 17;
    quote[12] = 192; quote[13] = 0; quote[14] = 2; quote[15] = 1;
    quote[16] = 198; quote[17] = 51; quote[18] = 100; quote[19] = 2;
    for (unsigned int i = 20; i < 60; ++i) quote[i] = (unsigned char)i;
    quote[60] = 0x12; quote[61] = 0x34; quote[62] = 0x56; quote[63] = 0x78;
    quote[64] = 0; quote[65] = 8; quote[66] = 0; quote[67] = 9;
    /* Independent wire checksum oracle, with the checksum field zeroed. */
    uint16_t ipcs = checksum(quote, 60);
    quote[10] = (unsigned char)(ipcs >> 8); quote[11] = (unsigned char)ipcs;

    struct ker_icmpv4_quoted_ipv4_view view;
    memset(&view, 0xa5, sizeof(view));
    struct ker_icmpv4_quoted_ipv4_view saved = view;
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote, 67, &view) == -EMSGSIZE);
    CHECK(!memcmp(&view, &saved, sizeof(view)));
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote, 68, &view) == 0);
    CHECK(view.header_length == 60 && view.quoted_length == 68 &&
        view.total_length == 256 && view.protocol == 17 && view.flow_available &&
        view.transport_length == 8 && !memcmp(view.transport, quote + 60, 8));
    /* Bytes beyond the original datagram length are capture padding. */
    quote[2] = 0; quote[3] = 62;
    quote[10] = quote[11] = 0;
    ipcs = checksum(quote, 60);
    quote[10] = (unsigned char)(ipcs >> 8); quote[11] = (unsigned char)ipcs;
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote, sizeof(quote), &view) == 0);
    CHECK(view.quoted_length == 62 && view.transport_length == 2 && !view.flow_available);
    quote[2] = 0; quote[3] = 0x40;
    quote[6] = 0; quote[7] = 1; /* Noninitial fragment. */
    quote[10] = quote[11] = 0;
    ipcs = checksum(quote, 60);
    quote[10] = (unsigned char)(ipcs >> 8); quote[11] = (unsigned char)ipcs;
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote, sizeof(quote), &view) == 0);
    CHECK(!view.flow_available && view.fragment_offset == 1);
    quote[0] = 0x44;
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote, sizeof(quote), &view) == -EINVAL);
}

static void generic_type_code_vectors(void)
{
    static const struct { uint8_t type, max_code; } supported[] = {
        {0, 0}, {8, 0}, {3, 15}, {5, 3}, {11, 1}, {12, 2}, {13, 0}, {14, 0},
    };
    static unsigned char body[28] = {0};
    body[0] = 0x45; body[2] = 0; body[3] = sizeof(body); body[8] = 64; body[9] = 17;
    struct sk_buff *skb = NULL;
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, body, sizeof(body), &skb) == 0);
    unsigned char *icmp = skb->data + ETH_HLEN + 20;
    struct ker_icmpv4_packet_view view;
    for (unsigned int i = 0; i < sizeof(supported) / sizeof(supported[0]); ++i) {
        for (unsigned int code = 0; code <= supported[i].max_code; ++code) {
            icmp[0] = supported[i].type;
            icmp[1] = (unsigned char)code;
            if (supported[i].type == 5) {
                icmp[4] = 192; icmp[5] = 0; icmp[6] = 2; icmp[7] = 254;
            } else {
                memset(icmp + 4, 0, 4);
            }
            icmp[2] = icmp[3] = 0;
            uint16_t c = checksum(icmp, 8 + sizeof(body));
            icmp[2] = (unsigned char)(c >> 8); icmp[3] = (unsigned char)c;
            struct rte_mbuf *mbuf = NULL;
            CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
            struct sk_buff *classified = NULL;
            CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
            ker_packet_free(mbuf);
            CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == 0);
            CHECK(view.type == supported[i].type && view.code == code &&
                view.message_length == 8 + sizeof(body) &&
                !memcmp(view.payload, body, sizeof(body)));
            if (supported[i].type == 5) {
                CHECK(view.quoted_length == sizeof(body) && view.quoted_ipv4 == view.payload &&
                    view.rest[0] == 192 && view.rest[1] == 0 &&
                    view.rest[2] == 2 && view.rest[3] == 254);
            }
            CHECK(ker_skb_free(classified) == 0);
        }
    }
    /* Source quench and obsolete address-mask messages stay explicit. */
    const uint8_t rejected[] = {4, 15, 16, 17, 18};
    for (unsigned int i = 0; i < sizeof(rejected); ++i) {
        icmp[0] = rejected[i]; icmp[1] = 0; icmp[2] = icmp[3] = 0;
        uint16_t c = checksum(icmp, 8 + sizeof(body));
        icmp[2] = (unsigned char)(c >> 8); icmp[3] = (unsigned char)c;
        struct rte_mbuf *mbuf = NULL;
        CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
        struct sk_buff *classified = NULL;
        CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
        ker_packet_free(mbuf);
        memset(&view, 0xa5, sizeof(view));
        struct ker_icmpv4_packet_view before = view;
        CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == -ENOTSUP);
        CHECK(!memcmp(&view, &before, sizeof(view)));
        CHECK(ker_skb_free(classified) == 0);
    }
    unsigned char *outer_ip = skb->data + ETH_HLEN;
    outer_ip[6] = 0x80; outer_ip[10] = outer_ip[11] = 0;
    uint16_t ip_sum = checksum(outer_ip, 20);
    outer_ip[10] = (unsigned char)(ip_sum >> 8); outer_ip[11] = (unsigned char)ip_sum;
    struct rte_mbuf *mbuf = NULL;
    CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
    struct sk_buff *classified = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
    ker_packet_free(mbuf);
    memset(&view, 0xa5, sizeof(view));
    struct ker_icmpv4_packet_view before = view;
    CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == -ENOTSUP);
    CHECK(!memcmp(&view, &before, sizeof(view)));
    CHECK(ker_skb_free(classified) == 0);
    CHECK(ker_skb_free(skb) == 0);
}

static void generic_constructor_vectors(void)
{
    const unsigned char rest[4] = {0x12, 0x34, 0x56, 0x78};
    unsigned char timestamp[12] = {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6};
    struct sk_buff *skb = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        14, 0, rest, 64, timestamp, sizeof(timestamp), &skb) == 0);
    const unsigned char *ip = skb->data + ETH_HLEN;
    const unsigned char *icmp = ip + 20;
    CHECK(ip[0] == 0x45 && ip[9] == 1 && icmp[0] == 14 && icmp[1] == 0 &&
        !memcmp(icmp + 4, rest, 4) && !memcmp(icmp + 8, timestamp, 12));
    CHECK(checksum(ip, 20) == 0 && checksum(icmp, 20) == 0);
    CHECK(ker_skb_free(skb) == 0);

    unsigned char quoted[40] __attribute__((aligned(4))) = {0};
    quoted[0] = 0x45; quoted[2] = 0; quoted[3] = sizeof(quoted);
    quoted[8] = 64; quoted[9] = 17;
    uint16_t ipcs = checksum(quoted, 20);
    quoted[10] = (unsigned char)(ipcs >> 8); quoted[11] = (unsigned char)ipcs;
    for (unsigned int i = 20; i < sizeof(quoted); ++i) quoted[i] = (unsigned char)i;
    unsigned char mtu_rest[4] = {0, 0, 0x05, 0x78};
    skb = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_error_create(&context, smac, dmac, source_ip, dest_ip,
        3, 4, mtu_rest, 64, quoted, sizeof(quoted), 60, &skb) == 0);
    ip = skb->data + ETH_HLEN; icmp = ip + 20;
    CHECK(((unsigned int)ip[2] << 8 | ip[3]) == 60 && icmp[0] == 3 && icmp[1] == 4 &&
        !memcmp(icmp + 4, mtu_rest, 4) && !memcmp(icmp + 8, quoted, 32));
    CHECK(checksum(ip, 20) == 0 && checksum(icmp, 40) == 0);
    CHECK(ker_skb_free(skb) == 0);
    skb = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_error_create(&context, smac, dmac, source_ip, dest_ip,
        3, 4, mtu_rest, 64, quoted, sizeof(quoted), 55, &skb) == -EMSGSIZE);
    CHECK(skb == (void *)(uintptr_t)0x1234 && context.live == 0);

    /* Default and larger path limits must not exceed the 576-byte baseline. */
    unsigned char long_quote[600] = {0};
    long_quote[0] = 0x45; long_quote[2] = 3; long_quote[3] = 0x84; /* original 900 */
    long_quote[8] = 64; long_quote[9] = 17;
    for (unsigned int i = 20; i < sizeof(long_quote); ++i)
        long_quote[i] = (unsigned char)i;
    const uint16_t path_limits[] = {0, 576, 1500};
    for (unsigned int i = 0; i < sizeof(path_limits) / sizeof(path_limits[0]); ++i) {
        CHECK(ker_icmpv4_ipv4_error_create(&context, smac, dmac, source_ip, dest_ip,
            3, 4, mtu_rest, 64, long_quote, sizeof(long_quote), path_limits[i], &skb) == 0);
        ip = skb->data + ETH_HLEN; icmp = ip + 20;
        CHECK(skb->len == ETH_HLEN + 576 && ip[2] == 2 && ip[3] == 0x40);
        CHECK(!memcmp(icmp + 8, long_quote, 548));
        CHECK(checksum(ip, 20) == 0 && checksum(icmp, 556) == 0);
        CHECK(ker_skb_free(skb) == 0);
    }

    unsigned char extension[16] = {
        0x20, 0, 0, 0, 0, 12, 3, 1,
        'e', 't', 'h', '0', 0, 0, 0, 0,
    };
    uint16_t extcs = checksum(extension, sizeof(extension));
    extension[2] = (unsigned char)(extcs >> 8); extension[3] = (unsigned char)extcs;
    const unsigned char probe_rest[4] = {0x12, 0x34, 7, 1};
    skb = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        42, 0, probe_rest, 64, extension, UINT_MAX, &skb) == -EMSGSIZE);
    CHECK(skb == (void *)(uintptr_t)0x1234 && context.live == 0);
    skb = NULL;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        42, 0, probe_rest, 64, extension, sizeof(extension), &skb) == 0);
    unsigned char *wire_icmp = skb->data + ETH_HLEN + 20;
    wire_icmp[1] = 23; wire_icmp[2] = wire_icmp[3] = 0;
    uint16_t wire_csum = checksum(wire_icmp, 8 + sizeof(extension));
    wire_icmp[2] = (unsigned char)(wire_csum >> 8); wire_icmp[3] = (unsigned char)wire_csum;
    struct rte_mbuf *mbuf = NULL;
    CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
    struct sk_buff *classified = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
    ker_packet_free(mbuf);
    struct ker_icmpv4_packet_view packet;
    CHECK(ker_icmpv4_packet_view_init(&context, classified, &packet) == 0 &&
        packet.type == 42 && packet.code == 23);
    struct ker_icmpv4_extended_echo_view probe;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &probe) == 0);
    CHECK(probe.identifier == rte_cpu_to_be_16(0x1234) && probe.sequence == 7 &&
        probe.local == 1 && probe.object_type == 1 && probe.identifier_length == 4 &&
        !memcmp(probe.identifier_data, "eth0", 4));
    CHECK(ker_skb_free(classified) == 0);
    CHECK(ker_skb_free(skb) == 0);

    const unsigned char reserved_probe_rest[4] = {0x12, 0x34, 7, 0x81};
    skb = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        42, 0, reserved_probe_rest, 64, extension, sizeof(extension), &skb) == -EINVAL);
    CHECK(skb == (void *)(uintptr_t)0x1234 && context.live == 0);

    const unsigned char reply_rest[4] = {0x12, 0x34, 7, 0x06};
    skb = NULL;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        43, 0, reply_rest, 255, NULL, 0, &skb) == 0);
    CHECK(skb->data[ETH_HLEN + 20] == 43 && skb->data[ETH_HLEN + 20 + 7] == 0x06 &&
        skb->data[ETH_HLEN + 8] == 255 && skb->data[ETH_HLEN + 6] == 0x40);
    CHECK(ker_skb_free(skb) == 0);
}

static void extended_echo_object_vectors(void)
{
    struct ker_icmpv4_packet_view packet = {.type = 42};
    packet.rest[3] = 1;
    struct ker_icmpv4_extended_echo_view view;
    unsigned char ext[28] __attribute__((aligned(4))) = {0};
    ext[0] = 0x20; ext[4] = 0; ext[5] = 8; ext[6] = 3;
    /* C-Type 2: a four-byte interface index. */
    ext[7] = 2; ext[8] = 0; ext[9] = 0; ext[10] = 0; ext[11] = 9;
    uint16_t c = checksum(ext, 12); ext[2] = (unsigned char)(c >> 8); ext[3] = (unsigned char)c;
    packet.payload = ext; packet.payload_length = 12;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.object_type == 2 && view.identifier_length == 4 && view.identifier_data[3] == 9);
    ext[2] = ext[3] = 0; /* RFC 4884 zero means checksum was omitted. */
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0);
    packet.rest[3] = 0x81; /* Reserved request bits are ignored on receipt. */
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0);
    packet.rest[3] = 1;
    /* C-Type 3: IPv4 address. */
    memset(ext, 0, sizeof(ext)); ext[0] = 0x20; ext[5] = 12; ext[6] = 3; ext[7] = 3;
    ext[8] = 0; ext[9] = 1; ext[10] = 4; ext[12] = 192; ext[13] = 0; ext[14] = 2; ext[15] = 4;
    c = checksum(ext, 16); ext[2] = (unsigned char)(c >> 8); ext[3] = (unsigned char)c;
    packet.payload_length = 16;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.object_type == 3 && view.identifier_length == 4 && view.identifier_data[0] == 192);
    CHECK(view.address_reserved == 0);
    /* RFC 8335 says to ignore the address object's Reserved octet on receipt. */
    ext[11] = 0xa5;
    ext[2] = ext[3] = 0;
    packet.payload_length = 16;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.address_reserved == 0xa5);
    ext[11] = 0;

    /* Unknown objects may surround the exactly-one interface identifier. */
    unsigned char objects[24] __attribute__((aligned(4))) = {
        0x20, 0, 0, 0,
        0, 4, 99, 77,
        0, 8, 3, 2, 0, 0, 0, 9,
        0, 4, 98, 76,
    };
    packet.payload = objects; packet.payload_length = 20;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.object_type == 2 && view.identifier_data[3] == 9);
    unsigned char duplicate[20] __attribute__((aligned(4))) = {
        0x20, 0, 0, 0,
        0, 8, 3, 2, 0, 0, 0, 1,
        0, 8, 3, 2, 0, 0, 0, 2,
    };
    packet.payload = duplicate; packet.payload_length = sizeof(duplicate);
    struct ker_icmpv4_extended_echo_view unchanged = view;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == -EINVAL &&
        !memcmp(&view, &unchanged, sizeof(view)));

    unsigned char long_name[28] __attribute__((aligned(4))) = {
        0x20, 0, 0, 0, 0, 24, 3, 1,
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q',0,0,0,
    };
    packet.payload = long_name; packet.payload_length = sizeof(long_name);
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.identifier_length == 17 && view.identifier_data[16] == 'q');
    long_name[5] = 20;
    packet.payload_length = 24; /* Exactly 16 name bytes: no NUL padding needed. */
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.identifier_length == 16 && view.identifier_data[15] == 'p');
    /* Public views can be assembled by callers; reject impossible lengths
     * before checksum code narrows the length or reads beyond the buffer. */
    packet.payload = ext; packet.payload_length = UINT_MAX;
    unchanged = view;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == -EINVAL &&
        !memcmp(&view, &unchanged, sizeof(view)));

    packet.payload = ext; packet.payload_length = 16;
    ext[11] = 0xa5;
    uint16_t extcs = checksum(ext, 16);
    ext[2] = (unsigned char)(extcs >> 8); ext[3] = (unsigned char)extcs;
    const unsigned char probe_rest[4] = {0x12, 0x34, 7, 1};
    struct sk_buff *bad_create = (void *)(uintptr_t)0x1234;
    CHECK(ker_icmpv4_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        42, 0, probe_rest, 64, ext, 16, &bad_create) == -EINVAL &&
        bad_create == (void *)(uintptr_t)0x1234);
    ext[11] = 0;

    /* IPv6 AFI is framed correctly for an IPv4 host but has no local backend. */
    memset(ext, 0, sizeof(ext)); ext[0] = 0x20; ext[5] = 24; ext[6] = 3; ext[7] = 3;
    ext[9] = 2; ext[10] = 16;
    for (unsigned int i = 0; i < 16; ++i) ext[12 + i] = (unsigned char)i;
    c = checksum(ext, 28); ext[2] = (unsigned char)(c >> 8); ext[3] = (unsigned char)c;
    packet.payload_length = 28;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == 0 &&
        view.identifier_length == 16 && view.identifier_data[15] == 15);
    ext[3] ^= 1;
    struct ker_icmpv4_extended_echo_view before = view;
    CHECK(ker_icmpv4_extended_echo_view_init(&packet, &view) == -EBADMSG);
    CHECK(!memcmp(&view, &before, sizeof(view)));
}

static void rfc4884_quote_boundary(void)
{
    unsigned char filler[136] = {0};
    struct sk_buff *skb = NULL;
    CHECK(ker_icmp_echo_ipv4_create(&context, smac, dmac, source_ip, dest_ip,
        0, 0, 8, 64, filler, sizeof(filler), &skb) == 0);
    unsigned char *ip = skb->data + ETH_HLEN;
    unsigned char *icmp = ip + 20;
    unsigned char *quoted = icmp + 8;
    memset(quoted, 0, 136);
    quoted[0] = 0x45; quoted[2] = 0; quoted[3] = 32;
    quoted[8] = 64; quoted[9] = 17;
    uint16_t c = checksum(quoted, 20);
    quoted[10] = (unsigned char)(c >> 8); quoted[11] = (unsigned char)c;
    quoted[20] = 0x12; quoted[21] = 0x34;
    quoted[22] = 0x56; quoted[23] = 0x78;
    icmp[0] = 3; icmp[1] = 3; icmp[4] = 0; icmp[5] = 32;
    unsigned char *ext = quoted + 128;
    ext[0] = 0x20; ext[4] = 0; ext[5] = 4; ext[6] = 1; ext[7] = 1;
    c = checksum(ext, 8); ext[2] = (unsigned char)(c >> 8); ext[3] = (unsigned char)c;
    icmp[2] = icmp[3] = 0;
    c = checksum(icmp, 8 + 136);
    icmp[2] = (unsigned char)(c >> 8); icmp[3] = (unsigned char)c;
    struct rte_mbuf *mbuf = NULL;
    CHECK(ker_skb_to_mbuf(skb, &mbuf) == 0);
    struct sk_buff *classified = NULL;
    CHECK(ker_eth_receive_copy_chain(&device, mbuf, 128, &classified) == 0);
    ker_packet_free(mbuf);
    struct ker_icmpv4_packet_view view;
    CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == 0);
    CHECK(view.quoted_length == 32 && view.extension_length == 8 &&
        view.extension == view.quoted_ipv4 + 128 && view.quoted_ipv4[20] == 0x12);
    unsigned char *received_icmp = classified->data + 20;
    received_icmp[8 + 128 + 2] = received_icmp[8 + 128 + 3] = 0;
    refresh_linux_checksum(received_icmp, 8 + 136);
    CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == 0);
    struct ker_icmpv4_packet_view unchanged = view;
    received_icmp[5] = 33;
    refresh_linux_checksum(received_icmp, 8 + 136);
    CHECK(checksum(received_icmp, 8 + 136) == 0);
    CHECK(csum_fold(csum_partial(received_icmp, 8 + 136, 0)) == 0);
    int malformed_error = ker_icmpv4_packet_view_init(&context, classified, &view);
    CHECK(malformed_error == -EINVAL);
    CHECK(!memcmp(&view, &unchanged, sizeof(view)));
    received_icmp[5] = 32;
    received_icmp[8 + 128 + 3] = 1;
    refresh_linux_checksum(received_icmp, 8 + 136);
    CHECK(ker_icmpv4_packet_view_init(&context, classified, &view) == -EBADMSG);
    CHECK(!memcmp(&view, &unchanged, sizeof(view)));
    CHECK(ker_skb_free(classified) == 0);
    CHECK(ker_skb_free(skb) == 0);
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
    skb->ip_summed = CHECKSUM_PARTIAL;
    skb->csum_start = skb_headroom(skb) + ETH_HLEN + 20;
    skb->csum_offset = 2;
    unsigned char original[128];
    CHECK(skb->len <= sizeof(original));
    memcpy(original, skb->data, skb->len);
    unsigned char original_summed = skb->ip_summed;
    uint16_t original_start = skb->csum_start, original_offset = skb->csum_offset;
    struct rte_mbuf *legacy = NULL;
    CHECK(ker_skb_to_mbuf_chain_software_checksum(skb, 1, &legacy) == 0);
    unsigned char checksum_bytes[2];
    CHECK(rte_pktmbuf_read(legacy, ETH_HLEN + 20 + 2, 2, checksum_bytes));
    CHECK(checksum_bytes[0] == 0xff && checksum_bytes[1] == 0xff);
    CHECK(!memcmp(original, skb->data, skb->len) && skb->ip_summed == original_summed &&
        skb->csum_start == original_start && skb->csum_offset == original_offset);
    ker_packet_free(legacy);
    struct rte_mbuf *exact = NULL;
    CHECK(ker_skb_to_mbuf_chain_software_checksum_exact(skb, 1, &exact) == 0);
    CHECK(rte_pktmbuf_read(exact, ETH_HLEN + 20 + 2, 2, checksum_bytes));
    CHECK(checksum_bytes[0] == 0 && checksum_bytes[1] == 0);
    CHECK(!memcmp(original, skb->data, skb->len) && skb->ip_summed == original_summed &&
        skb->csum_start == original_start && skb->csum_offset == original_offset);
    CHECK(skb->data[ETH_HLEN + 20 + 2] == 0 && skb->data[ETH_HLEN + 20 + 3] == 0);
    ker_packet_free(exact);
    skb->ip_summed = CHECKSUM_NONE;
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
    quoted_ipv4_vectors();
    generic_type_code_vectors();
    generic_constructor_vectors();
    extended_echo_object_vectors();
    rfc4884_quote_boundary();
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
