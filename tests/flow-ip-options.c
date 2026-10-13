#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/memory.h"
#include <rte_ether.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

static struct ker_packet_pool pool;

struct mbuf_snapshot {
    struct rte_mbuf *segment;
    struct rte_mbuf *next;
    uint16_t data_off, data_len, nb_segs, refcnt;
    uint32_t pkt_len;
    uint64_t ol_flags;
};

static unsigned int snapshot_packet(struct rte_mbuf *m, struct mbuf_snapshot s[2])
{
    unsigned int count = 0;
    for (struct rte_mbuf *part = m; part; part = part->next) {
        CHECK(count < 2);
        s[count++] = (struct mbuf_snapshot){.segment = part, .next = part->next,
            .data_off = part->data_off, .data_len = part->data_len, .nb_segs = part->nb_segs,
            .pkt_len = part->pkt_len, .ol_flags = part->ol_flags,
            .refcnt = rte_mbuf_refcnt_read(part)};
    }
    return count;
}

static void check_snapshot(const struct mbuf_snapshot s[2], unsigned int count,
    const uint8_t *expected, size_t length)
{
    size_t offset = 0;
    for (unsigned int i = 0; i < count; ++i) {
        struct rte_mbuf *m = s[i].segment;
        CHECK(m->next == s[i].next && m->data_off == s[i].data_off &&
            m->data_len == s[i].data_len && m->nb_segs == s[i].nb_segs &&
            m->pkt_len == s[i].pkt_len && m->ol_flags == s[i].ol_flags &&
            rte_mbuf_refcnt_read(m) == s[i].refcnt);
        CHECK(offset + m->data_len <= length);
        CHECK(!memcmp(rte_pktmbuf_mtod(m, const uint8_t *), expected + offset, m->data_len));
        offset += m->data_len;
    }
    CHECK(offset == length);
}

static size_t make_packet(uint8_t *b, unsigned int ihl, int proto, size_t l4len,
    size_t padding)
{
    size_t iplen = ihl * 4 + l4len, n = 14 + iplen + padding;
    memset(b, 0, n);
    b[12] = 8;
    uint8_t *ip = b + 14;
    ip[0] = (uint8_t)(0x40 | ihl); ip[2] = (uint8_t)(iplen >> 8); ip[3] = (uint8_t)iplen;
    ip[8] = 64; ip[9] = (uint8_t)proto;
    ip[12] = 192; ip[14] = 2; ip[15] = 1;
    ip[16] = 10; ip[19] = 1;
    for (unsigned int i = 20; i < ihl * 4; ++i) ip[i] = (uint8_t)(i ^ 0xa5);
    uint8_t *l4 = ip + ihl * 4;
    l4[0] = 0x04; l4[1] = 0xd2; l4[2] = 0x01; l4[3] = 0xbb;
    if (proto == IPPROTO_TCP) l4[12] = (uint8_t)((l4len >= 60 ? 15 : 5) << 4);
    else { l4[4] = (uint8_t)(l4len >> 8); l4[5] = (uint8_t)l4len; }
    return n;
}

static void reverse_ipv4_packet(uint8_t *b, unsigned int ihl)
{
    uint8_t *ip = b + 14;
    for (unsigned int i = 0; i < 4; ++i) {
        uint8_t tmp = ip[12 + i]; ip[12 + i] = ip[16 + i]; ip[16 + i] = tmp;
    }
    uint8_t *l4 = ip + ihl * 4;
    for (unsigned int i = 0; i < 2; ++i) {
        uint8_t tmp = l4[i]; l4[i] = l4[2 + i]; l4[2 + i] = tmp;
    }
}

static struct rte_mbuf *packet(const uint8_t *bytes, size_t length, size_t split)
{
    struct rte_mbuf *head = ker_packet_alloc(&pool);
    CHECK(head != NULL);
    size_t first = split == SIZE_MAX ? length : split;
    uint8_t *dst = (uint8_t *)rte_pktmbuf_append(head, (uint16_t)first);
    CHECK(dst != NULL); memcpy(dst, bytes, first);
    if (split != SIZE_MAX) {
        struct rte_mbuf *tail = ker_packet_alloc(&pool);
        CHECK(tail != NULL);
        dst = (uint8_t *)rte_pktmbuf_append(tail, (uint16_t)(length - split));
        CHECK(dst != NULL); memcpy(dst, bytes + split, length - split);
        CHECK(rte_pktmbuf_chain(head, tail) == 0);
    }
    return head;
}

static bool key_equal(const struct ker_flow_key *a, const struct ker_flow_key *b)
{
    return a->domain == b->domain && a->family == b->family && a->protocol == b->protocol &&
        a->local_port == b->local_port && a->remote_port == b->remote_port &&
        !memcmp(a->local, b->local, 16) && !memcmp(a->remote, b->remote, 16);
}

static void valid_cases(void)
{
    uint8_t bytes[256];
    for (unsigned int ihl = 5; ihl <= 15; ++ihl) {
        const int protocols[] = {IPPROTO_UDP, IPPROTO_TCP};
        for (size_t p = 0; p < sizeof(protocols) / sizeof(protocols[0]); ++p) {
            int proto = protocols[p];
            size_t l4len = proto == IPPROTO_UDP ? 8 : 20;
            size_t length = make_packet(bytes, ihl, proto, l4len, 9);
            struct ker_flow_key expected = {.domain = 71, .family = 4, .protocol = (uint8_t)proto,
                .local_port = 443, .remote_port = 1234}, actual;
            expected.local[12] = 10; expected.local[15] = 1;
            expected.remote[12] = 192; expected.remote[14] = 2; expected.remote[15] = 1;
            uint32_t expected_hash = proto == IPPROTO_TCP ? UINT32_C(0xac9d6d4c) : UINT32_C(0x647bdf7d);
            for (int dir = KER_FLOW_INGRESS; dir <= KER_FLOW_EGRESS; ++dir) {
                struct ker_flow_key wanted = expected;
                if (dir == KER_FLOW_EGRESS) {
                    memcpy(wanted.local, expected.remote, 16); memcpy(wanted.remote, expected.local, 16);
                    wanted.local_port = 1234; wanted.remote_port = 443;
                }
                uint32_t wanted_hash;
                CHECK(ker_flow_hash(&wanted, 0x1234, &wanted_hash) == 0);
                for (size_t split = 0; split <= length; ++split) {
                    struct rte_mbuf *m = packet(bytes, length, split == length ? SIZE_MAX : split);
                    struct mbuf_snapshot snapshot[2];
                    unsigned int segments = snapshot_packet(m, snapshot);
                    memset(&actual, 0xa5, sizeof(actual));
                    CHECK(ker_flow_parse(m, 71, (enum ker_flow_direction)dir, &actual) == 0);
                    CHECK(key_equal(&actual, &wanted));
                    uint32_t got;
                    CHECK(ker_flow_hash(&actual, 0x1234, &got) == 0 && got == wanted_hash);
                    if (dir == KER_FLOW_INGRESS) CHECK(got == expected_hash);
                    check_snapshot(snapshot, segments, bytes, length);
                    rte_pktmbuf_free(m);
                }

                /* A real reverse tuple parsed as egress must have the same canonical key. */
                uint8_t reverse[256]; memcpy(reverse, bytes, length);
                reverse_ipv4_packet(reverse, ihl);
                for (size_t split = 0; split <= length; ++split) {
                    struct rte_mbuf *m = packet(reverse, length,
                        split == length ? SIZE_MAX : split);
                    struct mbuf_snapshot snapshot[2];
                    unsigned int segments = snapshot_packet(m, snapshot);
                    struct ker_flow_key actual;
                    CHECK(ker_flow_parse(m, 71, KER_FLOW_EGRESS, &actual) == 0);
                    CHECK(key_equal(&actual, &expected));
                    uint32_t got;
                    CHECK(ker_flow_hash(&actual, 0x1234, &got) == 0 && got == expected_hash);
                    check_snapshot(snapshot, segments, reverse, length);
                    rte_pktmbuf_free(m);
                }
            }
        }
    }
    /* Maximum TCP data offset with maximum IPv4 IHL remains bounded and valid. */
    size_t length = make_packet(bytes, 15, IPPROTO_TCP, 60, 0);
    struct ker_flow_key key;
    for (size_t split = 0; split <= length; ++split) {
        struct rte_mbuf *m = packet(bytes, length, split == length ? SIZE_MAX : split);
        CHECK(ker_flow_parse(m, 71, KER_FLOW_INGRESS, &key) == 0);
        rte_pktmbuf_free(m);
    }
}

static void reject_packet(const uint8_t *bytes, size_t n, int expected_error)
{
    for (size_t split = 0; split <= n; ++split) {
        struct rte_mbuf *m = packet(bytes, n, split == n ? SIZE_MAX : split);
        struct mbuf_snapshot snapshot[2];
        unsigned int segments = snapshot_packet(m, snapshot);
        struct ker_flow_key key = {.domain = 99, .family = 6}, before;
        memcpy(&before, &key, sizeof(before));
        CHECK(ker_flow_parse(m, 71, KER_FLOW_INGRESS, &key) == expected_error);
        CHECK(!memcmp(&key, &before, sizeof(key)));
        check_snapshot(snapshot, segments, bytes, n);
        rte_pktmbuf_free(m);
    }
}

static void malformed_cases(void)
{
    uint8_t bytes[256];
    size_t n = make_packet(bytes, 5, IPPROTO_UDP, 8, 16);
    bytes[14] = 0x44; reject_packet(bytes, n, -EINVAL);
    bytes[14] = 0x45; bytes[16] = 0; bytes[17] = 19; reject_packet(bytes, n, -EINVAL);
    bytes[17] = 28; n = 14 + 19; reject_packet(bytes, n, -EMSGSIZE);

    for (unsigned int ihl = 6; ihl <= 15; ++ihl) {
        size_t header = ihl * 4;
        n = make_packet(bytes, ihl, IPPROTO_UDP, 8, 24);
        bytes[16] = 0; bytes[17] = (uint8_t)(header - 1);
        reject_packet(bytes, n, -EINVAL); /* Declared total is shorter than IHL. */

        n = make_packet(bytes, ihl, IPPROTO_UDP, 8, 24);
        n = 14 + header - 1;
        reject_packet(bytes, n, -EMSGSIZE); /* Options are physically truncated. */

        n = make_packet(bytes, ihl, IPPROTO_UDP, 8, 24);
        bytes[16] = (uint8_t)(header >> 8); bytes[17] = (uint8_t)(header + 7);
        reject_packet(bytes, n, -EINVAL); /* UDP's IP payload is seven bytes despite padding. */

        n = make_packet(bytes, ihl, IPPROTO_UDP, 8, 24);
        bytes[16] = (uint8_t)(header >> 8); bytes[17] = (uint8_t)(header + 8);
        uint8_t *udp = bytes + 14 + header;
        udp[4] = 0; udp[5] = 9;
        reject_packet(bytes, n, -EINVAL); /* UDP length exceeds declared IP payload. */

        n = make_packet(bytes, ihl, IPPROTO_TCP, 20, 24);
        bytes[14 + header + 12] = 0x60;
        bytes[16] = (uint8_t)(header >> 8); bytes[17] = (uint8_t)(header + 20);
        reject_packet(bytes, n, -EINVAL); /* TCP data offset exceeds declared payload. */
    }

    n = make_packet(bytes, 5, IPPROTO_UDP, 7, 16); bytes[17] = 27;
    reject_packet(bytes, n, -EINVAL);
    n = make_packet(bytes, 5, IPPROTO_TCP, 20, 16); bytes[46] = 0x40;
    reject_packet(bytes, n, -EINVAL);
    n = make_packet(bytes, 15, IPPROTO_TCP, 20, 0); bytes[14] = 0x4f; n = 14 + 59;
    reject_packet(bytes, n, -EMSGSIZE);
    n = make_packet(bytes, 6, IPPROTO_UDP, 8, 0); bytes[23] = IPPROTO_ICMP;
    reject_packet(bytes, n, -ENOTSUP);
    n = make_packet(bytes, 5, IPPROTO_UDP, 8, 0); bytes[20] = 0x20;
    reject_packet(bytes, n, -ENOTSUP);
    bytes[20] = 0; bytes[21] = 1; reject_packet(bytes, n, -ENOTSUP);
}

int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_flow_ip_opts", 511, 0, 512, SOCKET_ID_ANY) == 0);
    valid_cases(); malformed_cases();
    CHECK(ker_packet_pool_cleanup(&pool) == 0); CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("IPv4 flow options: variable IHL parsing and bounded segmented headers passed");
    return 0;
}
