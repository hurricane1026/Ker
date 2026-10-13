#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <rte_ether.h>
#include <rte_lcore.h>
#include <netinet/in.h>
#include <string.h>

static struct ker_packet_pool pool;

#define SNAPSHOT_SEGMENTS 4U
#define SNAPSHOT_BYTES 160U
struct segment_snapshot {
    struct rte_mbuf *mbuf;
    struct rte_mbuf *next;
    uint16_t data_off, data_len, nb_segs, refcnt;
    uint32_t pkt_len;
    uint64_t ol_flags;
    uint8_t bytes[SNAPSHOT_BYTES];
};
struct chain_snapshot {
    unsigned int count;
    struct segment_snapshot segment[SNAPSHOT_SEGMENTS];
};
struct receive_check {
    struct rte_mbuf *packet;
    struct ker_flow_key key;
    struct chain_snapshot snapshot;
    unsigned int delivered;
};
static bool key_equal(const struct ker_flow_key *a, const struct ker_flow_key *b);

static void take_snapshot(struct rte_mbuf *const *segments, unsigned int count,
    struct chain_snapshot *snapshot)
{
    CHECK(count && count <= SNAPSHOT_SEGMENTS);
    snapshot->count = count;
    for (unsigned int i = 0; i < count; ++i) {
        struct rte_mbuf *m = segments[i];
        struct segment_snapshot *s = &snapshot->segment[i];
        CHECK(m && m->data_len <= SNAPSHOT_BYTES);
        s->mbuf = m; s->next = m->next; s->data_off = m->data_off;
        s->data_len = m->data_len; s->nb_segs = m->nb_segs;
        s->pkt_len = m->pkt_len; s->ol_flags = m->ol_flags;
        s->refcnt = rte_mbuf_refcnt_read(m);
        memcpy(s->bytes, rte_pktmbuf_mtod(m, const uint8_t *), m->data_len);
    }
}

static void check_snapshot(const struct chain_snapshot *snapshot)
{
    for (unsigned int i = 0; i < snapshot->count; ++i) {
        const struct segment_snapshot *s = &snapshot->segment[i];
        struct rte_mbuf *m = s->mbuf;
        CHECK(m->next == s->next && m->data_off == s->data_off &&
            m->data_len == s->data_len && m->nb_segs == s->nb_segs &&
            m->pkt_len == s->pkt_len && m->ol_flags == s->ol_flags &&
            rte_mbuf_refcnt_read(m) == s->refcnt);
        CHECK(memcmp(s->bytes, rte_pktmbuf_mtod(m, const uint8_t *), m->data_len) == 0);
    }
}

static void snapshot_packet(struct rte_mbuf *packet, unsigned int count,
    struct chain_snapshot *snapshot)
{
    struct rte_mbuf *segments[SNAPSHOT_SEGMENTS];
    CHECK(count && count <= SNAPSHOT_SEGMENTS);
    struct rte_mbuf *m = packet;
    for (unsigned int i = 0; i < count; ++i) {
        CHECK(m != NULL);
        segments[i] = m;
        m = m->next;
    }
    CHECK(m == NULL);
    take_snapshot(segments, count, snapshot);
}

static void receive_check(void *arg, const struct ker_flow_key *key, struct rte_mbuf *packet)
{
    struct receive_check *check = arg;
    CHECK(packet == check->packet && key_equal(key, &check->key));
    check_snapshot(&check->snapshot);
    ++check->delivered;
    rte_pktmbuf_free(packet);
}

static bool key_equal(const struct ker_flow_key *a, const struct ker_flow_key *b)
{
    return a->domain == b->domain && a->family == b->family && a->protocol == b->protocol &&
        a->local_port == b->local_port && a->remote_port == b->remote_port &&
        memcmp(a->local, b->local, sizeof(a->local)) == 0 &&
        memcmp(a->remote, b->remote, sizeof(a->remote)) == 0;
}

static size_t packet_bytes(uint8_t *bytes, int family, int protocol, int reverse,
    size_t tcp_header, size_t payload, size_t padding)
{
    size_t transport = (protocol == IPPROTO_TCP ? tcp_header : 8) + payload;
    size_t length = 14 + (family == 4 ? 20 : 40) + transport;
    memset(bytes, 0, length + padding);
    bytes[12] = family == 4 ? 0x08 : 0x86;
    bytes[13] = family == 4 ? 0x00 : 0xdd;
    uint8_t *ip = bytes + 14;
    if (family == 4) {
        ip[0] = 0x45; ip[2] = 0; ip[3] = (uint8_t)(20 + transport);
        ip[8] = 64; ip[9] = (uint8_t)protocol;
        static const uint8_t a[4] = {192, 0, 2, 1};
        static const uint8_t b[4] = {10, 0, 0, 1};
        memcpy(ip + 12, reverse ? b : a, 4);
        memcpy(ip + 16, reverse ? a : b, 4);
    } else {
        ip[0] = 0x60; ip[4] = 0; ip[5] = (uint8_t)transport;
        ip[6] = (uint8_t)protocol; ip[7] = 64;
        uint8_t *src = ip + 8, *dst = ip + 24;
        src[0] = reverse ? 0x20 : 0x30; src[15] = reverse ? 1 : 2;
        dst[0] = reverse ? 0x30 : 0x20; dst[15] = reverse ? 2 : 1;
    }
    uint8_t *l4 = ip + (family == 4 ? 20 : 40);
    l4[0] = reverse ? 0x01 : 0x04; l4[1] = reverse ? 0xbb : 0xd2;
    l4[2] = reverse ? 0x04 : 0x01; l4[3] = reverse ? 0xd2 : 0xbb;
    if (protocol == IPPROTO_TCP) l4[12] = (uint8_t)((tcp_header / 4) << 4);
    else { l4[4] = (uint8_t)(transport >> 8); l4[5] = (uint8_t)transport; }
    return length + padding;
}

static struct rte_mbuf *chain(const uint8_t *bytes, const size_t *parts, size_t count)
{
    struct rte_mbuf *head = NULL;
    for (size_t i = 0, offset = 0; i < count; ++i) {
        struct rte_mbuf *segment = ker_packet_alloc(&pool);
        CHECK(segment != NULL);
        if (parts[i]) {
            uint8_t *dst = (uint8_t *)rte_pktmbuf_append(segment, (uint16_t)parts[i]);
            CHECK(dst != NULL);
            memcpy(dst, bytes + offset, parts[i]);
            offset += parts[i];
        }
        if (!head) head = segment;
        else CHECK(rte_pktmbuf_chain(head, segment) == 0);
    }
    CHECK(head != NULL);
    return head;
}

static void compare_parse(const uint8_t *bytes, size_t length, const size_t *parts, size_t count,
    int family, int protocol, enum ker_flow_direction direction)
{
    struct rte_mbuf *linear = chain(bytes, &length, 1);
    struct rte_mbuf *segmented = chain(bytes, parts, count);
    struct ker_flow_key expected = {.domain = 71, .family = (uint8_t)family,
        .protocol = (uint8_t)protocol, .local_port = 443, .remote_port = 1234}, actual;
    if (family == 4) {
        expected.local[12] = 10; expected.local[15] = 1;
        expected.remote[12] = 192; expected.remote[14] = 2; expected.remote[15] = 1;
    } else {
        expected.local[0] = 0x20; expected.local[15] = 1;
        expected.remote[0] = 0x30; expected.remote[15] = 2;
    }
    memset(&actual, 0xa5, sizeof(actual));
    struct ker_flow_key parsed_linear = {0};
    CHECK(ker_flow_parse(linear, 71, direction, &parsed_linear) == 0);
    CHECK(ker_flow_parse(segmented, 71, direction, &actual) == 0);
    CHECK(key_equal(&expected, &parsed_linear));
    CHECK(key_equal(&expected, &actual));
    CHECK(actual.family == family && actual.protocol == protocol);
    uint32_t expected_hash, actual_hash;
    CHECK(ker_flow_hash(&expected, 0x1234, &expected_hash) == 0);
    CHECK(ker_flow_hash(&actual, 0x1234, &actual_hash) == 0 && expected_hash == actual_hash);
    uint32_t fixed_hash = family == 4 ?
        (protocol == IPPROTO_TCP ? UINT32_C(0xac9d6d4c) : UINT32_C(0x647bdf7d)) :
        (protocol == IPPROTO_TCP ? UINT32_C(0x9dfc0169) : UINT32_C(0x8de37a5a));
    CHECK(actual_hash == fixed_hash);
    rte_pktmbuf_free(linear);
    rte_pktmbuf_free(segmented);
}

static void handoff_checks(void)
{
    uint16_t bucket_owner[KER_FLOW_BUCKETS];
    for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i) bucket_owner[i] = 1;
    uint8_t bytes[SNAPSHOT_BYTES];
    size_t local_length = packet_bytes(bytes, 6, IPPROTO_TCP, 0, 20, 0, 0);
    struct rte_mbuf *local_linear = chain(bytes, &local_length, 1);
    struct ker_flow_key local_key;
    CHECK(ker_flow_parse(local_linear, 72, KER_FLOW_INGRESS, &local_key) == 0);
    rte_pktmbuf_free(local_linear);
    struct ker_flow_special special = {.key = local_key, .owner = 0};
    struct ker_flow_config config = {.worker_count = 2, .bucket_owner = bucket_owner,
        .special = &special, .special_count = 1, .inbox_capacity = 1,
        .name = "ker_flow_chain_handoff", .socket_id = SOCKET_ID_ANY};
    struct ker_flow_fabric fabric = {0};
    struct ker_worker workers[2] = {0};
    struct ker_flow_context contexts[2] = {0};
    struct receive_check checks[2] = {0};
    struct ker_worker_config worker_config = {.timer_budget = 1, .handoff_budget = 1};
    struct ker_worker_ops worker_ops = {0};
    CHECK(ker_flow_fabric_init(&fabric, &config) == 0);
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK(ker_worker_init(&workers[i], &pool, &worker_config, &worker_ops) == 0);
        CHECK(ker_flow_attach(&contexts[i], &fabric, &workers[i], i, receive_check, &checks[i]) == 0);
    }

    size_t local_parts[] = {0, 11, 0, local_length - 11};
    struct rte_mbuf *local = chain(bytes, local_parts, 4);
    checks[0].packet = local; checks[0].key = local_key;
    snapshot_packet(local, 4, &checks[0].snapshot);
    CHECK(ker_flow_submit(&contexts[0], 72, KER_FLOW_INGRESS, &local) == 0 && local == NULL);
    CHECK(checks[0].delivered == 1);

    const int protocols[] = {IPPROTO_TCP, IPPROTO_UDP};
    for (unsigned int p = 0; p < sizeof(protocols) / sizeof(protocols[0]); ++p) {
        size_t length = packet_bytes(bytes, 6, protocols[p], 1,
            protocols[p] == IPPROTO_TCP ? 60 : 8, 13, 7);
        size_t parts[] = {0, 17, length - 17, 0};
        struct rte_mbuf *first = chain(bytes, parts, 4);
        struct rte_mbuf *second = chain(bytes, parts, 4);
        struct ker_flow_key key;
        CHECK(ker_flow_parse(first, 71, KER_FLOW_EGRESS, &key) == 0);

        /* A malformed submit leaves both the caller pointer and every chain
         * field intact. Restore the malformed length before any free. */
        struct chain_snapshot first_snapshot;
        snapshot_packet(first, 4, &first_snapshot);
        uint32_t saved_length = first->pkt_len;
        first->pkt_len++;
        struct chain_snapshot malformed_snapshot;
        snapshot_packet(first, 4, &malformed_snapshot);
        struct rte_mbuf *malformed = first;
        CHECK(ker_flow_submit(&contexts[0], 71, KER_FLOW_EGRESS, &malformed) == -EINVAL);
        CHECK(malformed == first);
        check_snapshot(&malformed_snapshot);
        first->pkt_len = saved_length;
        check_snapshot(&first_snapshot);

        checks[1].packet = first; checks[1].key = key;
        snapshot_packet(first, 4, &checks[1].snapshot);
        CHECK(ker_flow_submit(&contexts[0], 71, KER_FLOW_EGRESS, &first) == 0 && first == NULL);

        struct chain_snapshot second_snapshot;
        snapshot_packet(second, 4, &second_snapshot);
        CHECK(ker_flow_submit(&contexts[0], 71, KER_FLOW_EGRESS, &second) == -ENOBUFS);
        CHECK(second == second_snapshot.segment[0].mbuf);
        check_snapshot(&second_snapshot);

        CHECK(ker_flow_poll(&contexts[1], 1) == 1);
        CHECK(checks[1].delivered == p * 2 + 1);
        checks[1].packet = second; checks[1].key = key;
        checks[1].snapshot = second_snapshot;
        CHECK(ker_flow_submit(&contexts[0], 71, KER_FLOW_EGRESS, &second) == 0 && second == NULL);
        CHECK(ker_flow_poll(&contexts[1], 1) == 1);
        CHECK(checks[1].delivered == (p + 1) * 2);
    }
    for (unsigned int i = 0; i < 2; ++i) {
        CHECK(ker_flow_detach(&contexts[i]) == 0);
        CHECK(ker_worker_cleanup(&workers[i]) == 0);
    }
    CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "ker_flow_chain_packets", 512, 0, 512, SOCKET_ID_ANY) == 0);
    uint8_t bytes[160];
    for (int family = 4; family <= 6; family += 2)
        for (int protocol = IPPROTO_TCP; protocol <= IPPROTO_UDP; protocol += 11)
            for (int reverse = 0; reverse <= 1; ++reverse) {
                size_t tcp_header = protocol == IPPROTO_TCP && reverse ? 60 :
                    (protocol == IPPROTO_TCP ? 20 : 8);
                size_t payload = reverse ? 13 : 0;
                size_t padding = reverse ? 7 : 0;
                size_t length = packet_bytes(bytes, family, protocol, reverse,
                    tcp_header, payload, padding);
                enum ker_flow_direction direction = reverse ? KER_FLOW_EGRESS : KER_FLOW_INGRESS;
                for (size_t cut = 1; cut < length; ++cut) {
                    size_t parts[] = {cut, length - cut};
                    compare_parse(bytes, length, parts, 2, family, protocol, direction);
                }
                size_t triple[] = {0, length / 3, 0, length / 3, length - 2 * (length / 3), 0};
                compare_parse(bytes, length, triple, 6, family, protocol, direction);
                size_t bytewise[160];
                for (size_t i = 0; i < length; ++i) bytewise[i] = 1;
                compare_parse(bytes, length, bytewise, length, family, protocol, direction);
            }
    size_t indirect_length = packet_bytes(bytes, 6, IPPROTO_TCP, 1, 60, 13, 7);
    struct rte_mbuf *linear = chain(bytes, &indirect_length, 1);
    struct ker_flow_key direct_key, indirect_key;
    CHECK(ker_flow_parse(linear, 71, KER_FLOW_EGRESS, &direct_key) == 0);
    struct rte_mbuf *clone = rte_pktmbuf_clone(linear, pool.mbufs);
    CHECK(clone != NULL && !RTE_MBUF_DIRECT(clone));
    CHECK(rte_mbuf_refcnt_read(linear) == 2);
    CHECK(ker_flow_parse(linear, 71, KER_FLOW_EGRESS, &indirect_key) == 0);
    CHECK(key_equal(&direct_key, &indirect_key));
    CHECK(ker_flow_parse(clone, 71, KER_FLOW_EGRESS, &indirect_key) == 0);
    CHECK(key_equal(&direct_key, &indirect_key));
    rte_pktmbuf_free(clone);
    rte_pktmbuf_free(linear);
    size_t indirect_parts[] = {20, 30, indirect_length - 50};
    struct rte_mbuf *segmented = chain(bytes, indirect_parts, 3);
    clone = rte_pktmbuf_clone(segmented, pool.mbufs);
    CHECK(clone != NULL && clone->nb_segs == 3 && !RTE_MBUF_DIRECT(clone));
    CHECK(ker_flow_parse(clone, 71, KER_FLOW_EGRESS, &indirect_key) == 0);
    CHECK(key_equal(&direct_key, &indirect_key));
    rte_pktmbuf_free(clone);
    rte_pktmbuf_free(segmented);
    size_t whole = packet_bytes(bytes, 4, IPPROTO_UDP, 0, 8, 0, 0);
    size_t split[] = {20, whole - 20};
    struct rte_mbuf *bad = chain(bytes, split, 2);
    struct ker_flow_key sentinel, unchanged;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    memcpy(&unchanged, &sentinel, sizeof(unchanged));
    struct rte_mbuf *known_segments[] = {bad, bad->next};
    struct chain_snapshot valid_snapshot;
    take_snapshot(known_segments, 2, &valid_snapshot);
    uint32_t saved_len = bad->pkt_len;
    bad->pkt_len++;
    struct chain_snapshot malformed_snapshot;
    take_snapshot(known_segments, 2, &malformed_snapshot);
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == -EINVAL);
    CHECK(memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    check_snapshot(&malformed_snapshot);
    bad->pkt_len = saved_len;
    struct rte_mbuf *tail = bad->next;
    tail->next = bad;
    take_snapshot(known_segments, 2, &malformed_snapshot);
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == -EINVAL);
    check_snapshot(&malformed_snapshot);
    tail->next = NULL; /* Restore valid ownership topology before freeing. */
    CHECK(memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    uint16_t saved_segs = bad->nb_segs;
    bad->nb_segs = 0;
    take_snapshot(known_segments, 2, &malformed_snapshot);
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == -EINVAL);
    check_snapshot(&malformed_snapshot);
    bad->nb_segs = saved_segs;
    bad->nb_segs = 3;
    take_snapshot(known_segments, 2, &malformed_snapshot);
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == -EINVAL);
    check_snapshot(&malformed_snapshot);
    bad->nb_segs = saved_segs;
    CHECK(memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    check_snapshot(&valid_snapshot);
    uint16_t saved_off = tail->data_off;
    uint16_t saved_data_len = tail->data_len;
    tail->data_off = tail->buf_len;
    tail->data_len = 1;
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == -EINVAL);
    CHECK(tail->data_off == tail->buf_len && tail->data_len == 1 &&
        tail->nb_segs == valid_snapshot.segment[1].nb_segs &&
        tail->pkt_len == valid_snapshot.segment[1].pkt_len &&
        tail->ol_flags == valid_snapshot.segment[1].ol_flags &&
        rte_mbuf_refcnt_read(tail) == valid_snapshot.segment[1].refcnt &&
        memcmp((uint8_t *)tail->buf_addr + saved_off,
            valid_snapshot.segment[1].bytes, saved_data_len) == 0);
    tail->data_off = saved_off;
    tail->data_len = saved_data_len;
    CHECK(memcmp(&sentinel, &unchanged, sizeof(sentinel)) == 0);
    check_snapshot(&valid_snapshot);
    rte_mbuf_refcnt_update(tail, 1);
    CHECK(ker_flow_parse(bad, 71, KER_FLOW_INGRESS, &sentinel) == 0);
    rte_mbuf_refcnt_update(tail, -1);
    CHECK(sentinel.domain == 71 && sentinel.family == 4 && sentinel.protocol == IPPROTO_UDP);
    rte_pktmbuf_free(bad);
    handoff_checks();
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("Flow parser segmented-chain key/hash invariance passed");
    return 0;
}
