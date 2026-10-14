#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/memory.h"
#include <errno.h>
#include <string.h>

static struct ker_packet_pool pool;
static struct rte_mbuf *packet(const unsigned char *bytes, size_t size, size_t split)
{
    struct rte_mbuf *head = ker_packet_alloc(&pool);
    struct rte_mbuf *tail = ker_packet_alloc(&pool);
    CHECK(head && tail);
    void *p = rte_pktmbuf_append(head, (uint16_t)split);
    CHECK(p); memcpy(p, bytes, split);
    p = rte_pktmbuf_append(tail, (uint16_t)(size - split));
    CHECK(p); memcpy(p, bytes + split, size - split);
    CHECK(rte_pktmbuf_chain(head, tail) == 0);
    return head;
}
static void run(const unsigned char *bytes, size_t size, int expected,
    const struct ker_flow_key *wanted)
{
    for (size_t split = 0; split <= size; ++split) {
        struct rte_mbuf *m = packet(bytes, size, split);
        struct ker_flow_key key = {.domain = 999}, before = key;
        CHECK(ker_flow_parse(m, 51, KER_FLOW_INGRESS, &key) == expected);
        if (expected) CHECK(!memcmp(&key, &before, sizeof(key)));
        else {
            CHECK(key.domain == wanted->domain && key.family == wanted->family &&
                key.protocol == wanted->protocol && key.local_port == wanted->local_port &&
                key.remote_port == wanted->remote_port);
            CHECK(!memcmp(key.local, wanted->local, 16));
            CHECK(!memcmp(key.remote, wanted->remote, 16));
            uint32_t a, b;
            CHECK(ker_flow_hash(&key, 37, &a) == 0);
            CHECK(ker_flow_hash(wanted, 37, &b) == 0 && a == b);
        }
        unsigned char copy[128];
        CHECK(rte_pktmbuf_read(m, 0, (uint32_t)size, copy));
        const void *data = rte_pktmbuf_read(m, 0, (uint32_t)size, copy);
        CHECK(!memcmp(data, bytes, size));
        CHECK(m->nb_segs == 2 && m->data_len == split && m->pkt_len == size);
        CHECK(rte_mbuf_refcnt_read(m) == 1 && rte_mbuf_refcnt_read(m->next) == 1);
        rte_pktmbuf_free(m);
    }
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "flow_icmp", 127, 0, 512, SOCKET_ID_ANY) == 0);
    unsigned char bytes[128] = {0};
    bytes[12] = 8;
    unsigned char *ip = bytes + 14, *icmp = ip + 20, *quote = icmp + 8;
    ip[0] = 0x45; ip[3] = 56; ip[8] = 64; ip[9] = 1;
    ip[12] = 192; ip[14] = 2; ip[15] = 254;
    ip[16] = 10; ip[19] = 1;
    icmp[0] = 3; icmp[1] = 3;
    quote[0] = 0x45; quote[3] = 100; quote[6] = 0x40; quote[8] = 63; quote[9] = 17;
    quote[12] = 10; quote[15] = 1;
    quote[16] = 192; quote[18] = 2; quote[19] = 1;
    quote[20] = 0x9c; quote[21] = 0x40; quote[22] = 0; quote[23] = 53;
    quote[25] = 80; /* Original payload is truncated to UDP header in quote. */
    struct ker_flow_key wanted = {.domain = 51, .family = 4, .protocol = 17,
        .local_port = 40000, .remote_port = 53};
    memcpy(wanted.local + 12, quote + 12, 4);
    memcpy(wanted.remote + 12, quote + 16, 4);
    const unsigned char types[] = {3, 11, 12};
    for (size_t i = 0; i < sizeof(types); ++i) {
        icmp[0] = types[i]; icmp[1] = 0;
        run(bytes, 70, 0, &wanted);
        run(bytes, 79, 0, &wanted); /* Ethernet padding excluded. */
    }
    icmp[0] = 3; icmp[1] = 4;
    run(bytes, 70, 0, &wanted);
    struct rte_mbuf *m = packet(bytes, 70, 37);
    struct ker_flow_key key = {0};
    CHECK(ker_flow_parse(m, 51, KER_FLOW_EGRESS, &key) == -ENOTSUP);
    rte_pktmbuf_free(m);
    for (size_t n = 34; n < 70; ++n) run(bytes, n, -EMSGSIZE, NULL);
    ip[3] = 55; run(bytes, 79, -EMSGSIZE, NULL); ip[3] = 56;
    quote[0] = 0x46; run(bytes, 70, -ENOTSUP, NULL); quote[0] = 0x45;
    quote[6] = 0x20; run(bytes, 70, -ENOTSUP, NULL);
    quote[6] = 0; quote[7] = 1; run(bytes, 70, -ENOTSUP, NULL);
    quote[6] = 0x80; quote[7] = 0; run(bytes, 70, -ENOTSUP, NULL); quote[6] = 0x40;
    quote[9] = 6; run(bytes, 70, -ENOTSUP, NULL); quote[9] = 17;
    quote[25] = 79; run(bytes, 70, -EINVAL, NULL); quote[25] = 80;
    quote[3] = 27; run(bytes, 70, -EINVAL, NULL); quote[3] = 100;
    quote[15] = 2; run(bytes, 70, -EINVAL, NULL); quote[15] = 1;
    icmp[0] = 8; run(bytes, 70, -ENOTSUP, NULL);
    icmp[0] = 5; run(bytes, 70, -ENOTSUP, NULL);
    icmp[0] = 3; icmp[1] = 16; run(bytes, 70, -ENOTSUP, NULL);
    CHECK(ker_packet_pool_cleanup(&pool) == 0); CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("ICMPv4 quoted UDP flow keys: segmentation, direction and rejection passed");
    return 0;
}
