#include "check.h"
#include "eal.h"
#include "runtime/tx-export.h"
#include "runtime/memory.h"
#include <errno.h>
#include <string.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_tx_export tx;
static int mode, calls, fail_call;
static struct ker_worker worker;
static unsigned char expected[8];
static struct sk_buff *reentrant_packet;
static struct rte_mbuf *kept_copy;
static int sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(arg == &tx && worker.polling && !worker.timers.polling); calls++;
    CHECK(ker_tx_export_cleanup(&tx) == -EBUSY);
    struct sk_buff *untouched = (void *)(uintptr_t)1;
    CHECK(ker_tx_export_cancel(&tx, &untouched) == -EBUSY && untouched == (void *)(uintptr_t)1);
    CHECK(ker_tx_export_poll(&tx, 1) == -EBUSY);
    if (reentrant_packet)
        CHECK(ker_tx_export_enqueue(&tx, &reentrant_packet) == -EBUSY && reentrant_packet);
    CHECK(packet->ol_flags == 0 && packet->pkt_len == sizeof(expected));
    CHECK(!memcmp(rte_pktmbuf_mtod(packet, unsigned char *), expected, sizeof(expected)));
    if (fail_call == calls) return -EAGAIN;
    if (mode == 1) return -EAGAIN;
    if (mode == 2) return 1;
    if (mode == 4) { kept_copy = packet; return 0; }
    ker_packet_free(packet); return 0;
}
static struct sk_buff *make(unsigned char id)
{
    struct sk_buff *skb = NULL; uint8_t *p = NULL;
    CHECK(ker_skb_alloc(&context, 8, 64, &skb) == 0);
    CHECK(ker_skb_put(skb, sizeof(expected), &p) == 0);
    for (unsigned int i = 0; i < sizeof(expected); i++) p[i] = (unsigned char)(id + i);
    memcpy(expected, p, sizeof(expected));
    return skb;
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "tx_export", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "tx_export_skb") == 0);
    CHECK(ker_tx_export_init(&tx, &context, 2, SIZE_MAX, sink, &tx) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .tx_budget = 1};
    struct ker_worker_ops ops = {.tx = ker_tx_export_poll, .arg = &tx};
    struct ker_worker_result progress = {0};
    CHECK(ker_worker_init(&worker, &pool, &config, &ops) == 0);
    CHECK(ker_tx_export_poll(&tx, 0) == 0 && calls == 0);
    tx.last_completed = 77; tx.last_error = 88;
    CHECK(ker_tx_export_poll(&tx, UINT_MAX) == -EOVERFLOW && tx.last_completed == 77 && tx.last_error == 88);
    tx.last_completed = 0; tx.last_error = 0;
    struct sk_buff *a = make(0x10), *b = make(0x30), *out = (void *)(uintptr_t)1;
    size_t charge = a->truesize;
    struct sk_buff *bad = make(0x70);
    skb_shinfo(bad)->gso_size = 1;
    CHECK(ker_tx_export_enqueue(&tx, &bad) == -ENOTSUP && bad);
    skb_shinfo(bad)->gso_size = 0; skb_shinfo(bad)->tx_flags = 1;
    CHECK(ker_tx_export_enqueue(&tx, &bad) == -ENOTSUP && bad);
    skb_shinfo(bad)->tx_flags = 0; CHECK(ker_skb_free(bad) == 0);
    reentrant_packet = make(0x80);
    CHECK(ker_tx_export_enqueue(&tx, &a) == 0 && !a);
    memcpy(expected, (unsigned char[]){0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17}, sizeof(expected));
    CHECK(ker_tx_export_enqueue(&tx, &b) == 0 && !b && tx.packets == 2 && tx.bytes == charge * 2);
    mode = 1;
    CHECK(ker_worker_poll(&worker, 1, &progress) == -EAGAIN && progress.tx == 0 && tx.last_error == -EAGAIN && tx.last_completed == 0);
    CHECK(tx.pending && tx.pending->data[0] == 0x10 && tx.queue.native.qlen == 1);
    CHECK(ker_tx_export_cleanup(&tx) == -EBUSY);
    mode = 0;
    CHECK(ker_worker_poll(&worker, 2, &progress) == 0 && progress.tx == 1 && tx.last_completed == 1 && tx.packets == 1);
    CHECK(context.live == 2); /* Reentry probe remains caller-owned. */
    CHECK(ker_skb_free(reentrant_packet) == 0); reentrant_packet = NULL;
    struct sk_buff *c = make(0x50);
    memcpy(expected, (unsigned char[]){0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}, sizeof(expected));
    CHECK(ker_tx_export_enqueue(&tx, &c) == 0 && !c && tx.packets == 2);
    struct sk_buff *overflow = make(0x70);
    CHECK(ker_tx_export_enqueue(&tx, &overflow) == -ENOSPC && overflow && tx.packets == 2);
    CHECK(ker_skb_free(overflow) == 0);
    memcpy(expected, (unsigned char[]){0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}, sizeof(expected));
    struct rte_mbuf *held[31]; unsigned int held_count = 0;
    while (held_count < 31 && (held[held_count] = ker_packet_alloc(&pool)) != NULL) held_count++;
    CHECK(held_count > 0);
    CHECK(ker_worker_poll(&worker, 3, &progress) == -ENOMEM && tx.pending && tx.last_error == -ENOMEM);
    while (held_count) ker_packet_free(held[--held_count]);
    mode = 2;
    CHECK(ker_worker_poll(&worker, 4, &progress) == -EPROTO && tx.pending && tx.last_error == -EPROTO);
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out && out->data[0] == 0x30 && tx.packets == 1);
    CHECK(ker_skb_free(out) == 0);
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out && out->data[0] == 0x50 && !tx.packets && !tx.bytes);
    CHECK(ker_skb_free(out) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);

    CHECK(ker_tx_export_init(&tx, &context, 3, charge * 2 - 1, sink, &tx) == 0);
    struct sk_buff *d = make(0x90), *e = make(0xa0);
    memcpy(expected, (unsigned char[]){0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97}, sizeof(expected));
    CHECK(ker_tx_export_enqueue(&tx, &d) == 0 && !d);
    mode = 1;
    CHECK(ker_worker_poll(&worker, 5, &progress) == -EAGAIN && tx.pending && tx.bytes == charge);
    CHECK(ker_tx_export_enqueue(&tx, &e) == -ENOSPC && e && tx.packets == 1 && tx.bytes == charge);
    CHECK(ker_skb_free(e) == 0);
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out->data[0] == 0x90 && !tx.bytes);
    CHECK(ker_skb_free(out) == 0 && ker_tx_export_cleanup(&tx) == 0);

    CHECK(ker_tx_export_init(&tx, &context, 2, SIZE_MAX, sink, &tx) == 0);
    struct sk_buff *partial = NULL; uint8_t *partial_data = NULL;
    CHECK(ker_skb_alloc(&context, 8, 64, &partial) == 0);
    CHECK(ker_skb_put(partial, 8, &partial_data) == 0);
    const unsigned char partial_seed[8] = {0, 1, 2, 3, 0, 0, 6, 7};
    memcpy(partial_data, partial_seed, sizeof(partial_seed));
    partial->ip_summed = CHECKSUM_PARTIAL;
    partial->csum_start = (uint16_t)skb_headroom(partial);
    partial->csum_offset = 4;
    partial->csum_offset = UINT16_MAX;
    CHECK(ker_tx_export_enqueue(&tx, &partial) == -EINVAL && partial);
    partial->csum_offset = 4;
    memcpy(expected, partial_seed, sizeof(expected)); expected[4] = 0xf7; expected[5] = 0xf4;
    CHECK(ker_tx_export_enqueue(&tx, &partial) == 0 && !partial);
    mode = 4;
    CHECK(ker_worker_poll(&worker, 6, &progress) == 0 && progress.tx == 1 && !tx.packets);
    CHECK(context.live == 0 && kept_copy && kept_copy->pkt_len == sizeof(expected));
    CHECK(!memcmp(rte_pktmbuf_mtod(kept_copy, const unsigned char *), expected, sizeof(expected)));
    ker_packet_free(kept_copy); kept_copy = NULL;
    CHECK(ker_tx_export_cleanup(&tx) == 0);

    CHECK(ker_tx_export_init(&tx, &context, 2, SIZE_MAX, sink, &tx) == 0);
    worker.config.tx_budget = 2;
    mode = 0;
    struct sk_buff *prefix_a = make(0xc0), *prefix_b = make(0xc0);
    memcpy(expected, (unsigned char[]){0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7}, sizeof(expected));
    CHECK(ker_tx_export_enqueue(&tx, &prefix_a) == 0 && !prefix_a);
    CHECK(ker_tx_export_enqueue(&tx, &prefix_b) == 0 && !prefix_b);
    fail_call = calls + 2;
    CHECK(ker_worker_poll(&worker, 7, &progress) == 0 && progress.tx == 1);
    CHECK(tx.last_completed == 1 && tx.last_error == -EAGAIN && tx.pending && tx.packets == 1);
    fail_call = 0;
    CHECK(ker_tx_export_cancel(&tx, &out) == 1 && out->data[0] == 0xc0);
    CHECK(ker_skb_free(out) == 0);
    out = (void *)(uintptr_t)1;
    CHECK(ker_tx_export_cancel(&tx, &out) == 0 && out == (void *)(uintptr_t)1);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(calls == 7);
    return 0;
}
