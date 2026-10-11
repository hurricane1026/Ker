#include "check.h"
#include "eal.h"
#include "runtime/skb-queue.h"
#include "runtime/ipv4-packet-view.h"
#include "runtime/memory.h"
#include "runtime/worker.h"
#include <pthread.h>
#include <errno.h>
#include <limits.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context, other_context;
static struct ker_skb_queue queue, other;
static struct sk_buff *make(unsigned char value)
{
    struct sk_buff *skb = NULL; unsigned char *bytes;
    CHECK(ker_skb_alloc(&context, 64, 16, &skb) == 0);
    CHECK(ker_skb_put(skb, 4, &bytes) == 0); memset(bytes, value, 4);
    memset(skb->cb, 0xa5, sizeof(skb->cb));
    return skb;
}
static void blocked(struct sk_buff *alias)
{
    struct sk_buff *out = (void *)(uintptr_t)1;
    struct rte_mbuf *mbuf = (void *)(uintptr_t)1;
    unsigned char *data = (void *)(uintptr_t)1;
    CHECK(ker_skb_validate(alias, &context) == -EBUSY);
    CHECK(ker_skb_get(alias) == -EBUSY && ker_skb_free(alias) == -EBUSY);
    CHECK(ker_skb_clone(alias, &out) == -EBUSY && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_make_writable(alias, 16, 0) == -EBUSY);
    CHECK(ker_skb_to_mbuf(alias, &mbuf) == -EBUSY && mbuf == (void *)(uintptr_t)1);
    CHECK(ker_skb_put(alias, 1, &data) == -EBUSY && data == (void *)(uintptr_t)1);
    CHECK(ker_skb_push(alias, 1, &data) == -EBUSY && data == (void *)(uintptr_t)1);
    CHECK(ker_skb_pull(alias, 1) == -EBUSY && ker_skb_trim(alias, 1) == -EBUSY);
    struct sk_buff *duplicate = alias;
    CHECK(ker_skb_queue_push(&other, &duplicate) == -EBUSY && duplicate == alias);
    struct ker_ipv4_packet_view view = {(const unsigned char *)(uintptr_t)1, 11, 12, 13, 14};
    CHECK(ker_ipv4_packet_view_init(&context, alias, &view) == -EBUSY);
    CHECK(view.header == (const unsigned char *)(uintptr_t)1 && view.header_length == 11 &&
        view.packet_length == 12 && view.payload_length == 13 && view.frag_off == 14);
}
static void *wrong_worker(void *arg)
{
    struct sk_buff *packet = arg;
    struct ker_skb_queue fresh = {0};
    CHECK(ker_skb_queue_init(&fresh, &context, 1, SIZE_MAX) == -EXDEV);
    CHECK(ker_skb_queue_push(&queue, &packet) == -EXDEV && packet == arg);
    CHECK(ker_skb_queue_pop(&queue, &packet) == -EXDEV && packet == arg);
    CHECK(ker_skb_queue_purge(&queue, 1) == -EXDEV && ker_skb_queue_cleanup(&queue) == -EXDEV);
    return NULL;
}
static unsigned int destructed;
static void nested_destructor(struct sk_buff *skb)
{
    (void)skb;
    /* Outer purge has unlinked its last skb, so qlen is zero. Still reject
     * cleanup/reentry while its destructor is executing inside a nested purge. */
    CHECK(ker_skb_queue_cleanup(&queue) == -EBUSY);
    CHECK(ker_skb_queue_purge(&queue, 1) == -EBUSY);
    destructed++;
}
static void outer_destructor(struct sk_buff *skb)
{
    (void)skb;
    struct sk_buff *out = (void *)(uintptr_t)1;
    CHECK(ker_skb_queue_pop(&queue, &out) == -EBUSY && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_queue_purge(&other, 1) == 1);
    CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
    destructed++;
}
struct tx_state { struct sk_buff *pending; unsigned int sent; };
static int tx(void *arg, unsigned int budget)
{
    struct tx_state *state = arg;
    if (!budget) return 0;
    if (!state->pending) {
        int rc = ker_skb_queue_pop(&queue, &state->pending);
        if (rc <= 0) return rc;
    }
    struct rte_mbuf *output = NULL;
    int rc = ker_skb_to_mbuf(state->pending, &output);
    if (rc) return rc; /* Retain ownership across TX allocation backpressure. */
    CHECK(rte_pktmbuf_mtod(output, unsigned char *)[0] == 0x42);
    ker_packet_free(output); CHECK(ker_skb_free(state->pending) == 0);
    state->pending = NULL; state->sent++;
    return 1;
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "queue_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "queue_skb") == 0);
    CHECK(ker_skb_context_init(&other_context, &pool, "other_queue_skb") == 0);
    CHECK(ker_skb_queue_init(&queue, &context, 0, SIZE_MAX) == -EINVAL);
    CHECK(ker_skb_queue_init(&queue, &context, 1, 0) == -EINVAL);
    context.queue_live = UINT_MAX;
    CHECK(ker_skb_queue_init(&queue, &context, 1, SIZE_MAX) == -EOVERFLOW); context.queue_live = 0;
    ker_memory_fail_after(0);
    CHECK(ker_skb_queue_init(&queue, &context, 2, SIZE_MAX) == 0); /* No allocation */
    CHECK(ker_skb_queue_init(&other, &context, 7, SIZE_MAX) == 0);
    ker_memory_fail_after(-1);
    CHECK(ker_skb_queue_init(&queue, &context, 2, SIZE_MAX) == -EALREADY);
    CHECK(context.queue_live == 2 && ker_skb_context_cleanup(&context) == -EBUSY);
    struct sk_buff *out = (void *)(uintptr_t)1;
    CHECK(ker_skb_queue_pop(&queue, &out) == 0 && out == (void *)(uintptr_t)1);
    struct sk_buff *a = make(1), *b = make(2), *c = make(3), *alias = a;
    size_t charge = a->truesize; CHECK(charge > a->len);
    struct ker_memory_budget_stats before, after;
    CHECK(!ker_memory_budget_stats(KER_MEMORY_CACHE, &before));
    CHECK(ker_skb_get(a) == 0 && ker_skb_queue_push(&queue, &a) == -EBUSY && a == alias);
    CHECK(ker_skb_free(a) == 0);
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, wrong_worker, a) && !pthread_join(thread, NULL));
    ker_memory_fail_after(0);
    CHECK(ker_skb_queue_push(&queue, &a) == 0 && !a && queue.bytes == charge);
    CHECK(ker_skb_queue_push(&queue, &b) == 0 && !b && queue.native.qlen == 2);
    ker_memory_fail_after(-1);
    blocked(alias);
    CHECK(ker_skb_queue_push(&queue, &c) == -ENOSPC && c && queue.bytes == charge * 2);
    CHECK(ker_skb_queue_cleanup(&queue) == -EBUSY);
    CHECK(!ker_memory_budget_stats(KER_MEMORY_CACHE, &after) && before.used == after.used);
    CHECK(ker_skb_queue_pop(&queue, &out) == 1 && out == alias && !out->next && !out->prev && out->data[0] == 1);
    for (unsigned int i = 0; i < sizeof(out->cb); ++i) CHECK((unsigned char)out->cb[i] == 0xa5);
    CHECK(ker_skb_validate(out, &context) == 0 && ker_skb_free(out) == 0);
    CHECK(ker_skb_queue_push(&queue, &c) == 0 && !c);
    CHECK(ker_skb_queue_pop(&queue, &out) == 1 && out->data[0] == 2 && ker_skb_free(out) == 0);
    CHECK(ker_skb_queue_pop(&queue, &out) == 1 && out->data[0] == 3 && ker_skb_free(out) == 0);
    CHECK(!queue.bytes && !queue.native.qlen && ker_skb_queue_cleanup(&queue) == 0);
    /* Byte admission is by retained truesize, even for a tiny/empty payload. */
    CHECK(ker_skb_queue_init(&queue, &context, 7, charge * 2 - 1) == 0);
    a = make(4); b = make(5); CHECK(ker_skb_trim(b, 0) == 0);
    CHECK(ker_skb_queue_push(&queue, &a) == 0);
    CHECK(ker_skb_queue_push(&queue, &b) == -ENOSPC && !b->len && queue.native.qlen == 1);
    CHECK(ker_skb_free(b) == 0);
    CHECK(ker_skb_queue_purge(&queue, 0) == 0 && queue.native.qlen == 1);
    CHECK(ker_skb_queue_purge(&queue, 1) == 1 && !queue.bytes && ker_skb_queue_cleanup(&queue) == 0);
    CHECK(ker_skb_queue_init(&queue, &context, 7, SIZE_MAX) == 0);
    struct sk_buff *foreign = NULL; CHECK(ker_skb_alloc(&other_context, 0, 0, &foreign) == 0);
    CHECK(ker_skb_queue_push(&queue, &foreign) == -EXDEV && foreign && ker_skb_free(foreign) == 0);
    a = make(6); CHECK(ker_skb_clone(a, &b) == 0); /* Data shared, descriptors unique */
    CHECK(ker_skb_queue_push(&queue, &a) == 0 && ker_skb_queue_push(&queue, &b) == 0 && queue.bytes == charge * 2);
    CHECK(ker_skb_queue_purge(&queue, 1) == 1 && context.live == 1 && queue.bytes == charge);
    CHECK(ker_skb_queue_purge(&queue, 7) == 1 && !context.live && !queue.bytes);
    /* Freeze accounting at ownership transfer, independent of native fields.
     * Raw mutation is prohibited by contract; this fault probes the debit. */
    a = make(7); alias = a; CHECK(ker_skb_queue_push(&queue, &a) == 0);
    alias->truesize = 1; CHECK(ker_skb_queue_pop(&queue, &out) == 1 && !queue.bytes);
    out->truesize = (unsigned int)charge; CHECK(ker_skb_free(out) == 0);
    a = make(8); b = make(9); a->destructor = outer_destructor; b->destructor = nested_destructor;
    CHECK(ker_skb_queue_push(&queue, &a) == 0 && ker_skb_queue_push(&other, &b) == 0);
    CHECK(ker_skb_queue_purge(&queue, 1) == 1 && destructed == 2 && !context.live);
    /* Fill the real seven-object descriptor pool before admission. Queue
     * operations neither allocate nor fall back, and retain a strict budget. */
    struct sk_buff *all[7];
    for (unsigned int i = 0; i < 7; ++i) all[i] = make((unsigned char)i);
    for (unsigned int i = 0; i < 7; ++i) CHECK(ker_skb_queue_push(&queue, &all[i]) == 0 && !all[i]);
    CHECK(queue.native.qlen == 7 && ker_skb_queue_purge(&queue, 3) == 3 && queue.native.qlen == 4);
    CHECK(ker_skb_queue_purge(&queue, 7) == 4 && !queue.bytes);
    /* Existing worker TX retries a dequeued packet under actual mbuf-pool OOM. */
    a = make(0x42); CHECK(ker_skb_queue_push(&queue, &a) == 0);
    struct rte_mbuf *occupied[30];
    for (unsigned int i = 0; i < 30; ++i) CHECK((occupied[i] = ker_packet_alloc(&pool)) != NULL);
    struct tx_state state = {0}; struct ker_worker worker = {0};
    struct ker_worker_config cfg = {.timer_budget = 1, .tx_budget = 1};
    struct ker_worker_ops ops = {.tx = tx, .arg = &state}; struct ker_worker_result result;
    CHECK(ker_worker_init(&worker, &pool, &cfg, &ops) == 0);
    CHECK(ker_worker_poll(&worker, 1, &result) == -ENOMEM && state.pending && !queue.native.qlen);
    CHECK(ker_skb_validate(state.pending, &context) == 0 && state.pending->data[0] == 0x42);
    for (unsigned int i = 0; i < 30; ++i) ker_packet_free(occupied[i]);
    CHECK(ker_worker_poll(&worker, 2, &result) == 0 && result.tx == 1 && state.sent == 1 && !state.pending);
    CHECK(ker_worker_cleanup(&worker) == 0);
    CHECK(ker_skb_queue_cleanup(&queue) == 0 && context.queue_live == 1);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    out = (void *)(uintptr_t)1;
    CHECK(ker_skb_queue_pop(&other, &out) == -ESHUTDOWN && out == (void *)(uintptr_t)1);
    CHECK(ker_skb_context_cleanup(&context) == -EBUSY);
    CHECK(ker_skb_queue_cleanup(&other) == 0 && !context.queue_live);
    CHECK(ker_skb_context_cleanup(&other_context) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("skb queue: native FIFO, count/truesize bounds, transfer guards, purge and worker TX retry passed");
    return 0;
}
