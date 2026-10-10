#include "runtime/skb-queue.h"
#include "runtime/skb-queue-internal.h"
#include "runtime/memory.h"
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>
static int valid(struct ker_skb_queue *queue)
{
    if (!queue || !queue->context) return -EINVAL;
    if (rte_lcore_id() != queue->context->lcore) return -EXDEV;
    if (queue->purging) return -EBUSY;
    struct ker_memory_budget_stats stats;
    if (!queue->context->descriptors || !queue->context->packets->mbufs ||
        ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    return 0;
}
int ker_skb_queue_init(struct ker_skb_queue *queue, struct ker_skb_context *context,
    unsigned int packet_limit, size_t byte_limit)
{
    if (!queue || !context || !context->descriptors || !context->packets ||
        !context->packets->mbufs || !packet_limit || !byte_limit) return -EINVAL;
    if (queue->context) return -EALREADY;
    if (rte_lcore_id() != context->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    if (context->queue_live == UINT_MAX) return -EOVERFLOW;
    *queue = (struct ker_skb_queue){.context = context, .byte_limit = byte_limit, .packet_limit = packet_limit};
    skb_queue_head_init(&queue->native);
    context->queue_live++;
    return 0;
}
int ker_skb_queue_push(struct ker_skb_queue *queue, struct sk_buff **packet)
{
    int error = valid(queue);
    if (error) return error;
    if (!packet || !*packet) return -EINVAL;
    struct sk_buff *skb = *packet;
    error = ker_skb_validate(skb, queue->context);
    if (error) return error;
    if (skb_shared(skb) || skb->next || skb->prev) return -EBUSY;
    if (!skb->truesize) return -EINVAL;
    if (queue->native.qlen >= queue->packet_limit || skb->truesize > queue->byte_limit - queue->bytes)
        return -ENOSPC;
    ker_skb_queue_claim(skb, queue);
    __skb_queue_tail(&queue->native, skb);
    queue->bytes += skb->truesize;
    *packet = NULL;
    return 0;
}
static struct sk_buff *pop(struct ker_skb_queue *queue)
{
    struct sk_buff *skb = __skb_dequeue(&queue->native);
    if (skb) {
        unsigned int charge = ker_skb_queue_release(skb, queue);
        BUG_ON(charge > queue->bytes);
        queue->bytes -= charge;
    }
    return skb;
}
int ker_skb_queue_pop(struct ker_skb_queue *queue, struct sk_buff **packet)
{
    int error = valid(queue);
    if (error) return error;
    if (!packet) return -EINVAL;
    struct sk_buff *skb = pop(queue);
    if (!skb) return 0;
    *packet = skb;
    return 1;
}
int ker_skb_queue_purge(struct ker_skb_queue *queue, unsigned int budget)
{
    int error = valid(queue);
    if (error) return error;
    if (budget > INT_MAX) return -EINVAL;
    queue->purging = true;
    unsigned int done = 0;
    while (done < budget) {
        struct sk_buff *skb = pop(queue);
        if (!skb) break;
        BUG_ON(ker_skb_free(skb));
        done++;
    }
    queue->purging = false;
    return (int)done;
}
int ker_skb_queue_cleanup(struct ker_skb_queue *queue)
{
    int error = valid(queue);
    if (error) return error;
    if (queue->native.qlen || queue->bytes) return -EBUSY;
    BUG_ON(!queue->context->queue_live);
    queue->context->queue_live--;
    *queue = (struct ker_skb_queue){0};
    return 0;
}
