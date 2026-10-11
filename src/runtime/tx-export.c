#include "runtime/tx-export.h"
#include <errno.h>
#include <limits.h>
#include <rte_lcore.h>
#include <string.h>

static int valid(struct ker_tx_export *tx)
{
    if (!tx || !tx->sink || !tx->queue.context) return -EINVAL;
    if (rte_lcore_id() != tx->queue.context->lcore) return -EXDEV;
    return tx->polling ? -EBUSY : 0;
}

int ker_tx_export_init(struct ker_tx_export *tx, struct ker_skb_context *ctx,
    unsigned int packets, size_t bytes, ker_tx_export_sink_fn sink, void *arg)
{
    if (!tx || !ctx || !sink || !packets || !bytes) return -EINVAL;
    if (tx->queue.context || tx->pending || tx->sink) return -EALREADY;
    int rc = ker_skb_queue_init(&tx->queue, ctx, packets, bytes);
    if (rc) return rc;
    tx->packet_limit = packets; tx->byte_limit = bytes;
    tx->sink = sink; tx->sink_arg = arg;
    return 0;
}

static int exportable(struct sk_buff *skb, struct ker_skb_context *ctx)
{
    int rc = ker_skb_validate(skb, ctx);
    if (rc) return rc;
    struct skb_shared_info *info = skb_shinfo(skb);
    if (skb->data_len || info->nr_frags || info->frag_list || info->flags ||
        info->gso_size || info->gso_type || info->tx_flags || info->destructor_arg || skb->_skb_refdst ||
        skb->head_frag || skb->pp_recycle || skb->fclone || skb_shared(skb) ||
        skb_cloned(skb) || skb->nohdr)
        return -ENOTSUP;
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
        if (skb->csum_not_inet) return -ENOTSUP;
#endif
        int start = (int)skb->csum_start - (int)skb_headroom(skb);
        if (start < 0 || (unsigned int)start >= skb->len) return -EINVAL;
        uint64_t field = (uint64_t)(unsigned int)start + skb->csum_offset;
        if (field > skb->len || skb->len - (unsigned int)field < sizeof(__sum16)) return -EINVAL;
    } else if (skb->ip_summed != CHECKSUM_NONE) return -ENOTSUP;
    uint64_t geometry = (uint64_t)skb_headroom(skb) + skb->len;
    if (geometry > UINT_MAX) return -EOVERFLOW;
    if (geometry > rte_pktmbuf_data_room_size(ctx->packets->mbufs)) return -ENOSPC;
    return 0;
}

int ker_tx_export_enqueue(struct ker_tx_export *tx, struct sk_buff **packet)
{
    int rc = valid(tx);
    if (rc) return rc;
    if (!packet || !*packet) return -EINVAL;
    struct sk_buff *skb = *packet;
    rc = exportable(skb, tx->queue.context);
    if (rc) return rc;
    if (!skb->truesize || tx->bytes > tx->byte_limit || tx->packets >= tx->packet_limit ||
        skb->truesize > tx->byte_limit - tx->bytes) return -ENOSPC;
    rc = ker_skb_queue_push(&tx->queue, packet);
    if (rc) return rc;
    tx->packets++; tx->bytes += skb->truesize;
    return 0;
}

static int make_copy(struct sk_buff *skb, struct rte_mbuf **out)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        return ker_skb_to_mbuf_software_checksum(skb, out);
    return ker_skb_to_mbuf(skb, out);
}

int ker_tx_export_poll(void *arg, unsigned int budget)
{
    struct ker_tx_export *tx = arg;
    int rc = valid(tx);
    if (rc) return rc;
    if (!budget) return 0;
    if (budget > INT_MAX) return -EOVERFLOW;
    tx->last_completed = 0; tx->last_error = 0;
    tx->polling = true;
    unsigned int completed = 0;
    while (completed < budget) {
        if (!tx->pending) {
            struct sk_buff *skb = NULL;
            rc = ker_skb_queue_pop(&tx->queue, &skb);
            if (rc <= 0) { if (rc < 0) tx->last_error = rc; break; }
            tx->pending = skb; tx->pending_charge = skb->truesize;
        }
        struct rte_mbuf *copy = NULL;
        rc = make_copy(tx->pending, &copy);
        if (rc) { tx->last_error = rc; break; }
        rc = tx->sink(copy, tx->sink_arg);
        if (rc != 0) {
            ker_packet_free(copy);
            tx->last_error = rc > 0 ? -EPROTO : rc;
            break;
        }
        struct sk_buff *accepted = tx->pending;
        tx->pending = NULL;
        tx->bytes -= tx->pending_charge; tx->pending_charge = 0; tx->packets--;
        completed++;
        BUG_ON(ker_skb_free(accepted));
    }
    tx->polling = false;
    tx->last_completed = completed;
    if (completed) return (int)completed;
    return tx->last_error;
}

int ker_tx_export_cancel(struct ker_tx_export *tx, struct sk_buff **out)
{
    int rc = valid(tx);
    if (rc) return rc;
    if (!out) return -EINVAL;
    if (tx->pending) {
        *out = tx->pending; tx->pending = NULL;
        tx->bytes -= tx->pending_charge; tx->pending_charge = 0; tx->packets--;
        return 1;
    }
    size_t queued_bytes = tx->queue.bytes;
    rc = ker_skb_queue_pop(&tx->queue, out);
    if (rc == 1) {
        size_t charge = queued_bytes - tx->queue.bytes;
        tx->bytes -= charge; tx->packets--;
    }
    return rc;
}

int ker_tx_export_cleanup(struct ker_tx_export *tx)
{
    int rc = valid(tx);
    if (rc) return rc;
    if (tx->pending || tx->packets || tx->bytes) return -EBUSY;
    rc = ker_skb_queue_cleanup(&tx->queue);
    if (rc) return rc;
    memset(tx, 0, sizeof(*tx));
    return 0;
}
