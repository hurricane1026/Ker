#include "runtime/ethdev-tx.h"
#include <errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <string.h>

static int ethdev_sink(struct rte_mbuf *packet, void *arg)
{
    struct ker_ethdev_tx *tx = arg;
    if (!tx || !tx->initialized || !packet) return -EINVAL;
    if (rte_lcore_id() != tx->owner_lcore) return -EXDEV;
    if (packet->ol_flags || packet->tx_offload) return -ENOTSUP;
    if (tx->max_segments && packet->nb_segs > tx->max_segments) return -ENOTSUP;
    uint16_t sent = rte_eth_tx_burst(tx->port_id, tx->queue_id, &packet, 1);
    return sent == 1 ? 0 : -EAGAIN;
}

static uint16_t reported_segment_limit(const struct rte_eth_dev_info *info)
{
    uint16_t mtu_limit = info->tx_desc_lim.nb_mtu_seg_max;
    uint16_t total_limit = info->tx_desc_lim.nb_seg_max;
    if (!mtu_limit) return total_limit;
    if (!total_limit) return mtu_limit;
    return mtu_limit < total_limit ? mtu_limit : total_limit;
}

int ker_ethdev_tx_init(struct ker_ethdev_tx *tx, struct ker_skb_context *ctx,
    uint16_t port_id, uint16_t queue_id, unsigned int packet_limit,
    size_t byte_limit, unsigned int segment_payload_limit)
{
    if (!tx || !ctx || !packet_limit || !byte_limit || !segment_payload_limit)
        return -EINVAL;
    if (tx->initialized || tx->polling || tx->port_id || tx->queue_id || tx->max_segments ||
        tx->owner_lcore || tx->exporter.queue.native.next || tx->exporter.queue.native.prev ||
        tx->exporter.queue.context || tx->exporter.queue.bytes || tx->exporter.queue.byte_limit ||
        tx->exporter.queue.packet_limit || tx->exporter.queue.purging ||
        tx->exporter.pending || tx->exporter.pending_charge ||
        tx->exporter.bytes || tx->exporter.byte_limit || tx->exporter.packets ||
        tx->exporter.packet_limit || tx->exporter.segment_payload_limit ||
        tx->exporter.last_completed || tx->exporter.resolver_refs ||
        tx->exporter.responder_refs || tx->exporter.ethdev_refs || tx->exporter.last_error ||
        tx->exporter.polling || tx->exporter.mode != KER_TX_EXPORT_SINGLE ||
        tx->exporter.sink || tx->exporter.sink_arg || tx->exporter.observers)
        return -EALREADY;
    if (ctx->lcore != rte_lcore_id()) return -EXDEV;
    if (!rte_eth_dev_is_valid_port(port_id)) return -ENODEV;
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    int rc = rte_eth_dev_info_get(port_id, &info);
    if (rc) return rc < 0 ? rc : -rc;
    if (queue_id >= info.nb_tx_queues || queue_id >= info.max_tx_queues) return -EINVAL;
    if (!(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) return -ENOTSUP;
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    rc = rte_eth_dev_conf_get(port_id, &conf);
    if (rc) return rc < 0 ? rc : -rc;
    if (!(conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) return -ENOTSUP;

    tx->port_id = port_id;
    tx->queue_id = queue_id;
    tx->max_segments = reported_segment_limit(&info);
    tx->owner_lcore = ctx->lcore;
    tx->initialized = true;
    rc = ker_tx_export_init_chain(&tx->exporter, ctx, packet_limit, byte_limit,
        segment_payload_limit, ethdev_sink, tx);
    if (rc) {
        memset(tx, 0, sizeof(*tx));
        return rc;
    }
    tx->exporter.ethdev_refs++;
    return 0;
}

int ker_ethdev_tx_poll(void *arg, unsigned int budget)
{
    struct ker_ethdev_tx *tx = arg;
    if (!tx || !tx->initialized) return -EINVAL;
    if (rte_lcore_id() != tx->owner_lcore) return -EXDEV;
    if (tx->polling) return -EBUSY;
    tx->polling = true;
    int rc = ker_tx_export_poll(&tx->exporter, budget);
    tx->polling = false;
    return rc;
}

int ker_ethdev_tx_cleanup(struct ker_ethdev_tx *tx)
{
    if (!tx || !tx->initialized) return -EINVAL;
    if (rte_lcore_id() != tx->owner_lcore) return -EXDEV;
    if (tx->polling) return -EBUSY;
    tx->exporter.ethdev_refs--;
    int rc = ker_tx_export_cleanup(&tx->exporter);
    if (rc) {
        tx->exporter.ethdev_refs++;
        return rc;
    }
    memset(tx, 0, sizeof(*tx));
    return 0;
}
