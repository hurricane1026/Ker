#include "runtime/arp-responder.h"
#include "runtime/arp.h"
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>

int ker_arp_rx_responder_scope(struct ker_arp_receiver *, const struct ker_arp_message *);

static int respond(const struct ker_arp_message *message, void *arg)
{
    struct ker_arp_responder *responder = arg;
    ++responder->requests;
    int error = ker_arp_rx_responder_scope(&responder->receiver, message);
    if (error) goto dropped;
    if (message->operation != ARPOP_REQUEST || !message->sender_ip ||
        !message->target_local || !responder->address) {
        error = -ENOTSUP;
        goto dropped;
    }
    error = ker_ipv4_address_is_local(responder->address, message->target_ip);
    if (error != 1) {
        if (!error) error = -ENOTSUP;
        goto dropped;
    }

    struct sk_buff *reply = NULL;
    error = ker_arp_create_configured(responder->address, ARPOP_REPLY,
        message->sender_ip, message->sender_mac, message->sender_mac, &reply);
    if (error) goto dropped;
    error = ker_tx_export_enqueue(responder->tx, &reply);
    if (error) {
        BUG_ON(!reply || ker_skb_free(reply));
        goto dropped;
    }
    BUG_ON(reply);
    ++responder->replies_enqueued;
    responder->last_error = 0;
    return NET_RX_SUCCESS;

dropped:
    ++responder->dropped;
    responder->last_error = error;
    return NET_RX_DROP;
}

int ker_arp_responder_register(struct ker_arp_responder *responder,
    struct ker_receive_runtime *runtime, struct ker_ipv4_address *address,
    struct ker_tx_export *tx)
{
    if (!responder || !runtime || !address || !tx)
        return -EINVAL;
    if (responder->active || responder->receiver.handler.registered ||
        responder->address || responder->tx) return -EALREADY;
    if (!address->native || !address->device || !address->device->native ||
        !runtime->initialized || !runtime->context || !address->device->context)
        return -EINVAL;
    if (rte_lcore_id() != runtime->lcore || runtime->context != address->device->context ||
        address->device->lcore != runtime->lcore) return -EXDEV;
    if (!tx->queue.context || !tx->sink) return -EINVAL;
    if (tx->queue.context != address->device->context ||
        tx->queue.context->lcore != runtime->lcore) return -EXDEV;
    if (tx->polling) return -EBUSY;
    if (tx->responder_refs == UINT_MAX) return -EOVERFLOW;
    int local = ker_ipv4_address_is_local(address,
        address->native->ifa_list ? address->native->ifa_list->ifa_local : 0);
    if (local < 0) return local;
    if (!local) return -EINVAL;

    int error = ker_arp_receiver_register(&responder->receiver, runtime, address,
        respond, responder);
    if (error) return error;
    ++tx->responder_refs;
    responder->address = address;
    responder->tx = tx;
    responder->active = true;
    return 0;
}

int ker_arp_responder_unregister(struct ker_arp_responder *responder)
{
    if (!responder || !responder->active || !responder->tx || !responder->address)
        return -EINVAL;
    if (rte_lcore_id() != responder->receiver.handler.runtime->lcore) return -EXDEV;
    int error = ker_arp_receiver_unregister(&responder->receiver);
    if (error) return error;
    BUG_ON(!responder->tx->responder_refs);
    --responder->tx->responder_refs;
    responder->address = NULL;
    responder->tx = NULL;
    responder->active = false;
    return 0;
}
