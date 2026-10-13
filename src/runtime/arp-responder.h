#ifndef KER_RUNTIME_ARP_RESPONDER_H
#define KER_RUNTIME_ARP_RESPONDER_H
#include "runtime/arp-receive.h"
#include "runtime/tx-export.h"

/* Opt-in, same-worker ARP responder for one live configured IPv4 address.
 * Owns a receiver registration and pins tx against cleanup while active.
 * Replies are queued in the caller-configured bounded exporter; caller polls
 * that exporter through its normal worker TX callback. */
struct ker_arp_responder {
    struct ker_arp_receiver receiver;
    struct ker_ipv4_address *address;
    struct ker_tx_export *tx;
    unsigned int requests;
    unsigned int replies_enqueued;
    unsigned int dropped;
    int last_error;
    bool active;
};

/* Initialize responder to zero. The exporter must already be initialized,
 * bounded, not currently polling, and attached to the same context as the
 * address and runtime.
 * Sink ownership and retry behavior follow tx-export. */
int ker_arp_responder_register(struct ker_arp_responder *,
    struct ker_receive_runtime *, struct ker_ipv4_address *, struct ker_tx_export *);
/* Unregisters the receiver and releases the exporter pin. Queued replies remain
 * owned by the exporter and must be drained or canceled before its cleanup. */
int ker_arp_responder_unregister(struct ker_arp_responder *);

#endif
