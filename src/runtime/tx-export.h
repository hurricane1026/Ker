#ifndef KER_RUNTIME_TX_EXPORT_H
#define KER_RUNTIME_TX_EXPORT_H
#include "runtime/skb-queue.h"
#include "runtime/worker.h"

/* The sink accepts the copied mbuf only when it returns zero. Any nonzero
 * result means it accepted nothing; positive results are protocol errors. */
typedef int (*ker_tx_export_sink_fn)(struct rte_mbuf *, void *);
#define KER_TX_EXPORT_NOTE_SIZE 64U
struct ker_tx_export_observer_note {
    unsigned char bytes[KER_TX_EXPORT_NOTE_SIZE];
    size_t length;
    /* Valid only through the observer completion callback. */
    const struct sk_buff *skb;
    uint64_t skb_identity;
};
struct ker_tx_export_observer;
typedef int (*ker_tx_export_observer_prepare_fn)(
    const struct rte_mbuf *, struct ker_tx_export_observer_note *, void *);
typedef void (*ker_tx_export_observer_complete_fn)(
    const struct ker_tx_export_observer_note *, int sink_status, void *);
/* Caller-owned observer node. prepare must copy all data it needs into note;
 * complete runs after sink and must never inspect the mbuf. */
struct ker_tx_export_observer {
    struct ker_tx_export_observer *next;
    ker_tx_export_observer_prepare_fn prepare;
    ker_tx_export_observer_complete_fn complete;
    void *arg;
    struct ker_tx_export_observer_note note;
    /* Lifecycle pin; polling remains permitted while pinned. */
    bool attached, busy;
};
enum ker_tx_export_mode {
    KER_TX_EXPORT_SINGLE,
    KER_TX_EXPORT_CHAIN_NONE,
    KER_TX_EXPORT_CHAIN_SOFTWARE_CHECKSUM,
    KER_TX_EXPORT_CHAIN_SOFTWARE_CHECKSUM_EXACT,
};
struct ker_tx_export {
    struct ker_skb_queue queue;
    struct sk_buff *pending;
    size_t pending_charge;
    size_t bytes;
    size_t byte_limit;
    unsigned int packets;
    unsigned int packet_limit;
    unsigned int segment_payload_limit;
    unsigned int last_completed;
    unsigned int resolver_refs;
    unsigned int responder_refs;
    unsigned int ethdev_refs;
    int last_error;
    bool polling;
    enum ker_tx_export_mode mode;
    ker_tx_export_sink_fn sink;
    void *sink_arg;
    struct ker_tx_export_observer *observers;
};
/* Initialize tx to {0}. All operations are confined to the skb context's
 * owner worker. The sink owns only an accepted mbuf copy (return 0); every
 * other return accepts nothing. */
int ker_tx_export_init(struct ker_tx_export *, struct ker_skb_context *,
    unsigned int packet_limit, size_t byte_limit, ker_tx_export_sink_fn, void *);
/* Opt into copied DPDK chains. This mode admits CHECKSUM_NONE only; the sink
 * accepts/frees or retains the entire chain as one ownership unit. */
int ker_tx_export_init_chain(struct ker_tx_export *, struct ker_skb_context *,
    unsigned int packet_limit, size_t byte_limit, unsigned int segment_payload_limit,
    ker_tx_export_sink_fn, void *);
/* Opt into copied chains admitting CHECKSUM_NONE and supported Internet
 * CHECKSUM_PARTIAL packets. Partial checksums are completed in a private copy
 * on every attempt; the original remains unchanged while queued/retried. The
 * sink owns the whole chain only when it returns zero. */
int ker_tx_export_init_chain_software_checksum(struct ker_tx_export *,
    struct ker_skb_context *, unsigned int packet_limit, size_t byte_limit,
    unsigned int segment_payload_limit, ker_tx_export_sink_fn, void *);
/* Opt-in exact-fold variant. CHECKSUM_NONE packets are copied normally; only
 * CHECKSUM_PARTIAL completion preserves a folded zero. The caller selects
 * whether that protocol requires zero mangling. Existing modes are unchanged. */
int ker_tx_export_init_chain_software_checksum_exact(struct ker_tx_export *,
    struct ker_skb_context *, unsigned int packet_limit, size_t byte_limit,
    unsigned int segment_payload_limit, ker_tx_export_sink_fn, void *);
int ker_tx_export_enqueue(struct ker_tx_export *, struct sk_buff **);
int ker_tx_export_observer_attach(struct ker_tx_export *,
    struct ker_tx_export_observer *, ker_tx_export_observer_prepare_fn,
    ker_tx_export_observer_complete_fn, void *);
int ker_tx_export_observer_detach(struct ker_tx_export *,
    struct ker_tx_export_observer *);
/* Worker TX callback. Accepted copies are irreversible; failures after a
 * successful prefix return that count and expose the error in last_error. */
int ker_tx_export_poll(void *, unsigned int budget);
/* Return pending first, otherwise the FIFO head. */
int ker_tx_export_cancel(struct ker_tx_export *, struct sk_buff **);
/* Empty-only; never silently discards owned packets. */
int ker_tx_export_cleanup(struct ker_tx_export *);
#endif
