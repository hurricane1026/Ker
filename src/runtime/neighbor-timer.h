#ifndef KER_RUNTIME_NEIGHBOR_TIMER_H
#define KER_RUNTIME_NEIGHBOR_TIMER_H
#include "runtime/neighbor.h"
#include "runtime/timer-list.h"
#include "ker/linux_neighbor_timer.h"
struct ker_neighbor_monitor;
struct ker_tx_export;
/* Borrowed copied event data only; callbacks may enqueue a separately built
 * ARP packet. They may not mutate, remove, reenter, or free this monitor. */
struct ker_neighbor_event { __be32 ip; unsigned int state, probes; unsigned char mac[6]; int error; };
typedef void (*ker_neighbor_event_fn)(const struct ker_neighbor_event *, void *);
struct ker_neighbor_monitor {
    struct ker_neighbor_table *table;
    struct neighbour *entry;
    struct ker_timer_list timer;
    struct neigh_ops ops;
    unsigned char original_mac[ETH_ALEN];
    unsigned long original_confirmed, original_used, original_updated;
    unsigned int original_probes;
    ker_neighbor_event_fn probe, notify;
    void *arg;
    struct neigh_statistics stats;
    unsigned long debug_events, timer_events;
    unsigned long event_send_events, event_send_dead_events;
    int event_send_result;
    bool busy, notification, probe_callback;
    struct ker_tx_export *output_tx;
    const struct ker_neighbor_event *probe_event;
    int error; /* stopped adapter clock error; no synthetic NUD transition */
};
/* Pin a previously permanent entry and its table/clock. Explicit initialization
 * records REACHABLE from the supplied administrator-owned IP/MAC mapping.
 * Timing parameters must already be configured; no ARP learning or queues. */
int ker_neighbor_monitor_init(struct ker_neighbor_monitor *, struct ker_neighbor_table *,
    struct ker_runtime *, __be32 ip, ker_neighbor_event_fn probe, ker_neighbor_event_fn notify, void *);
/* Explicitly request delayed probing of a STALE entry through native
 * __neigh_event_send; only its documented monitor profile is admitted. */
int ker_neighbor_monitor_probe(struct ker_neighbor_monitor *);
/* Native __neigh_event_send on an existing empty-queue monitored entry.
 * Only REACHABLE/STALE/DELAY/PROBE and a NULL skb are supported. */
int ker_neighbor_monitor_event_send(struct ker_neighbor_monitor *);
/* Apply native neigh_resolve_output to one owned, writable, linear Ethernet +
 * IPv4 CHECKSUM_NONE skb with complete L2/L3 geometry, the monitor destination,
 * and the table's configured local source. Only REACHABLE/STALE/DELAY/PROBE
 * entries with the monitor's empty-queue/no-hh Ethernet profile are admitted.
 * Preflight errors preserve the packet slot and bytes. Native entry transfers
 * ownership; the slot is cleared even when export rejects and drops the packet. */
int ker_neighbor_monitor_output(struct ker_neighbor_monitor *, struct ker_tx_export *, struct sk_buff **);
/* Positive feedback only; invokes original neigh_confirm in the timer scope.
 * It does not revive FAILED neighbors or learn/change their MAC. */
int ker_neighbor_monitor_confirm(struct ker_neighbor_monitor *);
/* Apply native neigh_update semantics to an existing PROBE/DELAY entry.
 * flags accepts only zero or NEIGH_UPDATE_F_OVERRIDE. Updates are worker-owned,
 * monitor-scoped, and notify through the copied monitor event callback. */
int ker_neighbor_monitor_update(struct ker_neighbor_monitor *, const unsigned char mac[ETH_ALEN], u32 flags);
int ker_neighbor_monitor_snapshot(struct ker_neighbor_monitor *, struct ker_neighbor_event *);
/* Internal callback binding used by the native ARP probe adapter. */
int ker_neighbor_monitor_probe_scope(struct ker_neighbor_monitor *, const struct ker_neighbor_event *);
/* Cancel its timer/reference, restore the original permanent mapping, unpin.
 * Fails while native callbacks run or other lookup references remain. */
int ker_neighbor_monitor_cleanup(struct ker_neighbor_monitor *);
#endif
