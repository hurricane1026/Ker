#ifndef KER_RUNTIME_NEIGHBOR_TIMER_H
#define KER_RUNTIME_NEIGHBOR_TIMER_H
#include "runtime/neighbor.h"
#include "runtime/timer-list.h"
#include "ker/linux_neighbor_timer.h"
struct ker_neighbor_monitor;
/* Borrowed copied event data only; callbacks may enqueue a separately built
 * ARP packet. They may not mutate, remove, reenter, or free this monitor. */
struct ker_neighbor_event { __be32 ip; unsigned int state, probes; unsigned char mac[6]; int error; };
typedef void (*ker_neighbor_event_fn)(const struct ker_neighbor_event *, void *);
struct ker_neighbor_monitor {
    struct ker_neighbor_table *table;
    struct neighbour *entry;
    struct ker_timer_list timer;
    struct neigh_ops ops;
    ker_neighbor_event_fn probe, notify;
    void *arg;
    struct neigh_statistics stats;
    unsigned long debug_events, timer_events;
    bool busy, notification;
    int error; /* stopped adapter clock error; no synthetic NUD transition */
};
/* Pin a previously permanent entry and its table/clock. Explicit initialization
 * records REACHABLE from the supplied administrator-owned IP/MAC mapping.
 * Timing parameters must already be configured; no ARP learning or queues. */
int ker_neighbor_monitor_init(struct ker_neighbor_monitor *, struct ker_neighbor_table *,
    struct ker_runtime *, __be32 ip, ker_neighbor_event_fn probe, ker_neighbor_event_fn notify, void *);
/* Explicitly request delayed probing of a STALE entry; deadline/state are set
 * at this adapter boundary, then original Linux timer transitions take over. */
int ker_neighbor_monitor_probe(struct ker_neighbor_monitor *);
/* Positive feedback only; invokes original neigh_confirm in the timer scope.
 * It does not revive FAILED neighbors or learn/change their MAC. */
int ker_neighbor_monitor_confirm(struct ker_neighbor_monitor *);
int ker_neighbor_monitor_snapshot(struct ker_neighbor_monitor *, struct ker_neighbor_event *);
/* Cancel its timer/reference, restore the original permanent mapping, unpin.
 * Fails while native callbacks run or other lookup references remain. */
int ker_neighbor_monitor_cleanup(struct ker_neighbor_monitor *);
#endif
