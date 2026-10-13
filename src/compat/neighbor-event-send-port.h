#ifndef KER_COMPAT_NEIGHBOR_EVENT_SEND_PORT_H
#define KER_COMPAT_NEIGHBOR_EVENT_SEND_PORT_H
#include "ker/linux_neighbor_event_send.h"
#include "compat/neighbor-timer-port.h"
#include <linux/irqflags.h>
#include <linux/bug.h>
void ker_neigh_event_write_lock_bh(rwlock_t *);
void ker_neigh_event_write_unlock_bh(rwlock_t *);
void ker_neigh_event_write_unlock(rwlock_t *);
void ker_neigh_event_local_bh_enable(void);
void ker_neigh_event_trace_done(struct neighbour *, int);
void ker_neigh_event_trace_dead(struct neighbour *, int);
void ker_neigh_native_dst_force(struct sk_buff *);
struct sk_buff *ker_neigh_native_dequeue(struct sk_buff_head *);
void ker_neigh_native_queue_tail(struct sk_buff_head *, struct sk_buff *);
void ker_neigh_native_free(struct sk_buff *);
void ker_neigh_native_stat(struct neigh_table *, unsigned int);
#endif
