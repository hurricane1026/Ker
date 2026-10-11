#ifndef KER_COMPAT_NEIGHBOR_TIMER_PORT_H
#define KER_COMPAT_NEIGHBOR_TIMER_PORT_H
#include "ker/linux_neighbor_timer.h"
#include <linux/gfp.h>
#include <stdio.h>
#include <limits.h>
#include "compat/timer-list-scope.h"
#define __releases(lock)
#define __acquires(lock)
#define max(a,b) ((a) > (b) ? (a) : (b))
void ker_neigh_write_lock(rwlock_t *);
void ker_neigh_write_unlock(rwlock_t *);
#define write_lock ker_neigh_write_lock
#define write_unlock ker_neigh_write_unlock
void ker_neigh_timer_release(struct neighbour *);
#define neigh_release ker_neigh_timer_release
void ker_neigh_timer_stat(struct neigh_table *, unsigned int);
#define NEIGH_CACHE_STAT_INC(table, field) ker_neigh_timer_stat(table, offsetof(struct neigh_statistics, field))
void ker_neigh_timer_debug(void);
#define neigh_dbg(level, ...) ker_neigh_timer_debug()
#define printk(...) fprintf(stderr, __VA_ARGS__)
#define dump_stack() BUG_ON(true)
struct sk_buff *ker_neigh_empty_tail(struct sk_buff_head *);
void ker_neigh_empty_purge(struct sk_buff_head *);
#define skb_peek_tail ker_neigh_empty_tail
#define __skb_queue_purge ker_neigh_empty_purge
struct sk_buff *ker_neigh_unsupported_clone(struct sk_buff *, gfp_t);
void ker_neigh_empty_consume(struct sk_buff *);
#define skb_clone ker_neigh_unsupported_clone
#define consume_skb ker_neigh_empty_consume
/* Route notifications to the scoped adapter, not a pretend netlink service. */
void ker_neigh_timer_notify(struct neighbour *);
#define __neigh_notify(n, type, pid, flags) ker_neigh_timer_notify(n)
int ker_neigh_timer_deliver(struct neighbour *);
#define call_netevent_notifiers(type,n) ker_neigh_timer_deliver(n)
void ker_neigh_timer_trace(struct neighbour *);
#define trace_neigh_timer_handler(n, rc) ker_neigh_timer_trace(n)
#endif
