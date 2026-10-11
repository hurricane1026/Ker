#include "runtime/neighbor-timer.h"
#include "compat/neighbor-timer-port.h"
#include <rte_lcore.h>
#include <errno.h>
static _Thread_local struct ker_neighbor_monitor *active;
static int horizon(struct ker_runtime *, unsigned long);
static unsigned long interval(struct neigh_parms *p)
{
    unsigned long result = 10;
    unsigned long values[] = {(unsigned long)p->reachable_time,
        (unsigned long)NEIGH_VAR(p, RETRANS_TIME), (unsigned long)NEIGH_VAR(p, DELAY_PROBE_TIME)};
    for (unsigned int i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        if (values[i] > result) result = values[i];
    return result;
}
static struct ker_neighbor_monitor *scope(struct neighbour *entry)
{
    BUG_ON(!active || active->entry != entry || rte_lcore_id() != active->table->lcore);
    return active;
}
void ker_neigh_write_lock(rwlock_t *lock) { BUG_ON(pthread_rwlock_wrlock(&lock->native)); }
void ker_neigh_write_unlock(rwlock_t *lock) { BUG_ON(pthread_rwlock_unlock(&lock->native)); }
void ker_neigh_timer_release(struct neighbour *entry)
{
    scope(entry); BUG_ON(refcount_read(&entry->refcnt) <= 2);
    BUG_ON(refcount_dec_and_test(&entry->refcnt));
}
void ker_neigh_timer_stat(struct neigh_table *table, unsigned int offset)
{
    BUG_ON(!active || active->table->native != table || offset != offsetof(struct neigh_statistics, res_failed));
    active->stats.res_failed++;
}
void ker_neigh_timer_debug(void) { BUG_ON(!active); active->debug_events++; }
struct sk_buff *ker_neigh_empty_tail(struct sk_buff_head *queue)
{
    BUG_ON(!active || queue != &active->entry->arp_queue || queue->qlen ||
        queue->next != (struct sk_buff *)queue || queue->prev != (struct sk_buff *)queue);
    return NULL;
}
void ker_neigh_empty_purge(struct sk_buff_head *queue) { (void)ker_neigh_empty_tail(queue); }
struct sk_buff *ker_neigh_unsupported_clone(struct sk_buff *skb, gfp_t flags)
{ (void)skb; (void)flags; BUG_ON(true); return NULL; }
void ker_neigh_empty_consume(struct sk_buff *skb) { BUG_ON(skb); }
static void event(struct ker_neighbor_monitor *m, struct ker_neighbor_event *out)
{
    *out = (struct ker_neighbor_event){.state = m->entry->nud_state, .probes = (unsigned int)atomic_read(&m->entry->probes), .error=m->error};
    memcpy(&out->ip, m->entry->primary_key, sizeof(out->ip));
    memcpy(out->mac, m->entry->ha, sizeof(out->mac));
}
void ker_neigh_timer_notify(struct neighbour *entry) { scope(entry)->notification = true; }
int ker_neigh_timer_deliver(struct neighbour *entry)
{
    struct ker_neighbor_monitor *m = scope(entry); BUG_ON(!m->notification);
    m->notification = false;
    struct ker_neighbor_event e; event(m, &e);
    if (m->notify) m->notify(&e, m->arg);
    return 0;
}
void ker_neigh_timer_trace(struct neighbour *entry) { scope(entry)->timer_events++; }
static void solicit(struct neighbour *entry, struct sk_buff *skb)
{
    struct ker_neighbor_monitor *m = scope(entry); BUG_ON(skb);
    struct ker_neighbor_event e; event(m, &e);
    BUG_ON(m->probe_callback || m->probe_event);
    m->probe_callback = true; m->probe_event = &e;
    m->probe(&e, m->arg);
    m->probe_event = NULL; m->probe_callback = false;
}
static int unsupported_output(struct neighbour *entry, struct sk_buff *skb)
{ (void)entry; (void)skb; return -ENOTSUP; }
static void unsupported_error(struct neighbour *entry, struct sk_buff *skb)
{ (void)entry; (void)skb; BUG_ON(true); }
static int valid(struct ker_neighbor_monitor *m)
{
    if (!m || !m->table || !m->entry) return -EINVAL;
    if (rte_lcore_id() != m->table->lcore) return -EXDEV;
    if (m->busy || m->timer.running || m->timer.scoping) return -EBUSY;
    if (m->entry->tbl != m->table->native || m->entry->ops != &m->ops || m->entry->dead || m->entry->flags ||
        m->entry->arp_queue.qlen || m->entry->arp_queue_len_bytes) return -EINVAL;
    return 0;
}
static void timeout(struct timer_list *native)
{
    struct neighbour *entry = timer_container_of(entry, native, timer);
    struct ker_neighbor_monitor *m = container_of(entry->ops, struct ker_neighbor_monitor, ops);
    struct ker_neighbor_monitor *previous = active;
    BUG_ON(m->busy || m->entry != entry); m->busy = true; active = m;
    int bounds = horizon(m->timer.runtime, interval(entry->parms));
    if (bounds) {
        /* The expired timer still owns one reference. Stop before entering
         * native code, which cannot return an error from mod_timer. */
        m->error = bounds;
        if (m->notify) {
            struct ker_neighbor_event e; event(m, &e); m->notify(&e, m->arg);
        }
        ker_neigh_timer_release(entry);
    } else {
        ker_linux_neigh_timeout(native);
    }
    active = previous; m->busy = false;
}
static int start(void *arg)
{
    struct ker_neighbor_monitor *m = arg;
    ker_linux_neigh_start(m->entry, m->entry->nud_state == NUD_REACHABLE ?
        jiffies + m->entry->parms->reachable_time : jiffies + NEIGH_VAR(m->entry->parms, DELAY_PROBE_TIME));
    return 0;
}
static int confirm(void *arg) { neigh_confirm(((struct ker_neighbor_monitor *)arg)->entry); return 0; }
static int call(struct ker_neighbor_monitor *m, ker_timer_list_fn fn)
{
    struct ker_neighbor_monitor *previous = active; active = m; m->busy = true;
    int result = ker_timer_list_call(&m->timer, fn, m);
    m->busy = false; active = previous; return result;
}
static int horizon(struct ker_runtime *clock, unsigned long ticks)
{
    if (clock->now_ns < 0) return -EINVAL;
    int64_t base = clock->now_ns - clock->now_ns % INT64_C(1000000);
    if (ticks > (unsigned long)((INT64_MAX - base) / INT64_C(1000000))) return -EOVERFLOW;
    return 0;
}
int ker_neighbor_monitor_init(struct ker_neighbor_monitor *m, struct ker_neighbor_table *table,
    struct ker_runtime *clock, __be32 ip, ker_neighbor_event_fn probe, ker_neighbor_event_fn notify, void *arg)
{
    if (!m || !table || !table->native || !clock || !probe) return -EINVAL;
    if (m->entry || m->table) return -EALREADY;
    if (rte_lcore_id() != table->lcore) return -EXDEV;
    if (!NEIGH_VAR(&table->native->parms, RETRANS_TIME) || table->native->parms.reachable_time <= 0 ||
        !NEIGH_VAR(&table->native->parms, DELAY_PROBE_TIME)) return -EINVAL;
    if (clock->polling) return -EBUSY;
    int bounds = horizon(clock, interval(&table->native->parms));
    if (bounds) return bounds;
    struct neighbour *entry = NULL;
    int error = ker_neighbor_lookup(table, ip, &entry); if (error) return error;
    if (entry->nud_state != NUD_PERMANENT || refcount_read(&entry->refcnt) != 2 || entry->timer.function || entry->ops) {
        BUG_ON(refcount_dec_and_test(&entry->refcnt)); return -EBUSY;
    }
    *m = (struct ker_neighbor_monitor){.table=table,.entry=entry,.probe=probe,.notify=notify,.arg=arg};
    error = ker_timer_list_init(&m->timer, clock, &entry->timer, timeout);
    if (error) { BUG_ON(ker_neighbor_release(table, entry)); *m=(struct ker_neighbor_monitor){0}; return error; }
    m->ops = (struct neigh_ops){.solicit=solicit,.output=unsupported_output,.connected_output=unsupported_output,.error_report=unsupported_error};
    entry->ops=&m->ops; entry->output=m->ops.connected_output;
    unsigned long now; BUG_ON(ker_timer_list_now(&m->timer,&now));
    entry->nud_state=NUD_REACHABLE; entry->confirmed=now; entry->used=now; entry->updated=now;
    return call(m,start);
}
int ker_neighbor_monitor_probe(struct ker_neighbor_monitor *m)
{
    int error=valid(m); if(error)return error;
    if (m->error) return m->error;
    if(m->entry->nud_state != NUD_STALE)return -EALREADY;
    if (m->timer.runtime->polling) return -EBUSY;
    error = horizon(m->timer.runtime, interval(m->entry->parms));
    if (error) return error;
    unsigned long now; BUG_ON(ker_timer_list_now(&m->timer,&now));
    m->entry->nud_state=NUD_DELAY; m->entry->updated=now; m->entry->used=now;
    return call(m,start);
}
int ker_neighbor_monitor_confirm(struct ker_neighbor_monitor *m)
{
    int error=valid(m); if(error)return error;
    if (m->error) return m->error;
    if(!(m->entry->nud_state & (NUD_REACHABLE|NUD_DELAY|NUD_PROBE|NUD_STALE)))return -ENOTSUP;
    return call(m,confirm);
}
int ker_neighbor_monitor_snapshot(struct ker_neighbor_monitor *m,struct ker_neighbor_event *out)
{
    int error=valid(m); if(error)return error;
    if(!out)return -EINVAL;
    event(m,out); return 0;
}
int ker_neighbor_monitor_probe_scope(struct ker_neighbor_monitor *m, const struct ker_neighbor_event *e)
{
    if (!m || !e) return -EINVAL;
    if (!m->table || !m->entry) return -EINVAL;
    if (rte_lcore_id() != m->table->lcore) return -EXDEV;
    if (active != m || !m->busy || !m->probe_callback || m->probe_event != e) return -EPERM;
    struct ker_neighbor_event current; event(m, &current);
    if (current.ip != e->ip || current.state != e->state || current.probes != e->probes ||
        current.error != e->error || memcmp(current.mac, e->mac, sizeof(e->mac))) return -ESTALE;
    return 0;
}
int ker_neighbor_monitor_cleanup(struct ker_neighbor_monitor *m)
{
    int error=valid(m); if(error)return error;
    unsigned int refs=2U+!!timer_pending(&m->entry->timer);
    if((unsigned int)refcount_read(&m->entry->refcnt)!=refs)return -EBUSY;
    int pending=ker_timer_list_shutdown(&m->timer); if(pending<0)return pending;
    if(pending)BUG_ON(refcount_dec_and_test(&m->entry->refcnt));
    BUG_ON(ker_timer_list_cleanup(&m->timer));
    m->entry->nud_state=NUD_PERMANENT; m->entry->ops=NULL; m->entry->output=NULL;
    BUG_ON(ker_neighbor_release(m->table,m->entry)); *m=(struct ker_neighbor_monitor){0};return 0;
}
