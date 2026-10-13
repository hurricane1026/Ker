#include "runtime/neighbor-timer.h"
#include "compat/neighbor-timer-port.h"
#include "compat/neighbor-event-send-port.h"
#include "compat/neighbor-output-port.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/tx-export.h"
#include "runtime/skb.h"
#include "runtime/arp.h"
#include <linux/if_ether.h>
#include <rte_lcore.h>
#include <errno.h>
#include <string.h>
#include <linux/bug.h>
static _Thread_local struct ker_neighbor_monitor *active;
static _Thread_local unsigned long bh_saved_flags;
static _Thread_local bool bh_active;
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
void ker_neigh_event_write_lock_bh(rwlock_t *lock)
{
    BUG_ON(!active || bh_active || ker_local_irq_disabled());
    bh_saved_flags=ker_local_irq_save(); bh_active=true;
    ker_neigh_write_lock(lock);
}
void ker_neigh_event_write_unlock(rwlock_t *lock)
{ BUG_ON(!active || !bh_active || !ker_local_irq_disabled()); ker_neigh_write_unlock(lock); }
void ker_neigh_event_local_bh_enable(void)
{
    BUG_ON(!active || !bh_active || !ker_local_irq_disabled());
    bh_active=false; ker_local_irq_restore(bh_saved_flags); bh_saved_flags=0;
}
void ker_neigh_event_write_unlock_bh(rwlock_t *lock)
{ ker_neigh_event_write_unlock(lock); ker_neigh_event_local_bh_enable(); }
void ker_neigh_event_trace_done(struct neighbour *entry,int result)
{ struct ker_neighbor_monitor *m=scope(entry); m->event_send_events++; m->event_send_result=result; }
void ker_neigh_event_trace_dead(struct neighbour *entry,int result)
{ struct ker_neighbor_monitor *m=scope(entry); m->event_send_dead_events++; m->event_send_result=result; }
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
static int call_arg(struct ker_neighbor_monitor *m, ker_timer_list_fn fn, void *arg)
{
    struct ker_neighbor_monitor *previous = active; active = m; m->busy = true;
    bool previous_polling=m->timer.runtime->polling; m->timer.runtime->polling=true;
    int result = ker_timer_list_call(&m->timer, fn, arg);
    m->timer.runtime->polling=previous_polling; m->busy = false; active = previous; return result;
}
static int call(struct ker_neighbor_monitor *m, ker_timer_list_fn fn) { return call_arg(m, fn, m); }
struct update_args { struct neighbour *entry; const unsigned char *mac; u32 flags; };
static int update_native(void *arg)
{
    struct update_args *update = arg;
    return ker_linux_neigh_update(update->entry, update->mac, NUD_REACHABLE, update->flags);
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
    neigh_ha_snapshot((char *)m->original_mac, entry, entry->dev);
    m->original_confirmed=entry->confirmed; m->original_used=entry->used;
    m->original_updated=entry->updated; m->original_probes=(unsigned int)atomic_read(&entry->probes);
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
    return ker_neighbor_monitor_event_send(m);
}
static int event_send_native(void *arg)
{
    struct ker_neighbor_monitor *m=arg;
    return ker_linux_neigh_event_send(m->entry,NULL,false);
}
int ker_neighbor_monitor_event_send(struct ker_neighbor_monitor *m)
{
    int error=valid(m); if(error)return error;
    if(m->error)return m->error;
    if(m->timer.runtime->polling || ker_local_irq_disabled())return -EBUSY;
    struct neighbour *entry=m->entry;
    unsigned int state=entry->nud_state;
    if(state!=NUD_REACHABLE && state!=NUD_STALE && state!=NUD_DELAY && state!=NUD_PROBE)
        return -ENOTSUP;
    if(!entry->dev || !m->table->address || !m->table->address->device ||
       !m->table->address->device->native || entry->dev->type!=ARPHRD_ETHER ||
       entry->dev->addr_len!=ETH_ALEN || m->table->address->device->native!=entry->dev ||
       NEIGH_VAR(entry->parms,APP_PROBES)!=0 || entry->arp_queue.qlen ||
       entry->arp_queue_len_bytes || entry->hh.hh_len ||
       (entry->dev->header_ops && entry->dev->header_ops->cache_update))return -ENOTSUP;
    bool pending=timer_pending(&entry->timer);
    if(pending != (state!=NUD_STALE))return -ENOTSUP;
    unsigned int refs=2U+(unsigned int)pending;
    if((unsigned int)refcount_read(&entry->refcnt)!=refs)return -EBUSY;
    if(state==NUD_STALE) {
        error=horizon(m->timer.runtime,(unsigned long)NEIGH_VAR(entry->parms,DELAY_PROBE_TIME));
        if(error)return error;
    }
    int result=call_arg(m,event_send_native,m);
    BUG_ON(bh_active || ker_local_irq_disabled());
    return result;
}
struct output_args { struct ker_neighbor_monitor *monitor; struct sk_buff **packet; };
static int output_native(void *arg)
{
    struct output_args *a=arg;
    struct sk_buff *skb=*a->packet;
    /* This is the ownership boundary: timer-scope setup can fail before this
     * callback, while every native output path consumes the skb. */
    *a->packet=NULL;
    if (!skb->dev) skb->dev=a->monitor->entry->dev;
    return ker_linux_neigh_resolve_output(a->monitor->entry,skb);
}
void ker_neighbor_output_free(struct sk_buff *skb)
{
    BUG_ON(!active || !active->busy || !skb || ker_skb_free(skb));
}
int ker_neighbor_output_xmit(struct sk_buff *skb)
{
    BUG_ON(!active || !active->busy || !active->output_tx || !skb);
    struct sk_buff *owned=skb;
    int error=ker_tx_export_enqueue(active->output_tx,&owned);
    if(error) BUG_ON(ker_skb_free(skb));
    return error;
}
void ker_neighbor_output_unsupported_hh(void) { BUG_ON(true); }
int ker_neighbor_monitor_output(struct ker_neighbor_monitor *m, struct ker_tx_export *tx,
    struct sk_buff **packet)
{
    int error=valid(m); if(error)return error;
    if(!tx || !packet || !*packet)return -EINVAL;
    if(m->error)return m->error;
    if(m->timer.runtime->polling || ker_local_irq_disabled())return -EBUSY;
    struct neighbour *entry=m->entry;
    unsigned int state=entry->nud_state;
    if(state!=NUD_REACHABLE && state!=NUD_STALE && state!=NUD_DELAY && state!=NUD_PROBE)
        return -ENOTSUP;
    struct net_device *dev=entry->dev;
    if(!dev || dev->type!=ARPHRD_ETHER || dev->addr_len!=ETH_ALEN ||
       dev->hard_header_len!=ETH_HLEN || dev->needed_headroom || dev->needed_tailroom ||
       !dev->header_ops || dev->header_ops->create!=eth_header || dev->header_ops->cache ||
       dev->header_ops->cache_update || entry->hh.hh_len || entry->arp_queue.qlen ||
       entry->arp_queue_len_bytes || !m->table->address || !m->table->address->device ||
       !m->table->address->native || !m->table->address->native->ifa_list ||
       m->table->address->device->native!=dev || NEIGH_VAR(entry->parms,APP_PROBES)!=0)
        return -ENOTSUP;
    bool pending=timer_pending(&entry->timer);
    if(pending != (state!=NUD_STALE))return -ENOTSUP;
    if((unsigned int)refcount_read(&entry->refcnt)!=2U+(unsigned int)pending)return -EBUSY;
    if(tx->queue.context!=m->table->address->device->context || !tx->sink || tx->polling)
        return -EXDEV;
    struct sk_buff *skb=*packet;
    error=ker_skb_validate(skb,tx->queue.context); if(error)return error;
    if(skb->next || skb->prev)return -EBUSY;
    if((uintptr_t)skb->data & 1U)return -EINVAL;
    struct skb_shared_info *info=skb_shinfo(skb);
    if(skb_shared(skb) || skb_cloned(skb) || skb->nohdr || skb->data_len ||
       info->nr_frags || info->frag_list || info->flags || info->gso_size || info->gso_type ||
       info->tx_flags || info->destructor_arg || skb->head_frag || skb->pp_recycle || skb->fclone ||
       skb->ip_summed!=CHECKSUM_NONE)return -ENOTSUP;
    if(skb->dev && skb->dev!=dev)return -EXDEV;
    if(skb->protocol!=rte_cpu_to_be_16(ETH_P_IP) || skb->len<ETH_HLEN+20 ||
       skb->mac_len!=ETH_HLEN || skb->mac_header!=skb_headroom(skb) ||
       skb->network_header!=skb->mac_header+ETH_HLEN)return -EINVAL;
    const unsigned char *frame=skb->data;
    const unsigned char *ip_header=frame+ETH_HLEN;
    unsigned int ihl=(ip_header[0]&0x0fU)*4U;
    unsigned int total=((unsigned int)ip_header[2]<<8)|ip_header[3];
    if(frame[12]!=0x08 || frame[13]!=0x00 || (ip_header[0]>>4)!=4 ||
       ihl<20 || ihl>60 || total<ihl || total!=skb->len-ETH_HLEN ||
       skb->transport_header!=skb->network_header+ihl ||
       total>dev->mtu || memcmp(ip_header+12,&m->table->address->native->ifa_list->ifa_local,4) ||
       memcmp(ip_header+16,entry->primary_key,4))return -EINVAL;
    if(state==NUD_STALE) {
        error=horizon(m->timer.runtime,(unsigned long)NEIGH_VAR(entry->parms,DELAY_PROBE_TIME));
        if(error)return error;
    }
    struct output_args args={m,packet};
    m->output_tx=tx;
    int result=call_arg(m,output_native,&args);
    m->output_tx=NULL;
    BUG_ON(bh_active || ker_local_irq_disabled());
    return result;
}
int ker_neighbor_monitor_confirm(struct ker_neighbor_monitor *m)
{
    int error=valid(m); if(error)return error;
    if (m->error) return m->error;
    if(!(m->entry->nud_state & (NUD_REACHABLE|NUD_DELAY|NUD_PROBE|NUD_STALE)))return -ENOTSUP;
    return call(m,confirm);
}
int ker_neighbor_monitor_update(struct ker_neighbor_monitor *m, const unsigned char mac[ETH_ALEN], u32 flags)
{
    int error=valid(m); if(error)return error;
    if(m->error)return m->error;
    if(!mac)return -EINVAL;
    if(flags != 0 && flags != NEIGH_UPDATE_F_OVERRIDE)return -ENOTSUP;
    if(m->notification || m->probe_callback)return -EBUSY;
    struct net_device *dev=m->entry->dev;
    if(!m->table->address || !m->table->address->device ||
       dev!=m->table->address->device->native || dev->type!=ARPHRD_ETHER || dev->addr_len!=ETH_ALEN)
        return -ENOTSUP;
    if(m->timer.runtime->polling)return -EBUSY;
    if(m->entry->nud_state != NUD_PROBE && m->entry->nud_state != NUD_DELAY)return -ENOTSUP;
    if(!timer_pending(&m->entry->timer) || m->entry->arp_queue.qlen || m->entry->arp_queue_len_bytes ||
       m->entry->hh.hh_len || (m->entry->dev->header_ops && m->entry->dev->header_ops->cache_update))return -ENOTSUP;
    unsigned int refs=2U+!!timer_pending(&m->entry->timer);
    if((unsigned int)refcount_read(&m->entry->refcnt)!=refs)return -EBUSY;
    bool nonzero=false; for(unsigned int i=0;i<ETH_ALEN;++i)nonzero|=mac[i]!=0;
    if(!nonzero || (mac[0]&1))return -EINVAL;
    error=horizon(m->timer.runtime,(unsigned long)m->entry->parms->reachable_time);
    if(error)return error;
    struct update_args args={m->entry,mac,flags};
    return call_arg(m,update_native,&args);
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
    ker_neighbor_update_restore_mac(m->entry,m->original_mac);
    m->entry->confirmed=m->original_confirmed; m->entry->used=m->original_used;
    m->entry->updated=m->original_updated; atomic_set(&m->entry->probes,(int)m->original_probes);
    m->entry->nud_state=NUD_PERMANENT; m->entry->ops=NULL; m->entry->output=NULL;
    BUG_ON(ker_neighbor_release(m->table,m->entry)); *m=(struct ker_neighbor_monitor){0};return 0;
}
