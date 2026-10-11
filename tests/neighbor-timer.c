#include "check.h"
#include "eal.h"
#include "runtime/neighbor-timer.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>
#include <limits.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static struct ker_runtime runtime_clock;
static struct ker_neighbor_monitor monitor;
static unsigned int probes, notifications, last_state;
static const unsigned char mac[6] = {2,1,2,3,4,5};
static __be32 ip(unsigned int n) { return rte_cpu_to_be_32(0xc0000200U+n); }
static void guarded(const struct ker_neighbor_event *e)
{
    CHECK(e->ip == ip(2) && memcmp(e->mac,mac,6)==0);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-EBUSY);
    struct ker_neighbor_event out = {.state=99};
    CHECK(ker_neighbor_monitor_snapshot(&monitor,&out)==-EBUSY && out.state==99);
    CHECK(ker_runtime_poll(&runtime_clock,runtime_clock.now_ns,1)==-EBUSY);
}
static void probe(const struct ker_neighbor_event *e,void *arg)
{
    CHECK(arg==&monitor); guarded(e);
    CHECK(e->state==NUD_PROBE && e->probes==probes);
    ++probes;
}
static void notify(const struct ker_neighbor_event *e,void *arg)
{
    CHECK(arg==&monitor); guarded(e); ++notifications; last_state=e->state;
}
static unsigned int state(void)
{
    struct ker_neighbor_event e;
    CHECK(ker_neighbor_monitor_snapshot(&monitor,&e)==0);
    return e.state;
}
static void next(void)
{
    int64_t when;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&when)==1);
    CHECK(ker_runtime_poll(&runtime_clock,when,1)==1);
}
static void stale(void)
{
    for(unsigned int i=0;state()==NUD_REACHABLE && i<4;++i) next();
    CHECK(state()==NUD_STALE && !timer_pending(&monitor.entry->timer));
    CHECK(refcount_read(&monitor.entry->refcnt)==2);
}
static void init(void)
{
    probes=notifications=last_state=0;
    ker_memory_fail_after(0);
    CHECK(ker_neighbor_monitor_init(&monitor,&table,&runtime_clock,ip(2),probe,notify,&monitor)==0);
    ker_memory_fail_after(-1);
    CHECK(state()==NUD_REACHABLE && refcount_read(&monitor.entry->refcnt)==3);
    CHECK(ker_runtime_cleanup(&runtime_clock)==-EBUSY);
    CHECK(ker_neighbor_remove(&table,ip(2))==-EBUSY);
    CHECK(ker_neighbor_monitor_init(&monitor,&table,&runtime_clock,ip(2),probe,notify,&monitor)==-EALREADY);
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EALREADY);
    CHECK(monitor.entry->output(monitor.entry,NULL)==-ENOTSUP);
}
static void *foreign(void *arg)
{
    (void)arg; struct ker_neighbor_event out={.state=99};
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EXDEV);
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-EXDEV);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==-EXDEV);
    CHECK(ker_neighbor_monitor_snapshot(&monitor,&out)==-EXDEV && out.state==99);
    return NULL;
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    CHECK(ker_packet_pool_init(&pool,"timer_packets",31,0,2048,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&context,&pool,"timer_skbs")==0);
    CHECK(ker_eth_device_init(&device,&context,"eth0",1,mac)==0);
    CHECK(ker_ipv4_address_init(&address,&device,ip(1),24)==0);
    CHECK(ker_neighbor_table_init(&table,&address,"timer_neighbors",3,1)==0);
    struct ker_neighbor_config config={.retrans_ticks=20,.reachable_ticks=100,.delay_ticks=30,.ucast_probes=2,.mcast_reprobes=1};
    CHECK(ker_neighbor_configure(&table,&config)==0);
    CHECK(ker_neighbor_add(&table,ip(2),mac)==0);
    ker_runtime_init(&runtime_clock);
    CHECK(ker_neighbor_monitor_init(&monitor,&table,&runtime_clock,ip(3),probe,notify,&monitor)==-ENOENT);
    runtime_clock.now_ns=INT64_MAX;
    CHECK(ker_neighbor_monitor_init(&monitor,&table,&runtime_clock,ip(2),probe,notify,&monitor)==-EOVERFLOW);
    CHECK(!monitor.entry && !monitor.table); runtime_clock.now_ns=0;
    /* A mismatched clock owner rejects initialization without leaving a pin. */
    runtime_clock.native_owned=true; runtime_clock.native_lcore=1;
    CHECK(ker_neighbor_monitor_init(&monitor,&table,&runtime_clock,ip(2),probe,notify,&monitor)==-EXDEV);
    CHECK(!monitor.entry && !monitor.table && runtime_clock.native_live==0);
    ker_runtime_init(&runtime_clock);
    init();
    int64_t equality;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&equality)==1);
    CHECK(ker_runtime_poll(&runtime_clock,equality,8)==1);
    CHECK(state()==NUD_REACHABLE);
    int64_t clamped;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&clamped)==1);
    CHECK(clamped==equality+INT64_C(10000000));
    pthread_t thread;
    CHECK(pthread_create(&thread,NULL,foreign,NULL)==0 && pthread_join(thread,NULL)==0);
    struct neighbour *held=NULL;
    CHECK(ker_neighbor_lookup(&table,ip(2),&held)==0);
    unsigned char snapshot[6]={99};
    CHECK(ker_neighbor_mac(&table,held,snapshot)==-ENOTSUP && snapshot[0]==99);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==-EBUSY);
    CHECK(ker_neighbor_release(&table,held)==0);
    stale(); CHECK(last_state==NUD_STALE);
    int64_t saved_now=runtime_clock.now_ns;
    runtime_clock.now_ns=INT64_MAX;
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EOVERFLOW && state()==NUD_STALE);
    CHECK(!timer_pending(&monitor.entry->timer)); runtime_clock.now_ns=saved_now;
    CHECK(ker_neighbor_monitor_probe(&monitor)==0 && state()==NUD_DELAY);
    next(); CHECK(state()==NUD_PROBE && probes==1 && last_state==NUD_PROBE);
    next(); next(); CHECK(probes==3 && state()==NUD_PROBE);
    next(); CHECK(state()==NUD_FAILED && last_state==NUD_FAILED);
    CHECK(monitor.stats.res_failed==1 && notifications==3);
    CHECK(refcount_read(&monitor.entry->refcnt)==2 && !timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-ENOTSUP);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    /* First deadline fits, but its native equality rearm would overflow.
     * The adapter stops with an explicit error and releases the expired hold. */
    ker_runtime_init(&runtime_clock);
    int reachable=table.native->parms.reachable_time;
    runtime_clock.now_ns=INT64_MAX-(int64_t)reachable*INT64_C(1000000);
    init(); next();
    struct ker_neighbor_event stopped;
    CHECK(ker_neighbor_monitor_snapshot(&monitor,&stopped)==0);
    CHECK(stopped.error==-EOVERFLOW && stopped.state==NUD_REACHABLE);
    CHECK(refcount_read(&monitor.entry->refcnt)==2 && !timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-EOVERFLOW);
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EOVERFLOW);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    ker_runtime_init(&runtime_clock);
    /* Positive feedback during DELAY restores native REACHABLE on expiry. */
    init(); stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0);
    CHECK(ker_runtime_poll(&runtime_clock,runtime_clock.now_ns+INT64_C(15000000),1)==0);
    CHECK(ker_neighbor_monitor_confirm(&monitor)==0);
    next(); CHECK(state()==NUD_REACHABLE && probes==0 && last_state==NUD_REACHABLE);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0 && runtime_clock.native_live==0);
    /* Native unsigned jiffies rollover preserves the timeout ordering. */
    CHECK(ker_runtime_cleanup(&runtime_clock)==0); ker_runtime_init(&runtime_clock);
    CHECK(ker_timer_list_set_epoch(&runtime_clock,ULONG_MAX-50)==0);
    init(); stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0);
    next(); CHECK(state()==NUD_PROBE); CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_runtime_cleanup(&runtime_clock)==0);
    CHECK(ker_neighbor_remove(&table,ip(2))==0);
    config.ucast_probes=config.mcast_reprobes=0;
    CHECK(ker_neighbor_configure(&table,&config)==0);
    CHECK(ker_neighbor_add(&table,ip(2),mac)==0); ker_runtime_init(&runtime_clock);
    init(); stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0); next();
    CHECK(state()==NUD_FAILED && probes==0 && monitor.stats.res_failed==1);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_runtime_cleanup(&runtime_clock)==0 && ker_neighbor_remove(&table,ip(2))==0);
    CHECK(ker_neighbor_table_cleanup(&table)==0 && ker_ipv4_address_cleanup(&address)==0);
    CHECK(ker_eth_device_cleanup(&device)==0 && ker_skb_context_cleanup(&context)==0);
    CHECK(ker_packet_pool_cleanup(&pool)==0 && ker_memory_live_allocations()==0);
    CHECK(ker_memory_shutdown()==0 && rte_eal_cleanup()==0);
    puts("native neighbor timers: reachability, retries, feedback, rollover and lifetime passed");
}
