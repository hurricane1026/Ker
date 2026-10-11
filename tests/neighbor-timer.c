#include "check.h"
#include "eal.h"
#include "runtime/neighbor-timer.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/arp.h"
#include "runtime/memory.h"
#include "runtime/arp-probe-port.h"
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <stdatomic.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static struct ker_runtime runtime_clock;
static struct ker_neighbor_monitor monitor;
static unsigned int probes, notifications, last_state;
static bool build_probes;
static struct ker_neighbor_event saved_event;
static const struct ker_neighbor_event *saved_event_pointer;
static unsigned int built_probes;
static bool update_reentry;
static const unsigned char mac[6] = {2,1,2,3,4,5}, peer[6] = {2,6,7,8,9,10};
static const unsigned char changed_peer[6] = {2,10,9,8,7,6};
static struct neighbour *seq_entry;
static atomic_int seq_stress_error;
static __be32 ip(unsigned int n) { return rte_cpu_to_be_32(0xc0000200U+n); }
static void guarded(const struct ker_neighbor_event *e)
{
    CHECK(e->ip == ip(2) && (memcmp(e->mac,peer,6)==0 || memcmp(e->mac,changed_peer,6)==0));
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
    if (build_probes) {
        saved_event = *e; saved_event_pointer = &saved_event;
        struct ker_neighbor_event copy = *e;
        struct sk_buff *skb = (void *)(uintptr_t)1;
        CHECK(ker_arp_probe_create(NULL, e, &skb) == -EINVAL && skb == (void *)(uintptr_t)1);
        CHECK(ker_arp_probe_create(&monitor, NULL, &skb) == -EINVAL && skb == (void *)(uintptr_t)1);
        CHECK(ker_arp_probe_create(&monitor, e, NULL) == -EINVAL && skb == (void *)(uintptr_t)1);
        CHECK(ker_arp_probe_create(&monitor, &copy, &skb) == -EPERM && skb == (void *)(uintptr_t)1);
        if (!built_probes) {
            address.native->cnf.data[IPV4_DEVCONF_ARP_ANNOUNCE - 1] = 1;
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            address.native->cnf.data[IPV4_DEVCONF_ARP_ANNOUNCE - 1] = 0;
            address.native->cnf.data[IPV4_DEVCONF_ROUTE_LOCALNET - 1] = 1;
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            address.native->cnf.data[IPV4_DEVCONF_ROUTE_LOCALNET - 1] = 0;
            NEIGH_VAR_SET(monitor.entry->parms, APP_PROBES, 1);
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            NEIGH_VAR_SET(monitor.entry->parms, APP_PROBES, 0);
            unsigned int saved_flags = address.native->ifa_list->ifa_flags;
            address.native->ifa_list->ifa_flags |= IFA_F_SECONDARY;
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            address.native->ifa_list->ifa_flags = saved_flags;
            struct in_ifaddr *saved_ifa = address.native->ifa_list;
            address.native->ifa_list = NULL;
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            address.native->ifa_list = saved_ifa;
            const struct header_ops *saved_ops = device.native->header_ops;
            device.native->header_ops = NULL;
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOTSUP && skb == (void *)(uintptr_t)1);
            device.native->header_ops = saved_ops;
            ker_memory_fail_after(0);
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOMEM && skb == (void *)(uintptr_t)1);
            ker_memory_fail_after(-1);
            struct rte_mbuf *held[31];
            for (unsigned int i=0; i<31; ++i) CHECK((held[i]=ker_packet_alloc(&pool)) != NULL);
            CHECK(ker_arp_probe_create(&monitor, e, &skb) == -ENOMEM && skb == (void *)(uintptr_t)1);
            for (unsigned int i=0; i<31; ++i) ker_packet_free(held[i]);
        }
        __be32 saved_mask = address.native->ifa_list->ifa_mask;
        if (!built_probes) address.native->ifa_list->ifa_mask = inet_make_mask(32);
        CHECK(ker_arp_probe_create(&monitor, e, &skb) == 0);
        address.native->ifa_list->ifa_mask = saved_mask;
        CHECK(skb->len == 42 && skb->mac_len == ETH_HLEN && skb->mac_header == skb_headroom(skb));
        CHECK(skb->network_header == skb->mac_header + ETH_HLEN);
        unsigned char expected[42] = {0};
        if (e->probes < 2) memcpy(expected, peer, 6); else memset(expected, 0xff, 6);
        memcpy(expected + 6, mac, 6); expected[12] = 8; expected[13] = 6;
        expected[15] = 1; expected[16] = 8; expected[18] = 6; expected[19] = 4;
        expected[21] = ARPOP_REQUEST; memcpy(expected + 22, mac, 6);
        memcpy(expected + 28, &( __be32 ){ip(1)}, 4); memcpy(expected + 38, &e->ip, 4);
        CHECK(memcmp(skb->data, expected, sizeof(expected)) == 0);
        struct rte_mbuf *exported = NULL;
        CHECK(ker_skb_to_mbuf(skb, &exported) == 0 && exported->pkt_len == sizeof(expected));
        CHECK(memcmp(rte_pktmbuf_mtod(exported, const unsigned char *), expected, sizeof(expected)) == 0);
        CHECK(ker_skb_free(skb) == 0); ker_packet_free(exported); ++built_probes;
    }
    ++probes;
}
static void notify(const struct ker_neighbor_event *e,void *arg)
{
    CHECK(arg==&monitor); guarded(e); ++notifications; last_state=e->state;
    if(update_reentry)
        CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-EBUSY);
    if (build_probes) {
        struct sk_buff *skb = (void *)(uintptr_t)1;
        CHECK(ker_arp_probe_create(&monitor, e, &skb) == -EPERM && skb == (void *)(uintptr_t)1);
    }
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
static void *foreign_probe(void *arg)
{
    (void)arg; struct sk_buff *skb = (void *)(uintptr_t)1;
    CHECK(ker_arp_probe_create(&monitor, saved_event_pointer, &skb) == -EXDEV);
    CHECK(skb == (void *)(uintptr_t)1); return NULL;
}
static void *foreign_update(void *arg)
{
    (void)arg; CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-EXDEV); return NULL;
}
static void *seqlock_writer(void *arg)
{
    struct neighbour *entry=arg;
    const unsigned char first[ETH_ALEN]={0x22,0x22,0x22,0x22,0x22,0x22};
    const unsigned char second[ETH_ALEN]={0x44,0x44,0x44,0x44,0x44,0x44};
    for(unsigned int i=0;i<50000;++i) {
        ker_neighbor_update_seq_write_lock(&entry->ha_lock);
        memcpy(entry->ha,(i&1)?first:second,ETH_ALEN);
        ker_neighbor_update_seq_write_unlock(&entry->ha_lock);
    }
    return NULL;
}
static void *seqlock_reader(void *arg)
{
    struct neighbour *entry=arg;
    unsigned char snapshot[ETH_ALEN];
    for(unsigned int i=0;i<50000;++i) {
        neigh_ha_snapshot((char *)snapshot,entry,entry->dev);
        bool first=true,second=true;
        for(unsigned int j=0;j<ETH_ALEN;++j) {
            first &= snapshot[j]==0x22;
            second &= snapshot[j]==0x44;
        }
        if(!first && !second) atomic_store(&seq_stress_error,1);
    }
    return NULL;
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    CHECK(ker_packet_pool_init(&pool,"timer_packets",31,0,2048,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&context,&pool,"timer_skbs")==0);
    CHECK(ker_eth_device_init(&device,&context,"eth0",1,mac)==0);
    CHECK(ker_arp_device_setup(&device)==0);
    CHECK(ker_ipv4_address_init(&address,&device,ip(1),24)==0);
    CHECK(ker_neighbor_table_init(&table,&address,"timer_neighbors",3,1)==0);
    struct ker_neighbor_config config={.retrans_ticks=20,.reachable_ticks=100,.delay_ticks=30,.ucast_probes=2,.mcast_reprobes=1};
    CHECK(ker_neighbor_configure(&table,&config)==0);
    CHECK(ker_neighbor_add(&table,ip(2),peer)==0);
    CHECK(ker_neighbor_lookup(&table,ip(2),&seq_entry)==0);
    const unsigned char seq_initial[ETH_ALEN]={0x22,0x22,0x22,0x22,0x22,0x22};
    ker_neighbor_update_restore_mac(seq_entry,seq_initial);
    atomic_init(&seq_stress_error,0);
    pthread_t seq_writer,seq_reader;
    CHECK(pthread_create(&seq_writer,NULL,seqlock_writer,seq_entry)==0);
    CHECK(pthread_create(&seq_reader,NULL,seqlock_reader,seq_entry)==0);
    CHECK(pthread_join(seq_writer,NULL)==0 && pthread_join(seq_reader,NULL)==0);
    CHECK(atomic_load(&seq_stress_error)==0);
    ker_neighbor_update_restore_mac(seq_entry,peer);
    CHECK(ker_neighbor_release(&table,seq_entry)==0); seq_entry=NULL;
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
    build_probes=true; built_probes=0;
    next(); CHECK(state()==NUD_PROBE && probes==1 && last_state==NUD_PROBE);
    next(); next(); CHECK(probes==3 && state()==NUD_PROBE && built_probes==3);
    build_probes=false;
    struct sk_buff *outside = (void *)(uintptr_t)1;
    CHECK(ker_arp_probe_create(&monitor,saved_event_pointer,&outside)==-EPERM && outside==(void *)(uintptr_t)1);
    CHECK(pthread_create(&thread,NULL,foreign_probe,NULL)==0 && pthread_join(thread,NULL)==0);
    build_probes=true; next(); build_probes=false;
    CHECK(state()==NUD_FAILED && last_state==NUD_FAILED);
    CHECK(monitor.stats.res_failed==1 && notifications==3);
    CHECK(refcount_read(&monitor.entry->refcnt)==2 && !timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-ENOTSUP);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    struct sk_buff *clean_output = (void *)(uintptr_t)1;
    CHECK(ker_arp_probe_create(&monitor, &saved_event, &clean_output) == -EINVAL &&
          clean_output == (void *)(uintptr_t)1);
    /* Native neigh_update is bounded to valid monitored entries and preserves
     * Linux's no-override partial timestamp update before rejecting a new MAC. */
    init();
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-ENOTSUP);
    stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0 && state()==NUD_DELAY);
    CHECK(timer_pending(&monitor.entry->timer) && refcount_read(&monitor.entry->refcnt)==3);
    unsigned int saved_addr_len=monitor.entry->dev->addr_len;
    monitor.entry->dev->addr_len=5;
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-ENOTSUP);
    CHECK(state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0);
    monitor.entry->dev->addr_len=saved_addr_len;
    int64_t saved_clock=runtime_clock.now_ns;
    runtime_clock.now_ns=INT64_MAX-INT64_C(50000000);
    unsigned long saved_confirmed=monitor.entry->confirmed;
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-EOVERFLOW);
    CHECK(state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0 &&
          monitor.entry->confirmed==saved_confirmed && timer_pending(&monitor.entry->timer) &&
          refcount_read(&monitor.entry->refcnt)==3);
    runtime_clock.now_ns=saved_clock;
    pthread_t update_thread;
    CHECK(pthread_create(&update_thread,NULL,foreign_update,NULL)==0 && pthread_join(update_thread,NULL)==0);
    unsigned long confirmed=monitor.entry->confirmed, updated=monitor.entry->updated;
    int64_t original_deadline;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&original_deadline)==1);
    unsigned int before_notifications=notifications;
    runtime_clock.now_ns += INT64_C(3000000);
    CHECK(ker_neighbor_monitor_update(&monitor, NULL, NEIGH_UPDATE_F_OVERRIDE)==-EINVAL);
    CHECK(state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0 &&
          monitor.entry->confirmed==confirmed && monitor.entry->updated==updated &&
          timer_pending(&monitor.entry->timer) && refcount_read(&monitor.entry->refcnt)==3 &&
          notifications==before_notifications);
    int64_t unchanged_deadline;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&unchanged_deadline)==1 && unchanged_deadline==original_deadline);
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, 0)==0);
    CHECK(monitor.entry->confirmed > confirmed && monitor.entry->updated==updated);
    CHECK(state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0 && notifications==before_notifications);
    CHECK(ker_runtime_next_deadline(&runtime_clock,&unchanged_deadline)==1 && unchanged_deadline==original_deadline);
    const unsigned char invalid_macs[][ETH_ALEN]={{0,0,0,0,0,0},{1,0,0,0,0,1},{0xff,0xff,0xff,0xff,0xff,0xff}};
    for(unsigned int i=0;i<sizeof(invalid_macs)/sizeof(invalid_macs[0]);++i) {
        unsigned long before_confirmed=monitor.entry->confirmed, before_updated=monitor.entry->updated;
        CHECK(ker_neighbor_monitor_update(&monitor, invalid_macs[i], NEIGH_UPDATE_F_OVERRIDE)==-EINVAL);
        CHECK(state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0 &&
              monitor.entry->confirmed==before_confirmed && monitor.entry->updated==before_updated &&
              timer_pending(&monitor.entry->timer) && refcount_read(&monitor.entry->refcnt)==3 &&
              notifications==before_notifications);
        CHECK(ker_runtime_next_deadline(&runtime_clock,&unchanged_deadline)==1 && unchanged_deadline==original_deadline);
    }
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_ADMIN)==-ENOTSUP);
    struct neighbour *extra_reference=NULL;
    CHECK(ker_neighbor_lookup(&table,ip(2),&extra_reference)==0);
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-EBUSY);
    CHECK(ker_neighbor_release(&table,extra_reference)==0);
    update_reentry=true;
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==0);
    update_reentry=false;
    CHECK(state()==NUD_REACHABLE && memcmp(monitor.entry->ha,changed_peer,ETH_ALEN)==0);
    CHECK(monitor.entry->output==monitor.ops.connected_output && timer_pending(&monitor.entry->timer));
    CHECK(refcount_read(&monitor.entry->refcnt)==3 && notifications==before_notifications+1 && last_state==NUD_REACHABLE);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_neighbor_lookup(&table,ip(2),&extra_reference)==0);
    unsigned char restored[ETH_ALEN];
    CHECK(ker_neighbor_mac(&table,extra_reference,restored)==0 && memcmp(restored,peer,ETH_ALEN)==0);
    CHECK(ker_neighbor_release(&table,extra_reference)==0);
    init(); stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0);
    next(); CHECK(state()==NUD_PROBE && timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==0);
    CHECK(state()==NUD_REACHABLE && memcmp(monitor.entry->ha,changed_peer,ETH_ALEN)==0);
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
    CHECK(ker_neighbor_monitor_update(&monitor, changed_peer, NEIGH_UPDATE_F_OVERRIDE)==-EOVERFLOW);
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
    CHECK(ker_neighbor_add(&table,ip(2),peer)==0); ker_runtime_init(&runtime_clock);
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
