#include "check.h"
#include "eal.h"
#include "runtime/neighbor-timer.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/arp.h"
#include "runtime/udp-create.h"
#include "runtime/tx-export.h"
#include "runtime/memory.h"
#include "runtime/arp-probe-port.h"
#include <linux/irqflags.h>
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
static struct ker_tx_export output_tx;
static struct rte_mbuf *output_packet;
static int output_sink_error;
static unsigned int probes, notifications, last_state;
static bool build_probes;
static struct ker_neighbor_event saved_event;
static const struct ker_neighbor_event *saved_event_pointer;
static unsigned int built_probes;
static bool update_reentry;
static bool inject_resolution_probe_failure;
static const unsigned char mac[6] = {2,1,2,3,4,5}, peer[6] = {2,6,7,8,9,10};
static const unsigned char changed_peer[6] = {2,10,9,8,7,6};
static struct neighbour *seq_entry;
static atomic_int seq_stress_error;
static __be32 ip(unsigned int n) { return rte_cpu_to_be_32(0xc0000200U+n); }
static unsigned int state(void);
static int output_sink(struct rte_mbuf *packet, void *arg)
{
    CHECK(arg == &output_tx && !output_packet);
    if (output_sink_error) return output_sink_error;
    output_packet = packet;
    return 0;
}
static void resolved_output(unsigned int expected_state, const unsigned char expected_mac[ETH_ALEN])
{
    static const unsigned char old_mac[ETH_ALEN] = {2, 90, 91, 92, 93, 94};
    static const unsigned char payload[] = {0x31, 0x41, 0x59, 0x26};
    CHECK(ker_tx_export_init(&output_tx, &context, 2, SIZE_MAX, output_sink, &output_tx) == 0);
    struct sk_buff *skb = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1234), rte_cpu_to_be_16(4321), 64, NULL, 0,
        payload, sizeof(payload), &skb) == 0);
    unsigned char original[ETH_HLEN + 20 + 8 + sizeof(payload)];
    CHECK(skb->len == sizeof(original));
    memcpy(original, skb->data, sizeof(original));
    struct sk_buff *rejected = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1234), rte_cpu_to_be_16(4321), 64, NULL, 0,
        payload, sizeof(payload), &rejected) == 0);
    rejected->data[12] = 0x86;
    unsigned char rejected_wire[ETH_HLEN + 20 + 8 + sizeof(payload)];
    memcpy(rejected_wire, rejected->data, sizeof(rejected_wire));
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &rejected) == -EINVAL && rejected &&
        !memcmp(rejected->data, rejected_wire, sizeof(rejected_wire)));
    CHECK(ker_skb_free(rejected) == 0);
    unsigned int before_state = state();
    CHECK(before_state == expected_state);
    unsigned long used = monitor.entry->used;
    runtime_clock.now_ns += INT64_C(7000000);
    unsigned long now;
    CHECK(ker_timer_list_now(&monitor.timer, &now) == 0 && now > used);
    unsigned long event_trace = monitor.event_send_events;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == 0 && !skb);
    bool stale = before_state == NUD_STALE;
    CHECK(monitor.entry->used == now && monitor.event_send_events == event_trace + (stale ? 1U : 0U));
    if (stale) CHECK(state() == NUD_DELAY && timer_pending(&monitor.entry->timer) &&
        refcount_read(&monitor.entry->refcnt) == 3 && monitor.event_send_events == event_trace + 1);
    else CHECK(state() == before_state);
    CHECK(ker_tx_export_poll(&output_tx, 1) == 1 && output_packet);
    CHECK(output_packet->pkt_len == sizeof(original));
    const unsigned char *wire = rte_pktmbuf_mtod(output_packet, const unsigned char *);
    CHECK(!memcmp(wire, expected_mac, ETH_ALEN) && !memcmp(wire + ETH_ALEN, original + ETH_ALEN,
        sizeof(original) - ETH_ALEN));
    CHECK(memcmp(wire, original, ETH_ALEN) != 0 && used < monitor.entry->used);
    ker_packet_free(output_packet); output_packet = NULL;
    CHECK(ker_tx_export_cleanup(&output_tx) == 0);
}
static void output_admission_rejections(void)
{
    static const unsigned char old_mac[ETH_ALEN] = {2, 90, 91, 92, 93, 94};
    struct sk_buff *skb = NULL, *clone = NULL;
    CHECK(ker_tx_export_init(&output_tx, &context, 4, SIZE_MAX, output_sink, &output_tx) == 0);
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1), rte_cpu_to_be_16(2), 64, NULL, 0, "x", 1, &skb) == 0);
    CHECK(ker_skb_clone(skb, &clone) == 0);
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &clone) == -ENOTSUP && clone);
    CHECK(ker_skb_free(clone) == 0);
    int original_offset = skb->network_header;
    skb->network_header++;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EINVAL && skb);
    skb->network_header = original_offset;
    unsigned char original_wire[ETH_HLEN + 20 + 8 + 1];
    memcpy(original_wire, skb->data, sizeof(original_wire));
    skb->data[ETH_HLEN + 12] ^= 1;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EINVAL && skb);
    memcpy(skb->data, original_wire, sizeof(original_wire));
    skb->data[ETH_HLEN + 16] ^= 1;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EINVAL && skb);
    memcpy(skb->data, original_wire, sizeof(original_wire));
    unsigned int original_state = monitor.entry->nud_state;
    const unsigned int unresolved_states[] = {NUD_INCOMPLETE, NUD_FAILED};
    for (unsigned int i = 0; i < sizeof(unresolved_states) / sizeof(unresolved_states[0]); ++i) {
        monitor.entry->nud_state = unresolved_states[i];
        CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -ENOTSUP && skb);
    }
    monitor.entry->nud_state = original_state;
    unsigned short old_hh = monitor.entry->hh.hh_len;
    monitor.entry->hh.hh_len = 1;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -ENOTSUP && skb);
    monitor.entry->hh.hh_len = old_hh;
    unsigned long flags = ker_local_irq_save();
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EBUSY && skb);
    ker_local_irq_restore(flags);
    bool was_polling = runtime_clock.polling;
    runtime_clock.polling = true;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EBUSY && skb);
    runtime_clock.polling = was_polling;
    unsigned int timer_flags = monitor.timer.native->flags;
    monitor.timer.native->flags |= 0x80000000U;
    size_t live_before_scope_error = context.live;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &skb) == -EINVAL && skb &&
        context.live == live_before_scope_error && state() == original_state &&
        !memcmp(skb->data, original_wire, sizeof(original_wire)));
    monitor.timer.native->flags = timer_flags;
    CHECK(ker_skb_free(skb) == 0 && ker_tx_export_cleanup(&output_tx) == 0);
}
static void output_sink_retry(void)
{
    static const unsigned char old_mac[ETH_ALEN] = {2, 90, 91, 92, 93, 94};
    struct sk_buff *first = NULL, *second = NULL;
    CHECK(ker_tx_export_init(&output_tx, &context, 2, SIZE_MAX, output_sink, &output_tx) == 0);
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1111), rte_cpu_to_be_16(2222), 64, NULL, 0, "a", 1, &first) == 0);
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1111), rte_cpu_to_be_16(2222), 64, NULL, 0, "b", 1, &second) == 0);
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &first) == 0 && !first);
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &second) == 0 && !second);
    output_sink_error = -EAGAIN;
    CHECK(ker_tx_export_poll(&output_tx, 1) == -EAGAIN && !output_packet && output_tx.pending && output_tx.packets == 2);
    output_sink_error = 0;
    CHECK(ker_tx_export_poll(&output_tx, 1) == 1 && output_packet);
    CHECK(rte_pktmbuf_mtod(output_packet, const unsigned char *)[ETH_HLEN + 20 + 8] == 'a');
    ker_packet_free(output_packet); output_packet = NULL;
    CHECK(ker_tx_export_poll(&output_tx, 1) == 1 && output_packet);
    CHECK(rte_pktmbuf_mtod(output_packet, const unsigned char *)[ETH_HLEN + 20 + 8] == 'b');
    ker_packet_free(output_packet); output_packet = NULL;
    CHECK(ker_tx_export_cleanup(&output_tx) == 0);
}
static void output_backpressure(void)
{
    static const unsigned char old_mac[ETH_ALEN] = {2, 90, 91, 92, 93, 94};
    struct sk_buff *first = NULL, *second = NULL;
    CHECK(ker_tx_export_init(&output_tx, &context, 1, SIZE_MAX, output_sink, &output_tx) == 0);
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1111), rte_cpu_to_be_16(2222), 64, NULL, 0, "a", 1, &first) == 0);
    CHECK(ker_udp_ipv4_create_configured(&address, old_mac, ip(2),
        rte_cpu_to_be_16(1111), rte_cpu_to_be_16(2222), 64, NULL, 0, "b", 1, &second) == 0);
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &first) == 0 && !first && output_tx.packets == 1);
    size_t before_drop = context.live;
    CHECK(ker_neighbor_monitor_output(&monitor, &output_tx, &second) == -ENOSPC && !second &&
        output_tx.packets == 1 && context.live + 1 == before_drop);
    CHECK(ker_tx_export_poll(&output_tx, 1) == 1 && output_packet);
    ker_packet_free(output_packet); output_packet = NULL;
    CHECK(ker_tx_export_cleanup(&output_tx) == 0);
}
static void guarded(const struct ker_neighbor_event *e)
{
    CHECK(e->ip == ip(2) && (memcmp(e->mac,peer,6)==0 || memcmp(e->mac,changed_peer,6)==0));
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-EBUSY);
    struct ker_neighbor_event out = {.state=99};
    CHECK(ker_neighbor_monitor_snapshot(&monitor,&out)==-EBUSY && out.state==99);
    CHECK(ker_runtime_poll(&runtime_clock,runtime_clock.now_ns,1)==-EBUSY);
}
static void probe(const struct ker_neighbor_event *e,void *arg)
{
    CHECK(arg==&monitor); guarded(e);
    CHECK((e->state==NUD_PROBE || (monitor.resolution_enabled && e->state==NUD_INCOMPLETE)) && e->probes==probes);
    if (build_probes) {
        if (inject_resolution_probe_failure) {
            struct sk_buff *failed_probe = (void *)(uintptr_t)1;
            CHECK(ker_arp_probe_create(&monitor, e, &failed_probe) == -ENOMEM &&
                failed_probe == (void *)(uintptr_t)1);
            ++probes;
            return;
        }
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
        if (monitor.resolution_enabled) CHECK(ker_tx_export_enqueue(monitor.resolution_tx, &skb) == 0 && !skb);
        else CHECK(ker_skb_free(skb) == 0);
        ker_packet_free(exported); ++built_probes;
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
static void event_send_early(unsigned int expected_state)
{
    CHECK(state()==expected_state && timer_pending(&monitor.entry->timer));
    unsigned long confirmed=monitor.entry->confirmed,used=monitor.entry->used,updated=monitor.entry->updated;
    unsigned long trace=monitor.event_send_events;
    unsigned int refs=(unsigned int)refcount_read(&monitor.entry->refcnt);
    unsigned int probes=(unsigned int)atomic_read(&monitor.entry->probes);
    unsigned int notices=notifications;
    int64_t deadline,after;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&deadline)==1);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==0);
    CHECK(state()==expected_state && monitor.event_send_events==trace+1 &&
        monitor.event_send_result==0 && monitor.entry->confirmed==confirmed &&
        monitor.entry->used==used && monitor.entry->updated==updated &&
        atomic_read(&monitor.entry->probes)==(int)probes &&
        (unsigned int)refcount_read(&monitor.entry->refcnt)==refs && timer_pending(&monitor.entry->timer) &&
        notifications==notices);
    CHECK(ker_runtime_next_deadline(&runtime_clock,&after)==1 && after==deadline);
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
static void *foreign_event_send(void *arg)
{
    (void)arg; CHECK(ker_neighbor_monitor_event_send(&monitor)==-EXDEV); return NULL;
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
    struct ker_neighbor_config config={.retrans_ticks=20,.reachable_ticks=100,.delay_ticks=30,.ucast_probes=2,.mcast_probes=2,.mcast_reprobes=1,.queue_bytes=10000};
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
    CHECK(ker_neighbor_monitor_resolution_enable(&monitor, &output_tx) == -EINVAL);
    resolved_output(NUD_REACHABLE, peer);
    output_backpressure();
    output_admission_rejections();
    output_sink_retry();
    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
    init(); stale();
    resolved_output(NUD_STALE, peer);
    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
    init();
    int64_t equality;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&equality)==1);
    CHECK(ker_runtime_poll(&runtime_clock,equality,8)==1);
    CHECK(state()==NUD_REACHABLE);
    unsigned long event_used=monitor.entry->used;
    unsigned long event_trace=monitor.event_send_events;
    int64_t event_deadline;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&event_deadline)==1);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==0);
    CHECK(state()==NUD_REACHABLE && monitor.event_send_events==event_trace+1 &&
          monitor.event_send_result==0 && monitor.entry->used==event_used &&
          refcount_read(&monitor.entry->refcnt)==3 && timer_pending(&monitor.entry->timer));
    int64_t event_deadline_after;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&event_deadline_after)==1 && event_deadline_after==event_deadline);
    unsigned long irq_flags=ker_local_irq_save();
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-EBUSY && ker_local_irq_disabled());
    ker_local_irq_restore(irq_flags);
    unsigned long event_trace_before=monitor.event_send_events;
    NEIGH_VAR_SET(monitor.entry->parms,APP_PROBES,1);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-ENOTSUP && monitor.event_send_events==event_trace_before);
    NEIGH_VAR_SET(monitor.entry->parms,APP_PROBES,0);
    int64_t clamped;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&clamped)==1);
    CHECK(clamped==equality+INT64_C(10000000));
    pthread_t thread;
    CHECK(pthread_create(&thread,NULL,foreign,NULL)==0 && pthread_join(thread,NULL)==0);
    struct neighbour *held=NULL;
    CHECK(ker_neighbor_lookup(&table,ip(2),&held)==0);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-EBUSY);
    unsigned char snapshot[6]={99};
    CHECK(ker_neighbor_mac(&table,held,snapshot)==-ENOTSUP && snapshot[0]==99);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-EBUSY);
    CHECK(ker_neighbor_release(&table,held)==0);
    CHECK(pthread_create(&thread,NULL,foreign_event_send,NULL)==0 && pthread_join(thread,NULL)==0);
    stale(); CHECK(last_state==NUD_STALE);
    int64_t saved_now=runtime_clock.now_ns;
    runtime_clock.now_ns=INT64_MAX;
    unsigned long stale_updated=monitor.entry->updated, stale_used=monitor.entry->used;
    unsigned long stale_trace=monitor.event_send_events;
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-EOVERFLOW && state()==NUD_STALE);
    CHECK(!timer_pending(&monitor.entry->timer) && refcount_read(&monitor.entry->refcnt)==2 &&
          monitor.entry->updated==stale_updated && monitor.entry->used==stale_used &&
          monitor.event_send_events==stale_trace);
    runtime_clock.now_ns=saved_now;
    CHECK(ker_neighbor_monitor_event_send(&monitor)==0 && state()==NUD_DELAY);
    CHECK(monitor.event_send_events==stale_trace+1 && monitor.event_send_result==0 &&
          monitor.entry->used==stale_used && monitor.entry->updated>=stale_updated &&
          timer_pending(&monitor.entry->timer) && refcount_read(&monitor.entry->refcnt)==3);
    event_send_early(NUD_DELAY);
    resolved_output(NUD_DELAY, peer);
    CHECK(ker_neighbor_monitor_probe(&monitor)==-EALREADY);
    CHECK(ker_neighbor_monitor_event_send(&monitor)==0 && state()==NUD_DELAY);
    build_probes=true; built_probes=0;
    next(); CHECK(state()==NUD_PROBE && probes==1 && last_state==NUD_PROBE);
    resolved_output(NUD_PROBE, peer);
    event_send_early(NUD_PROBE);
    next(); next(); CHECK(probes==3 && state()==NUD_PROBE && built_probes==3);
    build_probes=false;
    struct sk_buff *outside = (void *)(uintptr_t)1;
    CHECK(ker_arp_probe_create(&monitor,saved_event_pointer,&outside)==-EPERM && outside==(void *)(uintptr_t)1);
    CHECK(pthread_create(&thread,NULL,foreign_probe,NULL)==0 && pthread_join(thread,NULL)==0);
    build_probes=true; next(); build_probes=false;
    CHECK(state()==NUD_FAILED && last_state==NUD_FAILED);
    stale_trace=monitor.event_send_events;
    CHECK(ker_neighbor_monitor_event_send(&monitor)==-ENOTSUP && monitor.event_send_events==stale_trace);
    CHECK(monitor.stats.res_failed==1 && notifications==3);
    CHECK(refcount_read(&monitor.entry->refcnt)==2 && !timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_confirm(&monitor)==-ENOTSUP);
    static const unsigned char old_destination[ETH_ALEN]={2,90,91,92,93,94};
    static const unsigned char payload_a[]={'a'}, payload_b[]={'b'};
    struct sk_buff *queued_a=NULL, *queued_b=NULL;
    CHECK(ker_tx_export_init(&output_tx,&context,8,SIZE_MAX,output_sink,&output_tx)==0);
    CHECK(NEIGH_VAR(monitor.entry->parms,QUEUE_LEN_BYTES)==10000);
    CHECK(NEIGH_VAR(monitor.entry->parms,MCAST_PROBES)>0);
    CHECK(ker_neighbor_monitor_resolution_enable(&monitor,&output_tx)==0);
    CHECK(ker_tx_export_cleanup(&output_tx)==-EBUSY);
    CHECK(ker_udp_ipv4_create_configured(&address,old_destination,ip(2),
        rte_cpu_to_be_16(1111),rte_cpu_to_be_16(2222),64,NULL,0,payload_a,sizeof(payload_a),&queued_a)==0);
    CHECK(ker_udp_ipv4_create_configured(&address,old_destination,ip(2),
        rte_cpu_to_be_16(1111),rte_cpu_to_be_16(2222),64,NULL,0,payload_b,sizeof(payload_b),&queued_b)==0);
    probes=(unsigned int)NEIGH_VAR(monitor.entry->parms,UCAST_PROBES); build_probes=true; built_probes=3;
    CHECK(ker_neighbor_monitor_resolve_output(&monitor,&queued_a)==0 && !queued_a);
    CHECK(state()==NUD_INCOMPLETE && monitor.entry->arp_queue.qlen==1 &&
        monitor.entry->arp_queue_len_bytes==monitor.entry->arp_queue.next->truesize &&
        monitor.unresolved_bytes==monitor.entry->arp_queue_len_bytes && output_tx.packets==1);
    CHECK(ker_neighbor_monitor_resolve_output(&monitor,&queued_b)==0 && !queued_b);
    CHECK(state()==NUD_INCOMPLETE && monitor.entry->arp_queue.qlen==2 && output_tx.packets==1);
    build_probes=false;
    CHECK(ker_neighbor_monitor_resolution_disable(&monitor)==-EBUSY);
    CHECK(ker_neighbor_monitor_update(&monitor,changed_peer,NEIGH_UPDATE_F_OVERRIDE)==0);
    CHECK(state()==NUD_REACHABLE && monitor.entry->arp_queue.qlen==0 &&
        monitor.entry->arp_queue_len_bytes==0 && monitor.unresolved_bytes==0 && output_tx.packets==3);
    CHECK(ker_tx_export_poll(&output_tx,1)==1 && output_packet);
    CHECK(output_packet->pkt_len==42 && rte_pktmbuf_mtod(output_packet,const unsigned char *)[0]==0xff);
    ker_packet_free(output_packet); output_packet=NULL;
    CHECK(ker_tx_export_poll(&output_tx,1)==1 && output_packet);
    CHECK(!memcmp(rte_pktmbuf_mtod(output_packet,const unsigned char *),changed_peer,ETH_ALEN));
    CHECK(rte_pktmbuf_mtod(output_packet,const unsigned char *)[ETH_HLEN+20+8]=='a');
    ker_packet_free(output_packet); output_packet=NULL;
    CHECK(ker_tx_export_poll(&output_tx,1)==1 && output_packet);
    CHECK(!memcmp(rte_pktmbuf_mtod(output_packet,const unsigned char *),changed_peer,ETH_ALEN));
    CHECK(rte_pktmbuf_mtod(output_packet,const unsigned char *)[ETH_HLEN+20+8]=='b');
    ker_packet_free(output_packet); output_packet=NULL;
    CHECK(ker_neighbor_monitor_resolution_disable(&monitor)==0);
    CHECK(ker_tx_export_cleanup(&output_tx)==0);
    while (state()==NUD_REACHABLE) next();
    CHECK(state()==NUD_STALE && ker_neighbor_monitor_probe(&monitor)==0 && state()==NUD_DELAY);
    probes=0; next(); CHECK(state()==NUD_PROBE);
    for (unsigned int i=0;i<8 && state()!=NUD_FAILED;++i) next();
    CHECK(state()==NUD_FAILED && !timer_pending(&monitor.entry->timer));
    CHECK(ker_tx_export_init(&output_tx,&context,32,SIZE_MAX,output_sink,&output_tx)==0);
    CHECK(ker_neighbor_monitor_resolution_enable(&monitor,&output_tx)==0);
    probes=(unsigned int)NEIGH_VAR(monitor.entry->parms,UCAST_PROBES);
    build_probes=true;
    unsigned long discards_before=monitor.stats.unres_discards;
    for (unsigned int i=0;i<12;++i) {
        unsigned char byte=(unsigned char)('0'+i);
        struct sk_buff *packet=NULL;
        int create_error=ker_udp_ipv4_create_configured(&address,old_destination,ip(2),
            rte_cpu_to_be_16(1111),rte_cpu_to_be_16(2222),64,NULL,0,&byte,1,&packet);
        CHECK(create_error==0);
        CHECK(ker_neighbor_monitor_resolve_output(&monitor,&packet)==0 && !packet);
    }
    build_probes=false;
    CHECK(monitor.entry->arp_queue.qlen>0 && monitor.entry->arp_queue_len_bytes<=monitor.resolution_queue_bytes &&
        monitor.unresolved_bytes==monitor.entry->arp_queue_len_bytes && monitor.stats.unres_discards>discards_before);
    unsigned char oldest=(unsigned char)monitor.entry->arp_queue.next->data[ETH_HLEN+20+8];
    unsigned int retained=monitor.entry->arp_queue.qlen;
    CHECK(oldest==(unsigned char)('0'+12-retained));
    struct sk_buff *held_packet=monitor.entry->arp_queue.next;
    struct sk_buff *forbidden_clone=(void *)(uintptr_t)1;
    CHECK(ker_skb_free(held_packet)==-EBUSY && ker_skb_clone(held_packet,&forbidden_clone)==-EBUSY &&
        forbidden_clone==(void *)(uintptr_t)1);
    struct sk_buff *cancelled=(void *)(uintptr_t)1;
    size_t bytes_before_cancel=monitor.entry->arp_queue_len_bytes;
    CHECK(ker_neighbor_monitor_resolution_cancel(&monitor,&cancelled)==1 && cancelled &&
        cancelled->data[ETH_HLEN+20+8]==oldest &&
        monitor.entry->arp_queue_len_bytes+cancelled->truesize==bytes_before_cancel &&
        state()==NUD_INCOMPLETE && timer_pending(&monitor.entry->timer));
    CHECK(ker_skb_free(cancelled)==0);
    inject_resolution_probe_failure=true; build_probes=true;
    ker_memory_fail_after(0); next(); ker_memory_fail_after(-1);
    inject_resolution_probe_failure=false; build_probes=false;
    CHECK(state()==NUD_INCOMPLETE && timer_pending(&monitor.entry->timer) &&
        monitor.resolution_error==-ENOMEM && monitor.entry->arp_queue.qlen>0);
    unsigned long failures_before_timeout=monitor.stats.res_failed;
    next();
    CHECK(state()==NUD_FAILED && monitor.entry->arp_queue.qlen==0 &&
        monitor.entry->arp_queue_len_bytes==0 && monitor.unresolved_bytes==0 &&
        monitor.stats.res_failed==failures_before_timeout+1);
    runtime_clock.now_ns=INT64_MAX-INT64_C(30000000);
    struct sk_buff *horizon_packet=NULL;
    CHECK(ker_udp_ipv4_create_configured(&address,old_destination,ip(2),
        rte_cpu_to_be_16(1111),rte_cpu_to_be_16(2222),64,NULL,0,payload_a,sizeof(payload_a),&horizon_packet)==0);
    probes=2;
    CHECK(ker_neighbor_monitor_resolve_output(&monitor,&horizon_packet)==0 && !horizon_packet &&
        state()==NUD_INCOMPLETE && monitor.entry->arp_queue.qlen==1);
    int64_t horizon_deadline;
    CHECK(ker_runtime_next_deadline(&runtime_clock,&horizon_deadline)==1);
    probes=(unsigned int)atomic_read(&monitor.entry->probes);
    CHECK(ker_runtime_poll(&runtime_clock,horizon_deadline,1)==1);
    CHECK(monitor.error==-EOVERFLOW && state()==NUD_INCOMPLETE && !timer_pending(&monitor.entry->timer));
    CHECK(ker_neighbor_monitor_resolution_cancel(&monitor,&cancelled)==1 && cancelled);
    CHECK(ker_skb_free(cancelled)==0 && monitor.unresolved_bytes==0);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    while (ker_tx_export_cancel(&output_tx,&cancelled)==1) CHECK(ker_skb_free(cancelled)==0);
    CHECK(ker_tx_export_cleanup(&output_tx)==0);
    runtime_clock.now_ns=0;
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
    resolved_output(NUD_REACHABLE, changed_peer);
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
    config.ucast_probes=config.mcast_reprobes=0; config.queue_bytes=1;
    CHECK(ker_neighbor_configure(&table,&config)==0);
    CHECK(ker_neighbor_add(&table,ip(2),peer)==0); ker_runtime_init(&runtime_clock);
    init(); stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0); next();
    CHECK(state()==NUD_FAILED && probes==0 && monitor.stats.res_failed==1);
    struct ker_tx_export oversize_tx={0};
    CHECK(ker_tx_export_init(&oversize_tx,&context,4,SIZE_MAX,output_sink,&oversize_tx)==0);
    CHECK(ker_neighbor_monitor_resolution_enable(&monitor,&oversize_tx)==0);
    struct sk_buff *oversize_packet=NULL;
    CHECK(ker_udp_ipv4_create_configured(&address,old_destination,ip(2),
        rte_cpu_to_be_16(1111),rte_cpu_to_be_16(2222),64,NULL,0,payload_a,sizeof(payload_a),&oversize_packet)==0);
    struct sk_buff *oversize_identity=oversize_packet;
    unsigned int oversize_charge=oversize_packet->truesize;
    unsigned int oversize_len=oversize_packet->len;
    unsigned char oversize_frame[128];
    CHECK(oversize_len<=sizeof(oversize_frame));
    memcpy(oversize_frame,oversize_packet->data,oversize_len);
    CHECK(oversize_charge>monitor.resolution_queue_bytes);
    CHECK(ker_neighbor_monitor_resolve_output(&monitor,&oversize_packet)==-ENOTSUP &&
        oversize_packet==oversize_identity && oversize_packet->truesize==oversize_charge &&
        oversize_packet->len==oversize_len && !memcmp(oversize_packet->data,oversize_frame,oversize_len) &&
        state()==NUD_FAILED && monitor.entry->arp_queue.qlen==0 &&
        monitor.entry->arp_queue_len_bytes==0 && monitor.unresolved_bytes==0);
    CHECK(ker_skb_free(oversize_packet)==0);
    CHECK(ker_neighbor_monitor_resolution_disable(&monitor)==0);
    CHECK(ker_tx_export_cleanup(&oversize_tx)==0);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_runtime_cleanup(&runtime_clock)==0 && ker_neighbor_remove(&table,ip(2))==0);
    CHECK(ker_neighbor_table_cleanup(&table)==0 && ker_ipv4_address_cleanup(&address)==0);
    CHECK(ker_eth_device_cleanup(&device)==0 && ker_skb_context_cleanup(&context)==0);
    CHECK(ker_packet_pool_cleanup(&pool)==0 && ker_memory_live_allocations()==0);
    CHECK(ker_memory_shutdown()==0 && rte_eal_cleanup()==0);
    puts("native neighbor timers: reachability, retries, feedback, rollover and lifetime passed");
}
