#include "check.h"
#include "eal.h"
#include "runtime/arp-receive.h"
#include "runtime/arp.h"
#include "runtime/neighbor-timer.h"
#include "runtime/worker.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/memory.h"
#include <pthread.h>
#include <errno.h>
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_receive_runtime runtime;
static struct ker_arp_receiver receiver;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor monitor;
static struct ker_worker worker;
static struct ker_ipv4_address alternate_address;
static struct ker_eth_device alternate_device;
static struct ker_protocol_handler observer;
static const unsigned char mac[6] = {2, 1, 2, 3, 4, 5}, peer[6] = {2, 6, 7, 8, 9, 10};
static __be32 local, remote;
static struct sk_buff *held, *reply;
static struct sk_buff *worker_packet;
static int worker_dispatch_status;
static unsigned int messages;
static unsigned int feedback_mode, feedback_notifications;
static int feedback_result;
static __be32 monitored_ip;
static const struct ker_arp_message *callback_message;
static const unsigned char learned_peer[6]={2,10,9,8,7,6};
static int callback_status = NET_RX_SUCCESS;
static bool make_reply;
static struct ker_arp_message last;
static int message(const struct ker_arp_message *m, void *arg)
{
    CHECK(arg == &receiver);
    CHECK(ker_arp_receiver_unregister(&receiver) == -EBUSY);
    CHECK(ker_ipv4_address_cleanup(&address) == -EBUSY);
    last = *m; messages++;
    if (feedback_mode) {
        if(feedback_mode==4)CHECK(!memcmp(m->sender_mac,learned_peer,ETH_ALEN));
        callback_message=m;
        struct ker_worker_result nested={0};
        CHECK(worker.polling && !worker.timers.polling);
        CHECK(ker_worker_poll(&worker,worker.timers.now_ns,&nested)==-EBUSY);
        struct ker_arp_message copy=*m;
        struct ker_arp_receiver other={0};
        CHECK(ker_arp_neighbor_feedback(&receiver,&monitor,&copy,NEIGH_UPDATE_F_OVERRIDE)==-EPERM);
        CHECK(ker_arp_neighbor_feedback(&other,&monitor,m,NEIGH_UPDATE_F_OVERRIDE)==-EPERM);
        if(feedback_mode==8) {
            struct ker_ipv4_address *saved=monitor.table->address;
            alternate_address=*saved; alternate_device=*saved->device; alternate_address.device=&alternate_device;
            monitor.table->address=&alternate_address;
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,NEIGH_UPDATE_F_OVERRIDE);
            monitor.table->address=saved;
        } else if(feedback_mode==9) {
            struct ker_arp_message *mutable=(struct ker_arp_message *)(uintptr_t)m;
            unsigned char saved[ETH_ALEN]; memcpy(saved,mutable->sender_mac,ETH_ALEN);
            mutable->sender_mac[0]^=2;
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,NEIGH_UPDATE_F_OVERRIDE);
            memcpy(mutable->sender_mac,saved,ETH_ALEN);
        } else if(feedback_mode==7) {
            struct neighbour *hold=NULL;
            CHECK(ker_neighbor_lookup(&neighbors,monitored_ip,&hold)==0);
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,NEIGH_UPDATE_F_OVERRIDE);
            CHECK(ker_neighbor_release(&neighbors,hold)==0);
        } else if(feedback_mode==10) {
            int64_t saved_now=worker.timers.now_ns;
            worker.timers.now_ns=INT64_MAX-100;
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,NEIGH_UPDATE_F_OVERRIDE);
            worker.timers.now_ns=saved_now;
        } else if(feedback_mode==11) {
            struct ker_arp_message *mutable=(struct ker_arp_message *)(uintptr_t)m;
            unsigned char saved[ETH_ALEN]; memcpy(saved,mutable->sender_mac,ETH_ALEN);
            memset(mutable->sender_mac,0,ETH_ALEN);
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,NEIGH_UPDATE_F_OVERRIDE);
            memcpy(mutable->sender_mac,saved,ETH_ALEN);
        } else {
            feedback_result=ker_arp_neighbor_feedback(&receiver,&monitor,m,
                feedback_mode==3?NEIGH_UPDATE_F_OVERRIDE:feedback_mode==4?0:
                feedback_mode==5?0x80000000U:NEIGH_UPDATE_F_OVERRIDE);
        }
        callback_message=NULL;
    }
    if (make_reply) {
        CHECK(m->target_local && m->operation == ARPOP_REQUEST && !reply);
        CHECK(ker_arp_create(&device, ARPOP_REPLY, m->target_ip, m->sender_ip,
            m->sender_mac, NULL, m->sender_mac, &reply) == 0);
    }
    return callback_status;
}
static void monitor_probe(const struct ker_neighbor_event *e,void *arg)
{ (void)e;(void)arg; }
static void monitor_notify(const struct ker_neighbor_event *e,void *arg)
{
    (void)arg; CHECK(e->ip==monitored_ip); feedback_notifications++;
    if(callback_message)
        CHECK(ker_arp_neighbor_feedback(&receiver,&monitor,callback_message,NEIGH_UPDATE_F_OVERRIDE)==-EBUSY);
}
static unsigned int monitor_state(void)
{
    struct ker_neighbor_event e; CHECK(ker_neighbor_monitor_snapshot(&monitor,&e)==0); return e.state;
}
static int worker_rx(void *arg,unsigned int budget)
{
    (void)arg; CHECK(budget>0);
    if(!worker_packet)return 0;
    struct ker_receive_result result={0};
    CHECK(ker_receive_dispatch(&runtime,&device,&worker_packet,&result)==0 && !worker_packet);
    worker_dispatch_status=result.status;
    return 1;
}
static void worker_feedback(struct sk_buff *skb,unsigned int mode,int expected)
{
    struct ker_worker_result result;
    struct ker_neighbor_event before={0}; unsigned long confirmed=0,updated=0;
    unsigned int refs=0,notifications=feedback_notifications; int64_t deadline=0;
    bool pending=monitor.entry && timer_pending(&monitor.entry->timer);
    if(expected) {
        CHECK(ker_neighbor_monitor_snapshot(&monitor,&before)==0);
        confirmed=monitor.entry->confirmed; updated=monitor.entry->updated;
        refs=(unsigned int)refcount_read(&monitor.entry->refcnt);
        if(pending)CHECK(ker_runtime_next_deadline(&worker.timers,&deadline)==1);
    }
    worker_packet=skb; feedback_mode=mode; feedback_result=1234;
    CHECK(ker_worker_poll(&worker,worker.timers.now_ns,&result)==0 && result.rx==1);
    feedback_mode=0;
    CHECK(feedback_result==expected && context.live==0);
    CHECK(worker_dispatch_status==NET_RX_SUCCESS);
    if(expected) {
        struct ker_neighbor_event after;
        CHECK(ker_neighbor_monitor_snapshot(&monitor,&after)==0);
        CHECK(after.state==before.state && after.probes==before.probes && after.ip==before.ip &&
            !memcmp(after.mac,before.mac,ETH_ALEN) && monitor.entry->confirmed==confirmed &&
            monitor.entry->updated==updated && refcount_read(&monitor.entry->refcnt)==(int)refs &&
            timer_pending(&monitor.entry->timer)==pending && feedback_notifications==notifications);
        if(pending) { int64_t after_deadline; CHECK(ker_runtime_next_deadline(&worker.timers,&after_deadline)==1 && after_deadline==deadline); }
    }
}
static void worker_next(void)
{
    int64_t deadline; struct ker_worker_result result;
    CHECK(ker_runtime_next_deadline(&worker.timers,&deadline)==1);
    CHECK(ker_worker_poll(&worker,deadline,&result)==0 && result.rx==0);
}
static void worker_stale(void)
{
    for(unsigned int i=0;monitor_state()==NUD_REACHABLE && i<4;++i)worker_next();
    CHECK(monitor_state()==NUD_STALE);
}
static void *foreign_feedback(void *arg)
{
    (void)arg;
    CHECK(ker_arp_neighbor_feedback(&receiver,&monitor,&last,NEIGH_UPDATE_F_OVERRIDE)==-EXDEV);
    return NULL;
}
static struct sk_buff *packet(unsigned int payload);
static struct sk_buff *arp_reply(__be32 sender_ip,__be32 target_ip,const unsigned char target_mac[6],
    unsigned int operation)
{
    struct sk_buff *skb=packet(28);
    memcpy(eth_hdr(skb)->h_dest,mac,ETH_ALEN);
    skb->pkt_type=PACKET_HOST;
    skb->data[7]=(unsigned char)operation;
    memcpy(skb->data+14,&sender_ip,4); memcpy(skb->data+18,target_mac,6);
    memcpy(skb->data+24,&target_ip,4);
    return skb;
}
static int observe(struct sk_buff *skb, struct ker_protocol_handler *h, struct net_device *orig, void *arg)
{
    (void)h; (void)arg;
    CHECK(orig == device.native && !held);
    held = skb; /* Retain the callback-owned reference, do not add another. */
    return NET_RX_SUCCESS;
}
static struct sk_buff *packet(unsigned int payload)
{
    struct rte_mbuf *mbuf = ker_packet_alloc(&pool); CHECK(mbuf);
    unsigned char *p = (unsigned char *)rte_pktmbuf_append(mbuf, (uint16_t)(ETH_HLEN + payload)); CHECK(p);
    unsigned char bytes[42] = {0};
    memset(bytes, 0xff, 6); memcpy(bytes + 6, peer, 6); bytes[12] = 8; bytes[13] = 6;
    bytes[15] = 1; bytes[16] = 8; bytes[18] = 6; bytes[19] = 4; bytes[21] = ARPOP_REQUEST;
    memcpy(bytes + 22, peer, 6); memcpy(bytes + 28, &remote, 4); memcpy(bytes + 38, &local, 4);
    memset(p, 0xcc, ETH_HLEN + payload);
    memcpy(p, bytes, ETH_HLEN + (payload < 28 ? payload : 28));
    struct sk_buff *skb = NULL; CHECK(ker_eth_receive(&device, mbuf, &skb) == 0);
    memset(skb->cb, 0xa5, sizeof(skb->cb));
    return skb;
}
static int dispatch(struct sk_buff *skb, int error)
{
    struct ker_receive_result result = {0};
    CHECK(ker_receive_dispatch(&runtime, &device, &skb, &result) == error && !skb);
    CHECK(result.handlers == (observer.registered ? 2U : 1U));
    return result.status;
}
static void *wrong_worker(void *arg)
{
    (void)arg;
    struct ker_arp_receiver other = {0};
    CHECK(ker_arp_receiver_register(&other, &runtime, &address, message, &receiver) == -EXDEV);
    CHECK(ker_arp_receiver_unregister(&receiver) == -EXDEV);
    return NULL;
}
int main(void)
{
    ker_test_eal_init(); local = rte_cpu_to_be_32(0xc0000201); remote = rte_cpu_to_be_32(0xc0000202);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "arp_rx_packets", 31, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "arp_rx_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "eth0", 1, mac) == 0);
    CHECK(ker_arp_device_setup(&device) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local, 24) == 0);
    monitored_ip=remote;
    CHECK(ker_neighbor_table_init(&neighbors,&address,"arp_feedback",4,2)==0);
    struct ker_neighbor_config ncfg={.retrans_ticks=20,.reachable_ticks=100,.delay_ticks=30,
        .ucast_probes=2,.mcast_reprobes=1};
    CHECK(ker_neighbor_configure(&neighbors,&ncfg)==0);
    CHECK(ker_neighbor_add(&neighbors,remote,peer)==0);
    CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, NULL, NULL) == -EINVAL);
    runtime.live = KER_RECEIVE_MAX_HANDLERS;
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == -ENOSPC);
    CHECK(refcount_read(&address.native->refcnt) == 2 && !receiver.handler.registered);
    runtime.live = 0;
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == 0);
    CHECK(ker_arp_receiver_register(&receiver, &runtime, &address, message, &receiver) == -EALREADY);
    CHECK(refcount_read(&address.native->refcnt) == 3 && ker_ipv4_address_cleanup(&address) == -EBUSY);
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, wrong_worker, NULL) && !pthread_join(thread, NULL));
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && messages == 1);
    CHECK(last.sender_ip == remote && last.target_ip == local && last.target_local &&
        !memcmp(last.sender_mac, peer, 6) && last.operation == ARPOP_REQUEST);
    CHECK(dispatch(packet(46), 0) == NET_RX_SUCCESS && messages == 2); /* Ethernet padding */
    for (unsigned int len = 0; len < 28; ++len) CHECK(dispatch(packet(len), 0) == NET_RX_DROP);
    CHECK(messages == 2 && !context.live);
    /* Structural gate and private decoder reject each malformed field. */
    for (unsigned int field = 0; field < 10; ++field) {
        struct sk_buff *skb = packet(28); unsigned char *p = skb->data;
        switch (field) {
        case 0: p[4] = 5; break; /* hardware address length */
        case 1: p[5] = 16; break; /* protocol address length */
        case 2: p[1] = 99; break; /* hardware type */
        case 3: p[2] = 0x86; p[3] = 0xdd; break;
        case 4: p[7] = 99; break;
        case 5: p[8] = 1; break; /* multicast sender MAC */
        case 6: memset(p + 8, 0, 6); break;
        case 7: p[24] = 127; break; /* loopback target */
        case 8: p[14] = 224; break; /* multicast sender */
        case 9: p[7] = ARPOP_REPLY; memset(p + 14, 0, 4); break;
        }
        CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 2);
    }
    struct sk_buff *skb = packet(28); skb->data[1] = ARPHRD_IEEE802;
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 3);
    skb = packet(28); memset(skb->data + 14, 0, 4);
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 4 && !last.sender_ip); /* DAD */
    skb = packet(28); memcpy(skb->data + 24, &remote, 4);
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 5 && !last.target_local);
    skb = packet(28); skb->data[7] = ARPOP_REPLY;
    CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 6 && last.operation == ARPOP_REPLY);
    for (unsigned int mode = 0; mode < 3; ++mode) {
        skb = packet(28);
        if (!mode) device.native->flags |= ker_linux_IFF_NOARP;
        else skb->pkt_type = mode == 1 ? PACKET_OTHERHOST : PACKET_LOOPBACK;
        CHECK(dispatch(skb, 0) == NET_RX_SUCCESS && messages == 6);
        device.native->flags &= ~ker_linux_IFF_NOARP;
    }
    /* Original share_check clones only the descriptor, preserving an earlier
     * observer's scratch/data and ownership on both success and OOM. */
    CHECK(ker_protocol_register(&runtime, &observer, NULL, rte_cpu_to_be_16(ETH_P_ARP), observe, NULL) == 0);
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && messages == 7 && held && context.live == 1);
    for (unsigned int i = 0; i < sizeof(held->cb); ++i) CHECK((unsigned char)held->cb[i] == 0xa5);
    CHECK(refcount_read(&held->users) == 1 && ker_skb_free(held) == 0); held = NULL;
    skb = packet(28); ker_memory_fail_after(0);
    CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 7 && held && refcount_read(&held->users) == 1);
    ker_memory_fail_after(-1); CHECK(ker_skb_free(held) == 0); held = NULL;
    skb = packet(28);
    struct sk_buff *occupied[6];
    for (unsigned int i = 0; i < 6; ++i) CHECK(ker_skb_alloc(&context, 0, 0, &occupied[i]) == 0);
    CHECK(dispatch(skb, 0) == NET_RX_DROP && messages == 7 && held && context.live == 7);
    CHECK(refcount_read(&held->users) == 1 && ker_skb_free(held) == 0); held = NULL;
    for (unsigned int i = 0; i < 6; ++i) CHECK(ker_skb_free(occupied[i]) == 0);
    CHECK(ker_protocol_unregister(&observer) == 0);
    callback_status = NET_RX_DROP;
    CHECK(dispatch(packet(28), 0) == NET_RX_DROP && !context.live);
    callback_status = -EIO;
    CHECK(dispatch(packet(28), -EPROTO) == NET_RX_DROP && !context.live);
    callback_status = NET_RX_SUCCESS; make_reply = true;
    CHECK(dispatch(packet(28), 0) == NET_RX_SUCCESS && reply && context.live == 1);
    CHECK(!memcmp(reply->data, peer, 6) && !memcmp(reply->data + 6, mac, 6));
    CHECK(arp_hdr(reply)->ar_op == rte_cpu_to_be_16(ARPOP_REPLY));
    CHECK(!memcmp(reply->data + 28, &local, 4) && !memcmp(reply->data + 38, &remote, 4));
    CHECK(ker_skb_free(reply) == 0); reply = NULL;
    make_reply=false;
    /* Native reply feedback is only admitted from an exact live host-reply
     * callback and updates an existing matching monitored entry. */
    struct ker_worker_config wcfg={.timer_budget=1,.rx_budget=1};
    struct ker_worker_ops wops={.rx=worker_rx};
    CHECK(ker_worker_init(&worker,&pool,&wcfg,&wops)==0);
    CHECK(ker_neighbor_monitor_init(&monitor,&neighbors,&worker.timers,remote,
        monitor_probe,monitor_notify,NULL)==0);
    worker_stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0 && monitor_state()==NUD_DELAY);
    struct sk_buff *bad_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(eth_hdr(bad_reply)->h_dest,(unsigned char[ETH_ALEN]){0xff,0xff,0xff,0xff,0xff,0xff},ETH_ALEN);
    bad_reply->pkt_type=PACKET_BROADCAST;
    worker_feedback(bad_reply,3,-ENOTSUP);
    bad_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(eth_hdr(bad_reply)->h_dest,(unsigned char[ETH_ALEN]){1,0,0,0,0,1},ETH_ALEN);
    bad_reply->pkt_type=PACKET_MULTICAST;
    worker_feedback(bad_reply,3,-ENOTSUP);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REQUEST),1,-ENOTSUP);
    unsigned int before_messages=messages;
    worker_packet=arp_reply(0,local,mac,ARPOP_REPLY); feedback_mode=3; feedback_result=1234;
    struct ker_worker_result worker_result;
    CHECK(ker_worker_poll(&worker,worker.timers.now_ns,&worker_result)==0 && worker_result.rx==1);
    feedback_mode=0;
    CHECK(worker_dispatch_status==NET_RX_DROP && feedback_result==1234 && messages==before_messages && context.live==0);
    worker_feedback(arp_reply(remote,remote,mac,ARPOP_REPLY),2,-ENOTSUP);
    worker_feedback(arp_reply(remote,local,peer,ARPOP_REPLY),2,-ENOTSUP);
    worker_feedback(arp_reply(rte_cpu_to_be_32(0xc0000203),local,mac,ARPOP_REPLY),6,-ENOENT);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),5,-ENOTSUP);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),8,-EXDEV);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),9,-ESTALE);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),7,-EBUSY);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),10,-EOVERFLOW);
    worker_feedback(arp_reply(remote,local,mac,ARPOP_REPLY),11,-ESTALE);
    pthread_t feedback_thread;
    CHECK(pthread_create(&feedback_thread,NULL,foreign_feedback,NULL)==0 && pthread_join(feedback_thread,NULL)==0);
    unsigned long old_confirmed=monitor.entry->confirmed,old_updated=monitor.entry->updated;
    int64_t old_deadline; CHECK(ker_runtime_next_deadline(&worker.timers,&old_deadline)==1);
    unsigned int old_notifications=feedback_notifications;
    struct sk_buff *learning_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(learning_reply->data+8,learned_peer,ETH_ALEN);
    worker_feedback(learning_reply,4,0);
    CHECK(monitor_state()==NUD_DELAY && memcmp(monitor.entry->ha,peer,ETH_ALEN)==0 &&
        monitor.entry->confirmed>old_confirmed && monitor.entry->updated==old_updated &&
        feedback_notifications==old_notifications && refcount_read(&monitor.entry->refcnt)==3 && timer_pending(&monitor.entry->timer));
    int64_t same_deadline; CHECK(ker_runtime_next_deadline(&worker.timers,&same_deadline)==1 && same_deadline==old_deadline);
    learning_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(learning_reply->data+8,learned_peer,ETH_ALEN);
    worker_feedback(learning_reply,3,0);
    CHECK(monitor_state()==NUD_REACHABLE && memcmp(monitor.entry->ha,learned_peer,ETH_ALEN)==0 &&
        refcount_read(&monitor.entry->refcnt)==3 && timer_pending(&monitor.entry->timer) && feedback_notifications==old_notifications+1);
    CHECK(ker_arp_neighbor_feedback(&receiver,&monitor,&last,NEIGH_UPDATE_F_OVERRIDE)==-EPERM);
    worker_feedback(arp_reply(remote,local,learned_peer,ARPOP_REPLY),3,-ENOTSUP);
    worker_stale();
    worker_feedback(arp_reply(remote,local,learned_peer,ARPOP_REPLY),3,-ENOTSUP);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_neighbor_monitor_init(&monitor,&neighbors,&worker.timers,remote,
        monitor_probe,monitor_notify,NULL)==0);
    worker_stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0);
    /* A same-MAC reply is still a valid native transition from PROBE. */
    worker_next(); CHECK(monitor_state()==NUD_PROBE);
    unsigned int same_mac_notifications=feedback_notifications;
    learning_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(learning_reply->data+8,peer,ETH_ALEN);
    worker_feedback(learning_reply,3,0);
    CHECK(monitor_state()==NUD_REACHABLE && !memcmp(monitor.entry->ha,peer,ETH_ALEN) &&
        feedback_notifications==same_mac_notifications+1);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    CHECK(ker_neighbor_monitor_init(&monitor,&neighbors,&worker.timers,remote,
        monitor_probe,monitor_notify,NULL)==0);
    worker_stale(); CHECK(ker_neighbor_monitor_probe(&monitor)==0);
    worker_next(); CHECK(monitor_state()==NUD_PROBE);
    unsigned int probe_notifications=feedback_notifications;
    learning_reply=arp_reply(remote,local,mac,ARPOP_REPLY);
    memcpy(learning_reply->data+8,learned_peer,ETH_ALEN);
    worker_feedback(learning_reply,3,0);
    CHECK(monitor_state()==NUD_REACHABLE && memcmp(monitor.entry->ha,learned_peer,ETH_ALEN)==0 &&
        feedback_notifications==probe_notifications+1);
    CHECK(ker_neighbor_monitor_cleanup(&monitor)==0);
    struct neighbour *learned=NULL; unsigned char restored[ETH_ALEN];
    CHECK(ker_neighbor_lookup(&neighbors,remote,&learned)==0);
    CHECK(ker_neighbor_mac(&neighbors,learned,restored)==0 && !memcmp(restored,peer,ETH_ALEN));
    CHECK(ker_neighbor_release(&neighbors,learned)==0);
    CHECK(ker_neighbor_remove(&neighbors,remote)==0);
    CHECK(ker_worker_cleanup(&worker)==0);
    CHECK(ker_arp_receiver_unregister(&receiver) == 0 && refcount_read(&address.native->refcnt) == 2);
    CHECK(ker_neighbor_table_cleanup(&neighbors)==0 && refcount_read(&address.native->refcnt)==1);
    CHECK(ker_receive_runtime_cleanup(&runtime) == 0 && ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0 && ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == 31 && ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("ARP receive: original gate, ownership, malformed frames, DAD, callback and reply construction passed");
    return 0;
}
