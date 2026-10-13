/* Distinct-lcore F-Stack-inspired segmented ingress through Ker flow steering. */
#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/flow-ring.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include "runtime/transport-receive.h"
#include <errno.h>
#include <pthread.h>
#include <rte_lcore.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define TRAFFIC 192U
#define DROP_ID TRAFFIC
#define RECOVER_ID (TRAFFIC + 1U)
#define TOTAL (TRAFFIC + 2U)
#define FRAME_CAP 160U
#define POOL_COUNT 511U
#define DOMAIN 0x4b455246U

struct record { unsigned len, ihl, proto; uint8_t bytes[FRAME_CAP]; };
struct fixture {
    struct record records[TOTAL];
    struct ker_flow_fabric fabric;
    struct ker_packet_pool ingress_pool;
    struct ker_skb_context ingress_skb;
    struct ker_eth_device ingress_device;
    struct ker_worker ingress_worker;
    struct ker_flow_context ingress_flow;
    struct ker_packet_pool owner_pool;
    struct ker_skb_context owner_skb;
    struct ker_eth_device owner_device;
    struct ker_receive_runtime runtime;
    struct ker_transport_receiver receiver;
    struct ker_worker owner_worker;
    struct ker_flow_context owner_flow;
    struct ker_tx_ring ring;
    struct ker_flow_ring adapter;
    atomic_bool owner_ready, release_owner, producer_done, owner_stop;
    atomic_bool pool_ready, release_drop, drop_seen, release_recovery;
    atomic_bool owner_cleaned, allow_owner_memory_shutdown;
    atomic_uint received, delivered, checksum_drops, overlap;
    atomic_uint main_cpu, owner_cpu, main_lcore, owner_lcore;
    atomic_bool producer_active;
    cpu_set_t allowed;
    int owner_cpu_target;
    pthread_t owner_thread;
};
static struct fixture f;
static const uint8_t mac[6] = {2,0,0,0,0,1};
static void ingress_retry(void);
static int64_t ingress_now;

static void put16(uint8_t *p, unsigned v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static uint16_t checksum(const uint8_t *p, unsigned n, uint32_t sum)
{
    for (unsigned i=0;i<n;i+=2) sum += ((unsigned)p[i]<<8) | (i+1<n?p[i+1]:0);
    while (sum>>16) sum=(sum&65535)+(sum>>16);
    return (uint16_t)~sum;
}
static void make_record(unsigned id)
{
    struct record *r=&f.records[id];
    r->proto=(id&1)?6:17;
    unsigned ipopt=(id<TRAFFIC)?((id%11)*4):0;
    unsigned tcpopt=(r->proto==6)?((id%11)*4):0;
    if (ipopt>40) ipopt=40; if (tcpopt>40) tcpopt=40;
    r->ihl=20+ipopt;
    unsigned l4=(r->proto==6?20+tcpopt:8)+8;
    r->len=14+r->ihl+l4;
    uint8_t *p=r->bytes, *ip=p+14, *t=ip+r->ihl;
    memset(p,0,r->len); memcpy(p,mac,6); memcpy(p+6,mac,6); put16(p+12,0x0800);
    ip[0]=(uint8_t)(0x40+r->ihl/4); put16(ip+2,r->ihl+l4); ip[8]=64; ip[9]=(uint8_t)r->proto;
    ip[1]=(uint8_t)(id*13+9); put16(ip+4,0x2000+id);
    const uint8_t ips[8]={192,0,2,10,198,51,100,20}; memcpy(ip+12,ips,8);
    for(unsigned j=0;j<ipopt;j++) ip[20+j]=(j+1==ipopt)?0:1;
    put16(ip+10,checksum(ip,r->ihl,0));
    put16(t,40000); put16(t+2,8443);
    if(r->proto==6) { t[12]=(uint8_t)((20+tcpopt)/4<<4); t[13]=0x18; for(unsigned j=0;j<tcpopt;j++)t[20+j]=1; }
    else put16(t+4,l4);
    for(unsigned j=0;j<8;j++) t[l4-8+j]=(uint8_t)((id>>(j%4*8))^(j*29+0x5a));
    uint8_t pseudo[12]={192,0,2,10,198,51,100,20,0,(uint8_t)r->proto,(uint8_t)(l4>>8),(uint8_t)l4};
    uint16_t cs=checksum(t,l4,(uint16_t)~checksum(pseudo,12,0));
    if(r->proto==17&&!cs)cs=65535;
    put16(t+(r->proto==6?16:6),cs);
    if(id==37) ip[10]^=1; /* Predictable IPv4 checksum drop. */
    if(id==81) t[l4-1]^=1; /* Predictable transport checksum drop. */
}

static uint64_t deadline(void)
{ struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec+30000000000ULL; }
static void alive(uint64_t end)
{ struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0); CHECK((uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec<end); }
static void wait_bool(atomic_bool *v,uint64_t end)
{ while(!atomic_load_explicit(v,memory_order_acquire)){alive(end);sched_yield();} }
static void set_cpu(int cpu)
{ cpu_set_t one; CPU_ZERO(&one); CPU_SET(cpu,&one); CHECK(pthread_setaffinity_np(pthread_self(),sizeof(one),&one)==0); }

static int message(const struct ker_transport_message *m, void *arg)
{
    CHECK(arg==&f); unsigned id=atomic_load_explicit(&f.received,memory_order_acquire);
    CHECK(id<TOTAL); const struct record *r=&f.records[id];
    CHECK((unsigned)sched_getcpu()==atomic_load_explicit(&f.owner_cpu,memory_order_relaxed));
    CHECK(rte_lcore_id()==atomic_load_explicit(&f.owner_lcore,memory_order_relaxed));
    CHECK(m->protocol==(r->proto==6?KER_TRANSPORT_TCP:KER_TRANSPORT_UDP));
    CHECK(m->ipv4.header_length==r->ihl && !memcmp(m->ipv4.header+20,r->bytes+34,r->ihl-20));
    const uint8_t *payload; size_t n;
    if(r->proto==6){CHECK(m->packet.tcp.source_port==rte_cpu_to_be_16(40000)); CHECK(m->packet.tcp.destination_port==rte_cpu_to_be_16(8443)); payload=m->packet.tcp.payload;n=m->packet.tcp.payload_length;}
    else {CHECK(m->packet.udp.source_port==rte_cpu_to_be_16(40000)); CHECK(m->packet.udp.destination_port==rte_cpu_to_be_16(8443));payload=m->packet.udp.payload;n=m->packet.udp.payload_length;}
    CHECK(n==8 && !memcmp(payload,r->bytes+r->len-8,8));
    atomic_fetch_add_explicit(&f.delivered,1,memory_order_relaxed); return NET_RX_SUCCESS;
}

static void owner_receive(void *arg,const struct ker_flow_key *key,struct rte_mbuf *packet)
{
    CHECK(arg==&f && rte_lcore_id()==atomic_load_explicit(&f.owner_lcore,memory_order_relaxed));
    CHECK((unsigned)sched_getcpu()==atomic_load_explicit(&f.owner_cpu,memory_order_relaxed));
    CHECK(f.owner_worker.polling && f.owner_flow.delivering);
    if(atomic_load_explicit(&f.producer_active,memory_order_acquire)) atomic_fetch_add(&f.overlap,1);
    unsigned id=atomic_load_explicit(&f.received,memory_order_relaxed); CHECK(id<TOTAL);
    const struct record *r=&f.records[id];
    CHECK(key->domain==DOMAIN && key->family==4 && key->protocol==r->proto && key->local_port==8443 && key->remote_port==40000);
    CHECK(!memcmp(key->local+12,(uint8_t[]){198,51,100,20},4) && !memcmp(key->remote+12,(uint8_t[]){192,0,2,10},4));
    CHECK(packet->pkt_len==r->len && packet->nb_segs==7);
    uint8_t bytes[FRAME_CAP]; const void *p=rte_pktmbuf_read(packet,0,packet->pkt_len,bytes);
    CHECK(p && !memcmp(p,r->bytes,r->len));
    struct sk_buff *skb=NULL; int rc=ker_eth_receive_copy_chain(&f.owner_device,packet,256,&skb); ker_packet_free(packet);
    if(id==DROP_ID){CHECK(rc==-ENOMEM&&!skb);atomic_store_explicit(&f.received,id+1,memory_order_release);atomic_store_explicit(&f.drop_seen,true,memory_order_release);return;}
    CHECK(rc==0 && skb);
    unsigned delivered_before=atomic_load_explicit(&f.delivered,memory_order_relaxed);
    struct ker_receive_result result={0}; CHECK(ker_receive_dispatch(&f.runtime,&f.owner_device,&skb,&result)==0);
    CHECK(!skb && result.handlers==1);
    if(id==37||id==81){CHECK(result.status==NET_RX_DROP && f.receiver.validation_error==-EBADMSG);CHECK(atomic_load(&f.delivered)==delivered_before);atomic_fetch_add(&f.checksum_drops,1);}
    else {CHECK(result.status==NET_RX_SUCCESS && f.receiver.validation_error==0);CHECK(atomic_load(&f.delivered)==delivered_before+1);}
    atomic_store_explicit(&f.received,id+1,memory_order_release);
    if(id==DROP_ID) atomic_store_explicit(&f.drop_seen,true,memory_order_release);
}

static struct rte_mbuf *make_chain(unsigned id)
{
    const struct record *r=&f.records[id];
    unsigned lens[7]={13,2,8,4,r->ihl-12,4,r->len-(14+r->ihl+5)};
    struct rte_mbuf *head=NULL; unsigned off=0;
    for(unsigned i=0;i<7;i++){
        struct rte_mbuf *m=ker_packet_alloc(&f.ingress_pool); CHECK(m);
        void *dst=rte_pktmbuf_append(m,(uint16_t)lens[i]); CHECK(dst);
        memcpy(dst,r->bytes+off,lens[i]); off+=lens[i];
        if(!head)head=m; else CHECK(rte_pktmbuf_chain(head,m)==0);
    }
    CHECK(off==r->len&&head->nb_segs==7); return head;
}
static void produce(unsigned id, bool drain)
{
    uint64_t end=deadline(); struct rte_mbuf *m=make_chain(id); int enqueued=ker_tx_ring_sink(m,&f.ring);
    while(enqueued==-EAGAIN){alive(end);ingress_retry();enqueued=ker_tx_ring_sink(m,&f.ring);}
    CHECK(enqueued==0);
    struct ker_worker_result result={0};
    if(drain){int rc=ker_worker_poll(&f.ingress_worker,ingress_now++,&result); CHECK(rc>=0||rc==-ENOBUFS);}
}
static void ingress_retry(void)
{
    struct ker_worker_result result={0}; int rc=ker_worker_poll(&f.ingress_worker,ingress_now++,&result);
    CHECK(rc>=0 || rc==-ENOBUFS);
}

static void *owner_main(void *unused)
{
    (void)unused; set_cpu(f.owner_cpu_target); CHECK(rte_thread_register()==0);
    CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    unsigned cpu=sched_getcpu(); CHECK(cpu==(unsigned)f.owner_cpu_target);
    atomic_store(&f.owner_cpu,cpu); atomic_store(&f.owner_lcore,rte_lcore_id());
    static const uint8_t owner_mac[6]={2,0,0,0,0,2};
    CHECK(ker_packet_pool_init(&f.owner_pool,"fc_owner_pool",POOL_COUNT,0,4096,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&f.owner_skb,&f.owner_pool,"fc_owner_skb")==0);
    CHECK(ker_eth_device_init(&f.owner_device,&f.owner_skb,"fc_owner",22,owner_mac)==0);
    CHECK(ker_receive_runtime_init(&f.runtime,&f.owner_skb)==0);
    CHECK(ker_transport_receiver_register(&f.receiver,&f.runtime,&f.owner_device,message,&f)==0);
    struct ker_worker_config cfg={.timer_budget=1,.handoff_budget=1,.rx_budget=0};
    struct ker_worker_ops ops={0}; CHECK(ker_worker_init(&f.owner_worker,&f.owner_pool,&cfg,&ops)==0);
    CHECK(ker_flow_attach(&f.owner_flow,&f.fabric,&f.owner_worker,1,owner_receive,&f)==0);
    atomic_store_explicit(&f.owner_ready,true,memory_order_release);
    uint64_t end=deadline(); wait_bool(&f.release_owner,end);
    /* Keep a real worker poll loop active while ingress produces the remaining
     * traffic; the start gate made the first inbox-full sequence deterministic. */
    while(!atomic_load_explicit(&f.owner_stop,memory_order_acquire) &&
        atomic_load_explicit(&f.received,memory_order_acquire)<TRAFFIC){
        alive(end); struct ker_worker_result progress={0};
        int rc=ker_worker_poll(&f.owner_worker,1,&progress); CHECK(rc==0); sched_yield();
    }
    /* Owner-local pool exhaustion is a designated, synchronous receive drop. */
    wait_bool(&f.pool_ready,end); struct rte_mbuf *held[POOL_COUNT]; unsigned n=0;
    while(n<POOL_COUNT && (held[n]=ker_packet_alloc(&f.owner_pool))) n++;
    CHECK(n==POOL_COUNT && ker_packet_alloc(&f.owner_pool)==NULL); atomic_store_explicit(&f.release_drop,true,memory_order_release);
    while(!atomic_load_explicit(&f.drop_seen,memory_order_acquire)){alive(end);struct ker_worker_result x={0}; CHECK(ker_worker_poll(&f.owner_worker,2,&x)==0);sched_yield();}
    for(unsigned i=0;i<n;i++)ker_packet_free(held[i]);
    atomic_store_explicit(&f.release_recovery,true,memory_order_release);
    while(atomic_load_explicit(&f.received,memory_order_acquire)<TOTAL){alive(end);struct ker_worker_result x={0};CHECK(ker_worker_poll(&f.owner_worker,3,&x)==0);sched_yield();}
    wait_bool(&f.producer_done,end);
    CHECK(f.owner_flow.flow_ring_live==0);
    CHECK(ker_flow_detach(&f.owner_flow)==0);
    CHECK(ker_worker_cleanup(&f.owner_worker)==0);
    CHECK(ker_transport_receiver_unregister(&f.receiver)==0);
    CHECK(ker_receive_runtime_cleanup(&f.runtime)==0);
    CHECK(ker_eth_device_cleanup(&f.owner_device)==0);
    CHECK(ker_skb_context_cleanup(&f.owner_skb)==0);
    CHECK(ker_packet_pool_cleanup(&f.owner_pool)==0);
    atomic_store_explicit(&f.owner_cleaned,true,memory_order_release);
    wait_bool(&f.allow_owner_memory_shutdown,end);
    CHECK(ker_memory_shutdown()==0); rte_thread_unregister(); return NULL;
}

int main(void)
{
    for(unsigned i=0;i<TOTAL;i++)make_record(i);
    CHECK(sched_getaffinity(0,sizeof(f.allowed),&f.allowed)==0);
    int cpus[2],count=0;
    for(int i=0;i<CPU_SETSIZE&&count<2;i++)if(CPU_ISSET(i,&f.allowed))cpus[count++]=i;
    if(count<2){puts("SKIP: fewer than two CPUs in the process affinity mask");return 77;}
    f.owner_cpu_target=cpus[1]; set_cpu(cpus[0]);
    atomic_init(&f.owner_ready,false);atomic_init(&f.release_owner,false);atomic_init(&f.producer_done,false);
    atomic_init(&f.owner_stop,false);atomic_init(&f.pool_ready,false);atomic_init(&f.release_drop,false);
    atomic_init(&f.drop_seen,false);atomic_init(&f.release_recovery,false);atomic_init(&f.received,0);
    atomic_init(&f.owner_cleaned,false);atomic_init(&f.allow_owner_memory_shutdown,false);
    atomic_init(&f.delivered,0);atomic_init(&f.checksum_drops,0);atomic_init(&f.overlap,0);
    atomic_init(&f.main_cpu,(unsigned)cpus[0]);atomic_init(&f.owner_cpu,UINT_MAX);
    atomic_init(&f.main_lcore,UINT_MAX);atomic_init(&f.owner_lcore,UINT_MAX);atomic_init(&f.producer_active,false);
    ker_test_eal_init_on_cpu(cpus[0]); CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    atomic_store(&f.main_cpu,(unsigned)sched_getcpu());atomic_store(&f.main_lcore,rte_lcore_id());
    uint16_t owners[KER_FLOW_BUCKETS];for(unsigned i=0;i<KER_FLOW_BUCKETS;i++)owners[i]=1;
    struct ker_flow_config fc={.worker_count=2,.bucket_owner=owners,.seed=0x12345678,.inbox_capacity=1,.name="fc_flow",.socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&f.fabric,&fc)==0);
    CHECK(ker_packet_pool_init(&f.ingress_pool,"fc_ingress_pool",POOL_COUNT,0,4096,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&f.ingress_skb,&f.ingress_pool,"fc_ingress_skb")==0);
    CHECK(ker_eth_device_init(&f.ingress_device,&f.ingress_skb,"fc_ingress",21,mac)==0);
    struct ker_worker_config icfg={.timer_budget=1,.handoff_budget=1,.rx_budget=1};
    struct ker_worker_ops iops={.rx=ker_flow_ring_poll,.arg=&f.adapter};
    CHECK(ker_worker_init(&f.ingress_worker,&f.ingress_pool,&icfg,&iops)==0);
    CHECK(ker_flow_attach(&f.ingress_flow,&f.fabric,&f.ingress_worker,0,owner_receive,&f)==0);
    CHECK(ker_tx_ring_init(&f.ring,"fc_source",4,SOCKET_ID_ANY)==0);
    CHECK(ker_flow_ring_init(&f.adapter,&f.ring,&f.ingress_flow,DOMAIN,KER_FLOW_INGRESS)==0);
    CHECK(pthread_create(&f.owner_thread,NULL,owner_main,NULL)==0); uint64_t end=deadline();wait_bool(&f.owner_ready,end);
    CHECK(atomic_load(&f.owner_cpu)!=(unsigned)atomic_load(&f.main_cpu));CHECK(atomic_load(&f.owner_lcore)!=atomic_load(&f.main_lcore));
    /* First chain fills inbox; second remains adapter-pending; third remains
     * in source ring until owner is released. */
    produce(0,true); CHECK(atomic_load(&f.received)==0&&f.adapter.last_completed==1&&f.adapter.last_error==0);
    struct rte_mbuf *saved_second=make_chain(1); CHECK(ker_tx_ring_sink(saved_second,&f.ring)==0);
    struct ker_worker_result blocked={0}; CHECK(ker_worker_poll(&f.ingress_worker,ingress_now++,&blocked)==-ENOBUFS);
    CHECK(f.adapter.pending==saved_second&&f.adapter.pending->nb_segs==7&&f.adapter.last_completed==0&&f.adapter.last_error==-ENOBUFS);
    produce(2,false); CHECK(rte_ring_count(f.ring.ring)==1); atomic_store(&f.release_owner,true);
    atomic_store(&f.producer_active,true);
    for(unsigned i=3;i<TRAFFIC;i++){
        produce(i,true);
        if(i==96){while(atomic_load_explicit(&f.received,memory_order_acquire)<48){alive(end);ingress_retry();sched_yield();}CHECK(atomic_load(&f.overlap)>0);}
    }
    atomic_store(&f.producer_active,false);
    while(f.adapter.pending || !rte_ring_empty(f.ring.ring)) {alive(end);ingress_retry();}
    while(atomic_load_explicit(&f.received,memory_order_acquire)<TRAFFIC){alive(end);sched_yield();}
    atomic_store_explicit(&f.pool_ready,true,memory_order_release); wait_bool(&f.release_drop,end);
    produce(DROP_ID,true); wait_bool(&f.drop_seen,end); wait_bool(&f.release_recovery,end);
    produce(RECOVER_ID,true); atomic_store(&f.producer_done,true); atomic_store(&f.owner_stop,true);
    wait_bool(&f.owner_cleaned,end);
    CHECK(atomic_load(&f.received)==TOTAL&&atomic_load(&f.delivered)==TRAFFIC-1);
    CHECK(atomic_load(&f.checksum_drops)==2&&atomic_load(&f.overlap)>0);
    CHECK(!f.adapter.pending&&rte_ring_empty(f.ring.ring)&&f.ingress_flow.flow_ring_live==1);
    CHECK(ker_flow_ring_cleanup(&f.adapter)==0);CHECK(!f.ingress_flow.flow_ring_live);CHECK(ker_tx_ring_cleanup(&f.ring)==0);
    CHECK(ker_flow_detach(&f.ingress_flow)==0);CHECK(ker_worker_cleanup(&f.ingress_worker)==0);
    CHECK(ker_eth_device_cleanup(&f.ingress_device)==0);CHECK(ker_skb_context_cleanup(&f.ingress_skb)==0);
    CHECK(ker_packet_pool_cleanup(&f.ingress_pool)==0);CHECK(ker_flow_fabric_cleanup(&f.fabric)==0);
    atomic_store_explicit(&f.allow_owner_memory_shutdown,true,memory_order_release);
    CHECK(pthread_join(f.owner_thread,NULL)==0);
    CHECK(ker_memory_shutdown()==0);CHECK(rte_eal_cleanup()==0);return 0;
}

