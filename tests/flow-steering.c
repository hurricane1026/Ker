#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <rte_lcore.h>
#include <rte_ip.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

#define PRODUCERS 3U
#define VARIANTS 24U
#define PASSES 128U
#define TOTAL (PRODUCERS * VARIANTS * PASSES)
#define DOMAIN 7U
#define SEED UINT64_C(0x123456789abcdef0)
#define PAYLOAD_SIZE 16U

struct fixture { uint8_t family, proto; uint16_t remote_port; uint32_t hash; unsigned owner; };
static const struct fixture fixtures[12] = {
    {4,6,1234,0x876c953f,0},{4,6,1237,0xde3adef1,1},{4,6,1235,0x6e85e320,2},
    {4,17,1234,0xcccabd24,0},{4,17,1235,0x5eab8b43,1},{4,17,1238,0x85f5a947,2},
    {6,6,1239,0x2b6084d2,0},{6,6,1235,0xde7ddd82,1},{6,6,1234,0xc86aa729,2},
    {6,17,1234,0xad12d2d5,0},{6,17,1247,0x12634fd3,1},{6,17,1237,0x2271deb0,2}
};
struct expected { struct ker_flow_key key; unsigned owner; unsigned cpu; unsigned lcore; };
struct harness {
    struct ker_packet_pool pool;
    struct ker_flow_fabric fabric;
    struct ker_worker workers[PRODUCERS];
    struct ker_flow_context contexts[PRODUCERS];
    struct expected expected[PRODUCERS][VARIANTS];
    atomic_uint seen[TOTAL];
    atomic_uint received[PRODUCERS];
    atomic_uint epoch_seen[VARIANTS][PRODUCERS];
    atomic_uint epoch_success[VARIANTS][PRODUCERS];
    atomic_uint epoch_done[VARIANTS];
    atomic_uint epoch_overlap[VARIANTS];
    atomic_uint producer_done;
    atomic_uint callback_errors;
    atomic_uint retries[PRODUCERS];
    pthread_barrier_t start;
    pthread_mutex_t attach_lock;
    bool multicore;
};
struct thread_arg { struct harness *h; unsigned worker; int cpu; };

static unsigned fixture_index(unsigned variant) { return variant / 2; }
static bool egress_variant(unsigned variant) { return (variant & 1U) != 0; }
static struct ker_flow_key fixture_key(const struct fixture *f)
{
    struct ker_flow_key k = {.domain=DOMAIN,.family=f->family,.protocol=f->proto,
        .local_port=443,.remote_port=f->remote_port};
    if (f->family == 4) {
        k.local[12]=10; k.local[15]=1;
        k.remote[12]=192; k.remote[14]=2; k.remote[15]=1;
    } else {
        const uint8_t local[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        const uint8_t remote[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
        memcpy(k.local,local,16); memcpy(k.remote,remote,16);
    }
    return k;
}
static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static size_t make_frame(uint8_t *out, unsigned variant, unsigned id)
{
    const struct fixture *f=&fixtures[fixture_index(variant)];
    bool egress=egress_variant(variant);
    size_t iplen=f->family==4 ? 20 : 40, translen=f->proto==6 ? 20 : 8;
    size_t total=14+iplen+translen+PAYLOAD_SIZE;
    memset(out,0,total);
    out[12]=f->family==4?0x08:0x86; out[13]=f->family==4?0x00:0xdd;
    uint8_t *ip=out+14;
    if (f->family==4) {
        ip[0]=0x45; put16(ip+2,(uint16_t)(iplen+translen+PAYLOAD_SIZE)); ip[8]=64; ip[9]=f->proto;
        const uint8_t local[4]={10,0,0,1}, remote[4]={192,0,2,1};
        memcpy(ip+12,egress?local:remote,4); memcpy(ip+16,egress?remote:local,4);
    } else {
        ip[0]=0x60; put16(ip+4,(uint16_t)(translen+PAYLOAD_SIZE)); ip[6]=f->proto; ip[7]=64;
        const struct ker_flow_key k=fixture_key(f);
        memcpy(ip+8,egress?k.local:k.remote,16); memcpy(ip+24,egress?k.remote:k.local,16);
    }
    uint8_t *l4=ip+iplen;
    put16(l4,egress?443:f->remote_port); put16(l4+2,egress?f->remote_port:443);
    if (f->proto==6) { l4[12]=0x50; l4[13]=0x18; }
    else put16(l4+4,(uint16_t)(translen+PAYLOAD_SIZE));
    uint8_t *payload=l4+translen;
    payload[0]=(uint8_t)(id>>24); payload[1]=(uint8_t)(id>>16); payload[2]=(uint8_t)(id>>8); payload[3]=(uint8_t)id;
    for (unsigned i=4;i<PAYLOAD_SIZE;i++) payload[i]=(uint8_t)((id*33U+i*17U+variant)&0xff);
    return total;
}
static struct rte_mbuf *packet_for(struct harness *h,unsigned variant,unsigned id)
{
    struct rte_mbuf *m=ker_packet_alloc(&h->pool); CHECK(m!=NULL);
    uint8_t expected[128]; size_t n=make_frame(expected,variant,id);
    uint8_t *p=(uint8_t *)rte_pktmbuf_append(m,(uint16_t)n); CHECK(p!=NULL); memcpy(p,expected,n);
    return m;
}
struct callback_arg { struct harness *h; unsigned worker; };
static struct callback_arg callback_args[PRODUCERS];
static void on_receive(void *arg,const struct ker_flow_key *key,struct rte_mbuf *m)
{
    struct callback_arg *ca=arg; struct harness *h=ca->h; unsigned owner=ca->worker;
    uint8_t *bytes=rte_pktmbuf_mtod(m,uint8_t *); size_t len=rte_pktmbuf_pkt_len(m);
    unsigned id=UINT_MAX, variant=UINT_MAX;
    if (len<14+20+8+PAYLOAD_SIZE) goto bad;
    size_t iplen=(bytes[14]>>4)==4?20:((bytes[14]>>4)==6?40:0);
    if (!iplen || len<14+iplen+8+PAYLOAD_SIZE) goto bad;
    uint8_t protocol=(bytes[14]>>4)==4?bytes[23]:bytes[20];
    size_t translen=protocol==IPPROTO_TCP?20:8;
    if ((protocol!=IPPROTO_TCP && protocol!=IPPROTO_UDP) || len<14+iplen+translen+PAYLOAD_SIZE) goto bad;
    uint8_t *payload=bytes+14+iplen+translen;
    id=((unsigned)payload[0]<<24)|((unsigned)payload[1]<<16)|((unsigned)payload[2]<<8)|payload[3];
    if (id>=TOTAL) goto bad;
    variant=(id% (VARIANTS*PASSES))/PASSES;
    if (owner>=PRODUCERS || h->expected[owner][variant].owner!=owner ||
        key->domain!=DOMAIN || key->family!=h->expected[owner][variant].key.family ||
        key->protocol!=h->expected[owner][variant].key.protocol ||
        key->local_port!=h->expected[owner][variant].key.local_port ||
        key->remote_port!=h->expected[owner][variant].key.remote_port ||
        memcmp(key->local,h->expected[owner][variant].key.local,16) ||
        memcmp(key->remote,h->expected[owner][variant].key.remote,16) ||
        rte_lcore_id()!=h->expected[owner][variant].lcore) goto bad;
    if (h->multicore && sched_getcpu()!=(int)h->expected[owner][variant].cpu) goto bad;
    uint8_t wanted[128]; size_t wanted_len=make_frame(wanted,variant,id);
    if (len!=wanted_len || memcmp(bytes,wanted,len)) goto bad;
    if (atomic_fetch_add(&h->seen[id],1)!=0) goto bad;
    unsigned source=id/(VARIANTS*PASSES), advancing=0;
    atomic_fetch_add(&h->epoch_seen[variant][owner],1);
    unsigned done=atomic_load(&h->epoch_done[variant]);
    for(unsigned i=0;i<PRODUCERS;i++)
        if (!(done&(1U<<i)) && atomic_load(&h->epoch_success[variant][i])>0) advancing++;
    if (source!=owner && advancing>=2) atomic_fetch_add(&h->epoch_overlap[variant],1);
    atomic_fetch_add(&h->received[owner],1);
    rte_pktmbuf_free(m); return;
bad:
    atomic_fetch_add(&h->callback_errors,1); rte_pktmbuf_free(m);
}

static void prepare(struct harness *h,bool multicore)
{
    memset(h,0,sizeof(*h)); h->multicore=multicore;
    for(unsigned i=0;i<TOTAL;i++) atomic_init(&h->seen[i],0);
    for(unsigned i=0;i<PRODUCERS;i++) {
        atomic_init(&h->received[i],0);
        atomic_init(&h->retries[i],0);
    }
    for(unsigned v=0;v<VARIANTS;v++) {
        atomic_init(&h->epoch_done[v],0);
        atomic_init(&h->epoch_overlap[v],0);
        for(unsigned i=0;i<PRODUCERS;i++) {
            atomic_init(&h->epoch_seen[v][i],0);
            atomic_init(&h->epoch_success[v][i],0);
        }
    }
    atomic_init(&h->producer_done,0);
    atomic_init(&h->callback_errors,0);
    uint16_t map[KER_FLOW_BUCKETS]; for(unsigned b=0;b<KER_FLOW_BUCKETS;b++) map[b]=(uint16_t)(b%3U);
    struct ker_flow_config cfg={.worker_count=PRODUCERS,.bucket_owner=map,.seed=SEED,
        .inbox_capacity=multicore?8U:32U,.name=multicore?"ker_flow_stress":"ker_flow_matrix",.socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&h->fabric,&cfg)==0);
    CHECK(ker_packet_pool_init(&h->pool,multicore?"ker_flow_stress_pool":"ker_flow_matrix_pool",511,0,2048,SOCKET_ID_ANY)==0);
    for(unsigned i=0;i<12;i++) {
        struct ker_flow_key k=fixture_key(&fixtures[i]); uint32_t hash=0;
        CHECK(ker_flow_hash(&k,SEED,&hash)==0 && hash==fixtures[i].hash);
        CHECK((hash & (KER_FLOW_BUCKETS-1U))%3U==fixtures[i].owner);
        for(unsigned d=0;d<2;d++) for(unsigned w=0;w<3;w++) {
            unsigned v=i*2+d; h->expected[w][v].key=k; h->expected[w][v].owner=fixtures[i].owner;
        }
    }
}
static void init_worker(struct harness *h,unsigned id,int cpu)
{
    struct ker_worker_config wc={.timer_budget=1,.handoff_budget=64}; struct ker_worker_ops ops={0};
    CHECK(ker_worker_init(&h->workers[id],&h->pool,&wc,&ops)==0);
    callback_args[id]=(struct callback_arg){h,id};
    for(unsigned v=0;v<VARIANTS;v++) {
        h->expected[id][v].cpu=(unsigned)cpu; h->expected[id][v].lcore=rte_lcore_id();
    }
    CHECK(pthread_mutex_lock(&h->attach_lock)==0);
    CHECK(ker_flow_attach(&h->contexts[id],&h->fabric,&h->workers[id],id,on_receive,&callback_args[id])==0);
    CHECK(pthread_mutex_unlock(&h->attach_lock)==0);
}
static void verify_seen(struct harness *h,bool stress)
{
    unsigned expected_owner[3]={0};
    if(stress) {
        for(unsigned i=0;i<12;i++) expected_owner[fixtures[i].owner]+=3U*2U*PASSES;
        for(unsigned o=0;o<3;o++) CHECK(atomic_load(&h->received[o])==expected_owner[o]);
    }
    for(unsigned id=0;id<TOTAL;id++)
        CHECK(atomic_load(&h->seen[id])==(stress?1U:((id%PASSES)==0?1U:0U)));
    CHECK(atomic_load(&h->callback_errors)==0);
}
static void cleanup(struct harness *h)
{
    for(unsigned i=0;i<3;i++) {
        CHECK(ker_flow_detach(&h->contexts[i])==0);
        CHECK(ker_worker_cleanup(&h->workers[i])==0);
    }
    CHECK(ker_flow_fabric_cleanup(&h->fabric)==0);
    CHECK(ker_packet_pool_cleanup(&h->pool)==0);
    CHECK(ker_memory_shutdown()==0);
}
static int poll_worker(struct harness *h,unsigned owner)
{
    struct timespec ts; CHECK(clock_gettime(CLOCK_MONOTONIC,&ts)==0);
    struct ker_worker_result result;
    int rc=ker_worker_poll(&h->workers[owner],(int64_t)ts.tv_sec*1000000000LL+ts.tv_nsec,&result);
    return rc==0?(int)result.handoff:rc;
}
static int matrix(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    struct harness h; prepare(&h,false); CHECK(pthread_mutex_init(&h.attach_lock,NULL)==0);
    int cpu=sched_getcpu();
    for(unsigned w=0;w<3;w++) init_worker(&h,w,cpu);
    unsigned callbacks[3]={0};
    for(unsigned src=0;src<3;src++) for(unsigned v=0;v<VARIANTS;v++) {
        unsigned id=(src*VARIANTS+v)*PASSES;
        unsigned own=fixtures[fixture_index(v)].owner;
        unsigned before=atomic_load(&h.received[own]);
        struct rte_mbuf *m=packet_for(&h,v,id);
        CHECK(ker_flow_submit(&h.contexts[src],DOMAIN,egress_variant(v)?KER_FLOW_EGRESS:KER_FLOW_INGRESS,&m)==0 && m==NULL);
        if(own==src) { CHECK(atomic_load(&h.received[own])==before+1); callbacks[own]++; }
        else CHECK(atomic_load(&h.received[own])==before);
    }
    for(unsigned o=0;o<3;o++) { int done=poll_worker(&h,o); CHECK(done==(int)(atomic_load(&h.received[o])-callbacks[o])); }
    for(unsigned o=0;o<3;o++) CHECK(atomic_load(&h.received[o])==24);
    for(unsigned p=0;p<3;p++) for(unsigned v=0;v<VARIANTS;v++)
        CHECK(atomic_load(&h.seen[(p*VARIANTS+v)*PASSES])==1);
    CHECK(atomic_load(&h.callback_errors)==0);
    cleanup(&h); CHECK(pthread_mutex_destroy(&h.attach_lock)==0); CHECK(rte_eal_cleanup()==0);
    puts("flow matrix: all fixture owners, reverse directions, and local/remote paths passed"); return 0;
}
static int allowed_cpus(int cpus[CPU_SETSIZE])
{
    cpu_set_t set; CHECK(sched_getaffinity(0,sizeof(set),&set)==0);
    int n=0; for(int i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&set)) cpus[n++]=i;
    return n;
}
static bool before_deadline(const struct timespec *start)
{
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC,&now)==0);
    return now.tv_sec-start->tv_sec<15;
}
static int pin_and_verify(int cpu)
{
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
    if(pthread_setaffinity_np(pthread_self(),sizeof(set),&set)!=0) return -1;
    cpu_set_t actual; CPU_ZERO(&actual);
    if(sched_getaffinity(0,sizeof(actual),&actual)!=0 || CPU_COUNT(&actual)!=1 || !CPU_ISSET(cpu,&actual) || sched_getcpu()!=cpu) return -1;
    return 0;
}
static void run_multicore_traffic(struct harness *h,unsigned worker)
{
    for(unsigned v=0;v<VARIANTS;v++) {
        pthread_barrier_wait(&h->start); /* begin this fixture/direction epoch */
        struct timespec start; CHECK(clock_gettime(CLOCK_MONOTONIC,&start)==0);
        for(unsigned pass=0;pass<PASSES;pass++) {
            unsigned id=(worker*VARIANTS+v)*PASSES+pass;
            struct rte_mbuf *m=packet_for(h,v,id); int rc;
            do {
                struct rte_mbuf *original=m;
                rc=ker_flow_submit(&h->contexts[worker],DOMAIN,
                    egress_variant(v)?KER_FLOW_EGRESS:KER_FLOW_INGRESS,&m);
                if(rc==-ENOBUFS) {
                    CHECK(m==original); atomic_fetch_add(&h->retries[worker],1);
                    CHECK(poll_worker(h,worker)>=0); CHECK(before_deadline(&start));
                }
            } while(rc==-ENOBUFS);
            CHECK(rc==0 && m==NULL);
            atomic_fetch_add(&h->epoch_success[v][worker],1);
            if(pass==0) pthread_barrier_wait(&h->start); /* all owners/senders made progress */
            CHECK(poll_worker(h,worker)>=0);
            CHECK(before_deadline(&start));
        }
        atomic_fetch_or(&h->epoch_done[v],1U<<worker);
        unsigned expected=fixtures[fixture_index(v)].owner==worker?PRODUCERS*PASSES:0;
        while(atomic_load(&h->epoch_done[v])!=((1U<<PRODUCERS)-1U) ||
              atomic_load(&h->epoch_seen[v][worker])<expected) {
            CHECK(poll_worker(h,worker)>=0); sched_yield(); CHECK(before_deadline(&start));
        }
        pthread_barrier_wait(&h->start); /* all producers stopped and this owner drained */
    }
    atomic_fetch_add(&h->producer_done,1);
}
static void *stress_thread(void *opaque)
{
    struct thread_arg *a=opaque; struct harness *h=a->h; unsigned w=a->worker;
    CHECK(pin_and_verify(a->cpu)==0); CHECK(rte_thread_register()==0);
    CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    init_worker(h,w,a->cpu);
    for(unsigned v=0;v<VARIANTS;v++) h->expected[w][v].lcore=rte_lcore_id();
    run_multicore_traffic(h,w);
    CHECK(ker_flow_detach(&h->contexts[w])==0); CHECK(ker_worker_cleanup(&h->workers[w])==0);
    CHECK(ker_memory_shutdown()==0); rte_thread_unregister(); return NULL;
}
static int multicore(void)
{
    int cpus[CPU_SETSIZE],n=allowed_cpus(cpus);
    if(n<3) { fprintf(stderr,"flow multicore skipped: requires 3 allowed CPUs (EAL/main plus two workers), found %d\n",n); return 77; }
    ker_test_eal_init_on_cpu(cpus[0]);
    CHECK(pin_and_verify(cpus[0])==0); CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    struct harness h; prepare(&h,true); CHECK(pthread_mutex_init(&h.attach_lock,NULL)==0);
    CHECK(pthread_barrier_init(&h.start,NULL,3)==0);
    init_worker(&h,0,cpus[0]);
    for(unsigned v=0;v<VARIANTS;v++) h.expected[0][v].lcore=rte_lcore_id();
    pthread_t threads[2]; struct thread_arg args[2]={{&h,1,cpus[1]},{&h,2,cpus[2]}};
    for(unsigned i=0;i<2;i++) CHECK(pthread_create(&threads[i],NULL,stress_thread,&args[i])==0);
    run_multicore_traffic(&h,0);
    CHECK(ker_flow_detach(&h.contexts[0])==0); CHECK(ker_worker_cleanup(&h.workers[0])==0);
    CHECK(ker_memory_shutdown()==0);
    for(unsigned i=0;i<2;i++) CHECK(pthread_join(threads[i],NULL)==0);
    CHECK(atomic_load(&h.producer_done)==3);
    for(unsigned v=0;v<VARIANTS;v++) CHECK(atomic_load(&h.epoch_overlap[v])>0);
    verify_seen(&h,true);
    CHECK(ker_flow_fabric_cleanup(&h.fabric)==0); CHECK(ker_packet_pool_cleanup(&h.pool)==0);
    CHECK(pthread_barrier_destroy(&h.start)==0); CHECK(pthread_mutex_destroy(&h.attach_lock)==0);
    CHECK(rte_eal_cleanup()==0);
    puts("flow multicore: 9216 exact-once packets passed on three pinned CPUs"); return 0;
}
int main(int argc,char **argv)
{
    CHECK(argc==2);
    if(strcmp(argv[1],"--matrix")==0) return matrix();
    if(strcmp(argv[1],"--multicore")==0) return multicore();
    return 2;
}
