#include "check.h"
#include "eal.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/tcp-create.h"
#include "runtime/udp-create.h"
#include "runtime/ipv4-address.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>
#include <limits.h>

#define POOL_SIZE 31U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static const unsigned char source_mac[6] = {2, 0x10, 0x21, 0x32, 0x43, 0x54};
static const unsigned char destination_mac[6] = {2, 0x60, 0x71, 0x82, 0x93, 0xa4};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x630200c6;
static const __be16 identifier = (__be16)0x3412, sequence = (__be16)0x7856;
static const unsigned char payload[] = {0x10, 0x21, 0x32, 0x43, 0x54};

static uint16_t checksum(const unsigned char *p, size_t n)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i += 2) {
        uint16_t word = (uint16_t)p[i] << 8;
        if (i + 1 < n) word |= p[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static void verify(struct sk_buff *skb, const unsigned char *dst, uint8_t type,
    const unsigned char *options, unsigned int options_len,
    const unsigned char *data, unsigned int data_len,
    const struct ker_ipv4_header_fields *fields, __be16 id, __be16 seq)
{
    unsigned int ihl = 20 + options_len, icmp_len = 8 + data_len;
    CHECK(skb && skb->len == ETH_HLEN + ihl + icmp_len && skb_headroom(skb) == 128 &&
        skb->mac_header == 128 && skb->network_header == 128 + ETH_HLEN &&
        skb->transport_header == 128 + ETH_HLEN + ihl && skb->mac_len == ETH_HLEN);
    const unsigned char *f = skb->data;
    CHECK(!memcmp(f, dst, 6) && !memcmp(f + 6, source_mac, 6) && f[12] == 8 && f[13] == 0);
    const unsigned char *ip = f + ETH_HLEN;
    CHECK(ip[0] == (unsigned char)(0x40U | ihl / 4U) && ip[1] == fields->ds_field &&
        !memcmp(ip + 4, &fields->identification, 2) && !memcmp(ip + 6, &fields->frag_off, 2) &&
        ip[2] == (unsigned char)((ihl + icmp_len) >> 8) &&
        ip[3] == (unsigned char)(ihl + icmp_len) && ip[8] == 64 && ip[9] == IPPROTO_ICMP &&
        !memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(checksum(ip, ihl) == 0 &&
        (!options_len || !memcmp(ip + 20, options, options_len)));
    const unsigned char *icmp = ip + ihl;
    CHECK(icmp[0] == type && icmp[1] == 0 && !memcmp(icmp + 4, &id, 2) &&
        !memcmp(icmp + 6, &seq, 2) && checksum(icmp, icmp_len) == 0 &&
        (!data_len || !memcmp(icmp + 8, data, data_len)));
}

static void success_vectors(void)
{
    unsigned char options[40], data[5];
    for (unsigned int i = 0; i < 40; ++i) options[i] = (unsigned char)(0x83U + i * 7U);
    memcpy(data, payload, sizeof(data));
    const unsigned int optlens[] = {0, 4, 40}, datalens[] = {0, 3, 5};
    const struct ker_ipv4_header_fields zero = {0};
    for (unsigned int type_index = 0; type_index < 2; ++type_index) {
        uint8_t type = type_index ? 0 : 8;
        for (unsigned int oi = 0; oi < 3; ++oi) for (unsigned int di = 0; di < 3; ++di) {
            struct sk_buff *actual = NULL, *raw = NULL;
            CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
                identifier,sequence,type,64,options,optlens[oi],data,datalens[di],&actual)==0);
            CHECK(ker_icmp_echo_ipv4_create_ip_options(&context,source_mac,destination_mac,
                source_ip,destination_ip,identifier,sequence,type,64,options,optlens[oi],
                data,datalens[di],&raw)==0);
            verify(actual,destination_mac,type,options,optlens[oi],data,datalens[di],&zero,
                identifier,sequence);
            CHECK(actual->len==raw->len && !memcmp(actual->data,raw->data,actual->len));
            CHECK(ker_skb_free(raw)==0 && ker_skb_free(actual)==0);
        }
    }
    struct ker_ipv4_header_fields fields = {.ds_field=0xff,
        .identification=(__be16)0x3412,.frag_off=rte_cpu_to_be_16(0x4000)};
    struct ker_ipv4_header_fields raw_fields = fields;
    unsigned char dst[6]; memcpy(dst,destination_mac,6);
    struct sk_buff *actual=NULL,*raw=NULL;
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,dst,destination_ip,
        identifier,sequence,8,64,&fields,options,40,data,sizeof(data),&actual)==0);
    CHECK(ker_icmp_echo_ipv4_create_fields(&context,source_mac,dst,source_ip,destination_ip,
        identifier,sequence,8,64,&raw_fields,options,40,data,sizeof(data),&raw)==0);
    verify(actual,destination_mac,8,options,40,data,sizeof(data),&fields,identifier,sequence);
    CHECK(actual->len==raw->len && !memcmp(actual->data,raw->data,actual->len));
    unsigned char snapshot[ETH_HLEN+60+8+sizeof(data)]; memcpy(snapshot,actual->data,actual->len);
    memset(options,0,40); memset(data,0,sizeof(data)); memset(dst,0,6);
    memset(device.native->dev_addr_shadow,0,6); fields.ds_field=0;
    CHECK(!memcmp(actual->data,snapshot,actual->len));
    memcpy(device.native->dev_addr_shadow,source_mac,6);
    CHECK(ker_skb_free(raw)==0 && ker_skb_free(actual)==0);
}

static void zero_checksum_vector(void)
{
    unsigned char data[5], header[13] = {8,0};
    memcpy(header + 4, &identifier, 2); memcpy(header + 6, &sequence, 2);
    bool found = false;
    for (unsigned int v=0; v<=UINT16_MAX; ++v) {
        data[0]=0x10; data[1]=0x21; data[2]=0x32;
        data[3]=(unsigned char)(v>>8); data[4]=(unsigned char)v;
        memcpy(header+8,data,sizeof(data));
        if (checksum(header,sizeof(header))==0) { found=true; break; }
    }
    CHECK(found);
    struct sk_buff *skb=NULL;
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,NULL,0,data,sizeof(data),&skb)==0);
    const unsigned char *icmp=skb->data+ETH_HLEN+20;
    CHECK(icmp[2]==0 && icmp[3]==0 && checksum(icmp,sizeof(header))==0);
    CHECK(ker_skb_free(skb)==0);
}

static void check_all_association(int expected)
{
    unsigned char data[1] = {0}; struct ker_ipv4_header_fields fields = {0};
    size_t avail = rte_mempool_avail_count(pool.mbufs);
    struct sk_buff *out=(void *)(uintptr_t)0x1234;
    CHECK(ker_udp_ipv4_create_configured(&address,destination_mac,destination_ip,
        rte_cpu_to_be_16(100),rte_cpu_to_be_16(200),64,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234);
    CHECK(ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        rte_cpu_to_be_16(100),rte_cpu_to_be_16(200),0,0,0,0x10,64,
        NULL,0,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234);
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
        0,0,8,64,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234);
    CHECK(ker_udp_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        0,0,64,&fields,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234);
    CHECK(ker_tcp_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        0,0,0,0,0,0x10,64,&fields,NULL,0,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234);
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        0,0,8,64,&fields,NULL,0,data,1,&out)==expected);
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0 &&
        rte_mempool_avail_count(pool.mbufs)==avail);
}

static void failures(void)
{
    unsigned char options[44]={0},data[4]={1,2,3,4};
    struct sk_buff *out=(void *)(uintptr_t)0x1234;
    struct ker_ipv4_header_fields good={0},bad={.frag_off=rte_cpu_to_be_16(0x2000)};
    size_t free_before=rte_mempool_avail_count(pool.mbufs);
#define REJECT(code,type,ttl,opts,olen,payload_arg,plen) do { \
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip, \
        identifier,sequence,(type),(ttl),(opts),(olen),(payload_arg),(plen),&out)==(code)); \
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0); \
} while(0)
    REJECT(-EINVAL,3,64,NULL,0,data,sizeof(data));
    REJECT(-EINVAL,8,0,NULL,0,data,sizeof(data));
    REJECT(-EINVAL,8,64,NULL,4,data,sizeof(data));
    REJECT(-EINVAL,8,64,options,2,data,sizeof(data));
    REJECT(-EINVAL,0,64,options,44,data,sizeof(data));
    REJECT(-EMSGSIZE,8,64,NULL,0,data,UINT_MAX);
    REJECT(-ENOSPC,8,64,options,40,data,65467);
    REJECT(-EMSGSIZE,8,64,options,40,data,65468);
#undef REJECT
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,&bad,NULL,0,data,sizeof(data),&out)==-ENOTSUP);
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0 &&
        rte_mempool_avail_count(pool.mbufs)==free_before);
    /* Invalid field profile is rejected before inspecting stale address state. */
    void *saved_ip_ptr=rcu_dereference_raw(device.native->ip_ptr);
    rcu_assign_pointer(device.native->ip_ptr,NULL);
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,&bad,NULL,0,data,sizeof(data),&out)==-ENOTSUP);
    rcu_assign_pointer(device.native->ip_ptr,saved_ip_ptr);
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0 &&
        rte_mempool_avail_count(pool.mbufs)==free_before);

    /* Shared association failures have identical errno/rollback across UDP,
     * TCP and echo adapters. */
    address.native->dead=1; check_all_association(-ESHUTDOWN); address.native->dead=0;
    struct in_device *saved_native=address.native;
    address.native=NULL; check_all_association(-ESHUTDOWN); address.native=saved_native;
    struct ker_eth_device *saved_device=address.device;
    address.device=NULL; check_all_association(-ESHUTDOWN); address.device=saved_device;
    struct in_ifaddr *ifa=address.native->ifa_list;
    struct in_ifaddr *saved_list=address.native->ifa_list;
    address.native->ifa_list=NULL; check_all_association(-ESHUTDOWN);
    address.native->ifa_list=saved_list;
    struct in_device wrong={0}; struct in_device *saved_ifa_dev=ifa->ifa_dev;
    ifa->ifa_dev=&wrong; check_all_association(-ESHUTDOWN); ifa->ifa_dev=saved_ifa_dev;
    unsigned int saved_flags=ifa->ifa_flags;
    ifa->ifa_flags &= ~IFA_F_PERMANENT; check_all_association(-ENOTSUP); ifa->ifa_flags=saved_flags;
    struct net_device *saved_native_dev=address.native->dev;
    address.native->dev=NULL; check_all_association(-ESHUTDOWN);
    address.native->dev=saved_native_dev;
    struct net_device *saved_device_native=device.native;
    device.native=NULL; check_all_association(-ESHUTDOWN); device.native=saved_device_native;
    void *saved_device_ip=rcu_dereference_raw(device.native->ip_ptr);
    rcu_assign_pointer(device.native->ip_ptr,NULL); check_all_association(-ESHUTDOWN);
    rcu_assign_pointer(device.native->ip_ptr,saved_device_ip);

    ker_memory_fail_after(0);
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,&good,NULL,0,data,sizeof(data),&out)==-ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0 &&
        rte_mempool_avail_count(pool.mbufs)==free_before);
    struct rte_mbuf *held[POOL_SIZE]; unsigned int count=0;
    while(count<POOL_SIZE && (held[count]=ker_packet_alloc(&pool))!=NULL) ++count;
    CHECK(count==POOL_SIZE);
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,NULL,0,data,sizeof(data),&out)==-ENOMEM);
    CHECK(out==(void *)(uintptr_t)0x1234 && context.live==0);
    ker_packet_free(held[--count]);
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,NULL,0,data,sizeof(data),&out)==0);
    CHECK(ker_skb_free(out)==0);
    while(count) ker_packet_free(held[--count]);
    CHECK(rte_mempool_avail_count(pool.mbufs)==POOL_SIZE && context.live==0);
}

static void *foreign_worker(void *unused)
{
    (void)unused; struct sk_buff *out=(void *)(uintptr_t)0x1234;
    CHECK(ker_icmp_echo_ipv4_create_configured(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,NULL,0,NULL,0,&out)==-EXDEV);
    CHECK(out==(void *)(uintptr_t)0x1234);
    struct ker_ipv4_header_fields fields={0};
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        identifier,sequence,8,64,&fields,NULL,0,NULL,0,&out)==-EXDEV);
    CHECK(out==(void *)(uintptr_t)0x1234);
    return NULL;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY,7)==0);
    CHECK(ker_packet_pool_init(&pool,"icmp_cfg",POOL_SIZE,0,2048,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&context,&pool,"icmp_cfg_skb")==0);
    CHECK(ker_eth_device_init(&device,&context,"icmp-cfg",43,source_mac)==0);
    CHECK(ker_ipv4_address_init(&address,&device,source_ip,24)==0);
    success_vectors(); zero_checksum_vector(); failures();
    pthread_t thread;
    CHECK(pthread_create(&thread,NULL,foreign_worker,NULL)==0 && pthread_join(thread,NULL)==0);
    CHECK(ker_ipv4_address_cleanup(&address)==0 && ker_eth_device_cleanup(&device)==0 &&
        ker_skb_context_cleanup(&context)==0 && rte_mempool_avail_count(pool.mbufs)==POOL_SIZE &&
        ker_packet_pool_cleanup(&pool)==0 && ker_memory_shutdown()==0 && rte_eal_cleanup()==0);
    puts("configured ICMP echo constructors: checksums, profiles, shared association rollback passed");
    return 0;
}
