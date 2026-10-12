#include "check.h"
#include "eal.h"
#include "runtime/tcp-create.h"
#include "runtime/ipv4-address.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#define POOL_SIZE 31U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static const unsigned char source_mac[6] = {2, 0x10, 0x21, 0x32, 0x43, 0x54};
static const unsigned char destination_mac[6] = {2, 0x60, 0x71, 0x82, 0x93, 0xa4};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x630200c6;
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;
static const __be32 sequence = (__be32)0x44332211;
static const __be32 acknowledgment = (__be32)0x88776655;
static const __be16 window = (__be16)0x3412;

static uint16_t checksum(const unsigned char *bytes, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = (uint16_t)bytes[i] << 8;
        if (i + 1 < length) word |= bytes[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_wire_checksum(const unsigned char *ip, unsigned int tcp_length)
{
    unsigned char pseudo[12 + UINT16_MAX];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
    pseudo[10] = (unsigned char)(tcp_length >> 8);
    pseudo[11] = (unsigned char)tcp_length;
    memcpy(pseudo + 12, ip + (ip[0] & 0x0fU) * 4U, tcp_length);
    return checksum(pseudo, 12U + tcp_length);
}

static void verify(struct sk_buff *skb, const unsigned char *dst,
    const unsigned char *ip_options, unsigned int ip_options_length,
    const unsigned char *tcp_options, unsigned int tcp_options_length,
    const struct ker_ipv4_header_fields *fields, const unsigned char *payload,
    unsigned int payload_length)
{
    unsigned int ihl = 20U + ip_options_length;
    unsigned int thl = 20U + tcp_options_length;
    unsigned int ip_length = ihl + thl + payload_length;
    CHECK(skb && skb->len == ETH_HLEN + ip_length && skb_headroom(skb) == 128 &&
        skb->mac_header == 128 && skb->network_header == 128 + ETH_HLEN &&
        skb->transport_header == 128 + ETH_HLEN + ihl && skb->mac_len == ETH_HLEN);
    const unsigned char *f = skb->data;
    CHECK(!memcmp(f, dst, 6) && !memcmp(f + 6, source_mac, 6) &&
        f[12] == 8 && f[13] == 0);
    const unsigned char *ip = f + ETH_HLEN;
    CHECK(ip[0] == (unsigned char)(0x40U + ihl / 4U) && ip[1] == fields->ds_field &&
        !memcmp(ip + 4, &fields->identification, 2) &&
        !memcmp(ip + 6, &fields->frag_off, 2) &&
        ip[2] == (unsigned char)(ip_length >> 8) && ip[3] == (unsigned char)ip_length &&
        ip[8] == 64 && ip[9] == IPPROTO_TCP &&
        !memcmp(ip + 12, &source_ip, 4) && !memcmp(ip + 16, &destination_ip, 4));
    CHECK(checksum(ip, ihl) == 0 &&
        (!ip_options_length || !memcmp(ip + 20, ip_options, ip_options_length)));
    const unsigned char *tcp = ip + ihl;
    CHECK(!memcmp(tcp, &source_port, 2) && !memcmp(tcp + 2, &destination_port, 2) &&
        !memcmp(tcp + 4, &sequence, 4) && !memcmp(tcp + 8, &acknowledgment, 4) &&
        tcp[12] == (unsigned char)((thl / 4U) << 4) && tcp[13] == 0x12 &&
        !memcmp(tcp + 14, &window, 2) && !memcmp(tcp + 18, "\0\0", 2) &&
        (!tcp_options_length || !memcmp(tcp + 20, tcp_options, tcp_options_length)) &&
        (!payload_length || !memcmp(tcp + thl, payload, payload_length)) &&
        tcp_wire_checksum(ip, thl + payload_length) == 0);
}

static void success_vectors(void)
{
    unsigned char ip_options[40], tcp_options[40], payload[7] = {1,2,3,4,5,6,7};
    for (unsigned int i = 0; i < 40; ++i) {
        ip_options[i] = (unsigned char)(0x81U + i * 3U);
        tcp_options[i] = (unsigned char)(0x42U + i * 5U);
    }
    const unsigned int lens[] = {0, 4, 40};
    const struct ker_ipv4_header_fields zero = {0};
    for (unsigned int i = 0; i < 3; ++i) {
        struct sk_buff *actual = NULL, *raw = NULL;
        CHECK(ker_tcp_ipv4_create_configured(&address, destination_mac, destination_ip,
            source_port, destination_port, sequence, acknowledgment, window, 0x12, 64,
            ip_options, lens[i], tcp_options, lens[i], payload, i, &actual) == 0);
        CHECK(ker_tcp_ipv4_create_headers(&context, source_mac, destination_mac,
            source_ip, destination_ip, source_port, destination_port, sequence,
            acknowledgment, window, 0x12, 64, ip_options, lens[i], tcp_options,
            lens[i], payload, i, &raw) == 0);
        verify(actual, destination_mac, ip_options, lens[i], tcp_options, lens[i],
            &zero, payload, i);
        CHECK(actual->len == raw->len && !memcmp(actual->data, raw->data, actual->len));
        CHECK(ker_skb_free(raw) == 0 && ker_skb_free(actual) == 0);
    }
    struct ker_ipv4_header_fields profile = {.ds_field=0xff,
        .identification=(__be16)0x3412, .frag_off=rte_cpu_to_be_16(0x4000)};
    unsigned char dst[6]; memcpy(dst, destination_mac, 6);
    struct ker_ipv4_header_fields raw_profile = profile;
    struct sk_buff *actual = NULL, *raw = NULL;
    CHECK(ker_tcp_ipv4_create_configured_fields(&address, dst, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, 0x12, 64,
        &profile, ip_options, 40, tcp_options, 40, payload, 5, &actual) == 0);
    CHECK(ker_tcp_ipv4_create_fields(&context, source_mac, dst, source_ip,
        destination_ip, source_port, destination_port, sequence, acknowledgment,
        window, 0x12, 64, &raw_profile, ip_options, 40, tcp_options, 40,
        payload, 5, &raw) == 0);
    verify(actual, destination_mac, ip_options, 40, tcp_options, 40, &profile, payload, 5);
    CHECK(actual->len == raw->len && !memcmp(actual->data, raw->data, actual->len));
    unsigned char saved[ETH_HLEN + 60 + 60 + 5]; memcpy(saved, actual->data, actual->len);
    memset(dst, 0, 6); memset(ip_options, 0, 40); memset(tcp_options, 0, 40);
    memset(payload, 0, sizeof(payload)); memset(device.native->dev_addr_shadow, 0, 6);
    profile.ds_field = 0;
    CHECK(!memcmp(actual->data, saved, actual->len));
    memcpy(device.native->dev_addr_shadow, source_mac, 6);
    CHECK(ker_skb_free(raw) == 0 && ker_skb_free(actual) == 0);
}

static void zero_checksum_vector(void)
{
    unsigned char candidate[2], ip[20] = {0}, tcp[22] = {0}, pseudo[34];
    ip[0] = 0x45; ip[2] = 0; ip[3] = 42; ip[9] = IPPROTO_TCP;
    memcpy(ip + 12, &source_ip, 4); memcpy(ip + 16, &destination_ip, 4);
    memcpy(tcp, &source_port, 2); memcpy(tcp + 2, &destination_port, 2);
    memcpy(tcp + 4, &sequence, 4); memcpy(tcp + 8, &acknowledgment, 4);
    tcp[12] = 0x50; tcp[13] = 0x12; memcpy(tcp + 14, &window, 2);
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
    pseudo[10] = 0; pseudo[11] = sizeof(tcp);
    bool found = false;
    for (unsigned int v = 0; v <= UINT16_MAX; ++v) {
        candidate[0] = (unsigned char)(v >> 8); candidate[1] = (unsigned char)v;
        memcpy(tcp + 20, candidate, 2); memcpy(pseudo + 12, tcp, sizeof(tcp));
        if (checksum(pseudo, sizeof(pseudo)) == 0) { found = true; break; }
    }
    CHECK(found);
    struct sk_buff *skb = NULL;
    CHECK(ker_tcp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, sequence, acknowledgment, window, 0x12, 64,
        NULL, 0, NULL, 0, candidate, sizeof(candidate), &skb) == 0);
    const unsigned char *tcp_bytes = skb->data + ETH_HLEN + 20;
    CHECK(tcp_bytes[16] == 0 && tcp_bytes[17] == 0 &&
        tcp_wire_checksum(skb->data + ETH_HLEN, sizeof(tcp)) == 0);
    CHECK(ker_skb_free(skb) == 0);
}

static void failures(void)
{
    unsigned char options[44] = {0}, payload[4] = {1,2,3,4};
    struct sk_buff *out = (void *)(uintptr_t)0x1234;
    struct ker_ipv4_header_fields good = {0}, bad = {.frag_off=rte_cpu_to_be_16(0x2000)};
    size_t free_before = rte_mempool_avail_count(pool.mbufs);
#define REJECT(code, call) CHECK((call) == (code) && out == (void *)(uintptr_t)0x1234)
    REJECT(-EINVAL, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,0,
        NULL,0,NULL,0,payload,sizeof(payload),&out));
    REJECT(-ENOTSUP, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x32,64,
        NULL,0,NULL,0,payload,sizeof(payload),&out));
    REJECT(-EINVAL, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,2,NULL,0,payload,sizeof(payload),&out));
    REJECT(-EINVAL, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        options,0,NULL,4,payload,sizeof(payload),&out));
    REJECT(-EINVAL, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        options,44,NULL,0,payload,sizeof(payload),&out));
    REJECT(-EINVAL, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,0,options,UINT_MAX,payload,sizeof(payload),&out));
    REJECT(-EMSGSIZE, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        options,0,NULL,0,payload,UINT_MAX,&out));
    REJECT(-ENOSPC, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        options,40,options,40,payload,65415,&out));
    REJECT(-EMSGSIZE, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        options,40,options,40,payload,65416,&out));
    REJECT(-ENOTSUP, ker_tcp_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        &bad,NULL,0,NULL,0,payload,sizeof(payload),&out));
    struct ker_ipv4_address *none = NULL;
    REJECT(-ENOTSUP, ker_tcp_ipv4_create_configured_fields(none,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        &bad,NULL,0,NULL,0,payload,sizeof(payload),&out));
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == free_before);
    address.native->dead = 1;
    REJECT(-ESHUTDOWN, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,0,NULL,0,payload,sizeof(payload),&out));
    address.native->dead = 0;
    ker_memory_fail_after(0);
    REJECT(-ENOMEM, ker_tcp_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        &good,NULL,0,NULL,0,payload,sizeof(payload),&out));
    ker_memory_fail_after(-1);
    struct rte_mbuf *held[POOL_SIZE]; unsigned int count = 0;
    while (count < POOL_SIZE && (held[count] = ker_packet_alloc(&pool)) != NULL) ++count;
    CHECK(count == POOL_SIZE);
    REJECT(-ENOMEM, ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,0,NULL,0,payload,sizeof(payload),&out));
    ker_packet_free(held[--count]);
    CHECK(ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,0,NULL,0,payload,sizeof(payload),&out) == 0);
    CHECK(ker_skb_free(out) == 0);
    while (count) ker_packet_free(held[--count]);
    CHECK(context.live == 0 && rte_mempool_avail_count(pool.mbufs) == POOL_SIZE);
#undef REJECT
}

static void *foreign_worker(void *unused)
{
    (void)unused;
    struct sk_buff *out = (void *)(uintptr_t)0x1234;
    CHECK(ker_tcp_ipv4_create_configured(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        NULL,0,NULL,0,NULL,0,&out) == -EXDEV);
    CHECK(out == (void *)(uintptr_t)0x1234);
    struct ker_ipv4_header_fields fields = {0};
    CHECK(ker_tcp_ipv4_create_configured_fields(&address,destination_mac,destination_ip,
        source_port,destination_port,sequence,acknowledgment,window,0x12,64,
        &fields,NULL,0,NULL,0,NULL,0,&out) == -EXDEV);
    CHECK(out == (void *)(uintptr_t)0x1234);
    return NULL;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool,"tcp_configured",POOL_SIZE,0,2048,SOCKET_ID_ANY)==0);
    CHECK(ker_skb_context_init(&context,&pool,"tcp_configured_skb")==0);
    CHECK(ker_eth_device_init(&device,&context,"tcp-cfg",41,source_mac)==0);
    CHECK(ker_ipv4_address_init(&address,&device,source_ip,24)==0);
    success_vectors(); zero_checksum_vector(); failures();
    pthread_t thread;
    CHECK(pthread_create(&thread,NULL,foreign_worker,NULL)==0 && pthread_join(thread,NULL)==0);
    CHECK(ker_ipv4_address_cleanup(&address)==0 && ker_eth_device_cleanup(&device)==0 &&
        ker_skb_context_cleanup(&context)==0 && rte_mempool_avail_count(pool.mbufs)==POOL_SIZE &&
        ker_packet_pool_cleanup(&pool)==0 && ker_memory_shutdown()==0 && rte_eal_cleanup()==0);
    puts("configured TCP constructors: wire checksums, rollback and ownership passed");
    return 0;
}
