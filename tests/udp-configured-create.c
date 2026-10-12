#include "check.h"
#include "eal.h"
#include "runtime/udp-create.h"
#include "runtime/ipv4-address.h"
#include "runtime/ethernet.h"
#include "runtime/memory.h"
#include <errno.h>
#include <pthread.h>

#define POOL_SIZE 31U
static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static const unsigned char source_mac[ETH_ALEN] = {2, 0x10, 0x21, 0x32, 0x43, 0x54};
static const unsigned char destination_mac[ETH_ALEN] = {2, 0x60, 0x71, 0x82, 0x93, 0xa4};
static const __be32 source_ip = (__be32)0x010200c0;
static const __be32 destination_ip = (__be32)0x630200c6; /* Outside the local /24. */
static const __be16 source_port = (__be16)0x3412;
static const __be16 destination_port = (__be16)0x7856;

static uint16_t byte_checksum(const unsigned char *bytes, size_t length)
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
static uint16_t udp_wire_checksum(const unsigned char *ip, unsigned int udp_length)
{
    unsigned char pseudo[12 + UINT16_MAX];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0; pseudo[9] = IPPROTO_UDP;
    pseudo[10] = (unsigned char)(udp_length >> 8);
    pseudo[11] = (unsigned char)udp_length;
    memcpy(pseudo + 12, ip + (ip[0] & 0x0fU) * 4U, udp_length);
    return byte_checksum(pseudo, 12U + udp_length);
}
static void verify(struct sk_buff *skb, const unsigned char *destination,
    const unsigned char *options, unsigned int options_length,
    const struct ker_ipv4_header_fields *fields, const unsigned char *payload,
    unsigned int payload_length)
{
    const unsigned int ihl = 20U + options_length;
    const unsigned int udp_length = 8U + payload_length;
    CHECK(skb && skb->len == ETH_HLEN + ihl + udp_length &&
        skb_headroom(skb) == 128 && skb->mac_header == 128 &&
        skb->network_header == 128 + ETH_HLEN &&
        skb->transport_header == 128 + ETH_HLEN + ihl && skb->mac_len == ETH_HLEN);
    const unsigned char *frame = skb->data;
    CHECK(!memcmp(frame, destination, ETH_ALEN) && !memcmp(frame + 6, source_mac, ETH_ALEN));
    CHECK(frame[12] == 0x08 && frame[13] == 0x00);
    const unsigned char *ip = frame + ETH_HLEN;
    CHECK(ip[0] == (unsigned char)(0x40U + ihl / 4U));
    CHECK(ip[1] == fields->ds_field &&
        !memcmp(ip + 4, &fields->identification, 2) &&
        !memcmp(ip + 6, &fields->frag_off, 2));
    CHECK(ip[2] == (unsigned char)((ihl + udp_length) >> 8) &&
        ip[3] == (unsigned char)(ihl + udp_length) && ip[8] == 64 &&
        ip[9] == IPPROTO_UDP && !memcmp(ip + 12, &source_ip, 4) &&
        !memcmp(ip + 16, &destination_ip, 4));
    CHECK(byte_checksum(ip, ihl) == 0 &&
        (!options_length || !memcmp(ip + 20, options, options_length)));
    const unsigned char *udp = ip + ihl;
    CHECK(!memcmp(udp, &source_port, 2) && !memcmp(udp + 2, &destination_port, 2) &&
        udp[4] == (unsigned char)(udp_length >> 8) && udp[5] == (unsigned char)udp_length &&
        (!payload_length || !memcmp(udp + 8, payload, payload_length)) &&
        udp_wire_checksum(ip, udp_length) == 0);
}
static void success_vectors(void)
{
    unsigned char options[40], payload[7] = {1, 2, 3, 4, 5, 6, 7};
    for (unsigned int i = 0; i < sizeof(options); ++i) options[i] = (unsigned char)(0x80U + i * 3U);
    const unsigned int option_lengths[] = {0, 4, 40};
    const unsigned int payload_lengths[] = {0, 3, 4};
    const struct ker_ipv4_header_fields zero = {0};
    for (unsigned int i = 0; i < 3; ++i) {
        struct sk_buff *actual = NULL, *raw = NULL;
        CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
            source_port, destination_port, 64, options, option_lengths[i],
            payload, payload_lengths[i], &actual) == 0);
        CHECK(ker_udp_ipv4_create_ip_options(&context, source_mac, destination_mac,
            source_ip, destination_ip, source_port, destination_port, 64,
            options, option_lengths[i], payload, payload_lengths[i], &raw) == 0);
        verify(actual, destination_mac, options, option_lengths[i], &zero,
            payload, payload_lengths[i]);
        CHECK(actual->len == raw->len && !memcmp(actual->data, raw->data, actual->len));
        CHECK(ker_skb_free(raw) == 0 && ker_skb_free(actual) == 0);
    }

    struct ker_ipv4_header_fields profile = {
        .ds_field = 0xff, .identification = (__be16)0x3412,
        .frag_off = rte_cpu_to_be_16(0x4000)
    };
    struct ker_ipv4_header_fields raw_profile = profile;
    unsigned char mutable_destination[ETH_ALEN];
    memcpy(mutable_destination, destination_mac, ETH_ALEN);
    struct sk_buff *actual = NULL, *raw = NULL;
    CHECK(ker_udp_ipv4_create_configured_fields(&address, mutable_destination,
        destination_ip, source_port, destination_port, 64, &profile,
        options, sizeof(options), payload, 5, &actual) == 0);
    CHECK(ker_udp_ipv4_create_fields(&context, source_mac, mutable_destination,
        source_ip, destination_ip, source_port, destination_port, 64, &raw_profile,
        options, sizeof(options), payload, 5, &raw) == 0);
    verify(actual, destination_mac, options, sizeof(options), &profile, payload, 5);
    CHECK(actual->len == raw->len && !memcmp(actual->data, raw->data, actual->len));
    unsigned char saved[ETH_HLEN + 20 + 40 + 8 + 5];
    memcpy(saved, actual->data, actual->len);
    memset(options, 0, sizeof(options)); memset(payload, 0, sizeof(payload));
    memset(mutable_destination, 0, sizeof(mutable_destination));
    memset(device.native->dev_addr_shadow, 0, ETH_ALEN);
    profile.ds_field = 0; profile.identification = 0;
    CHECK(!memcmp(actual->data, saved, actual->len));
    memcpy(device.native->dev_addr_shadow, source_mac, ETH_ALEN);
    CHECK(ker_skb_free(raw) == 0 && ker_skb_free(actual) == 0);
}

static void failure_vectors(void)
{
    unsigned char options[44] = {0}, payload[4] = {9, 8, 7, 6};
    struct sk_buff *sentinel = (void *)(uintptr_t)0x1234;
    const struct ker_ipv4_header_fields good = {0};
    const struct ker_ipv4_header_fields bad_profiles[] = {
        {.frag_off = rte_cpu_to_be_16(0x2000)},
        {.frag_off = rte_cpu_to_be_16(0x0001)},
        {.frag_off = rte_cpu_to_be_16(0x8000)}
    };
    size_t free_before = rte_mempool_avail_count(pool.mbufs);
    CHECK(ker_udp_ipv4_create_configured(NULL, destination_mac, destination_ip,
        source_port, destination_port, 0, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured(&address, NULL, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured_fields(NULL, destination_mac, destination_ip,
        source_port, destination_port, 64, &bad_profiles[0], NULL, 0, payload,
        sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_udp_ipv4_create_configured_fields(NULL, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, NULL, 0, payload,
        sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 0, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, options, UINT_MAX, payload,
        sizeof(payload), &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, UINT_MAX,
        &sentinel) == -EMSGSIZE);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, options, 40, payload, 65467,
        &sentinel) == -ENOSPC);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, options, 40, payload, 65468,
        &sentinel) == -EMSGSIZE);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 4, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, options, 2, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        rte_mempool_avail_count(pool.mbufs) == free_before);

    /* API argument/profile errors precede stale address inspection. */
    void *saved_ip_ptr = rcu_dereference_raw(device.native->ip_ptr);
    rcu_assign_pointer(device.native->ip_ptr, NULL);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    for (size_t i = 0; i < sizeof(bad_profiles) / sizeof(bad_profiles[0]); ++i)
        CHECK(ker_udp_ipv4_create_configured_fields(&address, destination_mac,
            destination_ip, source_port, destination_port, 64, &bad_profiles[i],
            NULL, 0, payload, sizeof(payload), &sentinel) == -ENOTSUP);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 0, NULL, 0, payload, sizeof(payload),
        &sentinel) == -EINVAL);
    rcu_assign_pointer(device.native->ip_ptr, saved_ip_ptr);
    struct in_device *native_address = address.native;
    native_address->dead = 1;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    native_address->dead = 0;

    /* Broken address associations are shutdown errors, distinct from bad API
     * arguments and live-but-unsupported address profiles. */
    struct in_device *saved_native = address.native;
    struct ker_eth_device *saved_device = address.device;
    address.native = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    address.native = saved_native;
    address.device = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    address.device = saved_device;

    struct in_ifaddr *saved_ifa_list = native_address->ifa_list;
    native_address->ifa_list = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    native_address->ifa_list = saved_ifa_list;
    struct in_ifaddr *ifa = native_address->ifa_list;
    struct in_device wrong_address = {0};
    struct in_device *saved_ifa_dev = ifa->ifa_dev;
    ifa->ifa_dev = &wrong_address;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ESHUTDOWN);
    ifa->ifa_dev = saved_ifa_dev;
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        rte_mempool_avail_count(pool.mbufs) == free_before);

    ker_memory_fail_after(0);
    CHECK(ker_udp_ipv4_create_configured_fields(&address, destination_mac,
        destination_ip, source_port, destination_port, 64, &good, NULL, 0,
        payload, sizeof(payload), &sentinel) == -ENOMEM);
    ker_memory_fail_after(-1);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0 &&
        rte_mempool_avail_count(pool.mbufs) == free_before);

    struct rte_mbuf *held[POOL_SIZE]; unsigned int count = 0;
    while (count < POOL_SIZE && (held[count] = ker_packet_alloc(&pool)) != NULL) ++count;
    CHECK(count == POOL_SIZE);
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &sentinel) == -ENOMEM);
    CHECK(sentinel == (void *)(uintptr_t)0x1234 && context.live == 0);
    ker_packet_free(held[--count]);
    struct sk_buff *retry = NULL;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, payload, sizeof(payload),
        &retry) == 0 && retry);
    CHECK(ker_skb_free(retry) == 0);
    while (count) ker_packet_free(held[--count]);
    CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_SIZE && context.live == 0);
}

static void *foreign_worker(void *arg)
{
    (void)arg;
    const struct ker_ipv4_header_fields fields = {0};
    struct sk_buff *out = (void *)(uintptr_t)0x1234;
    CHECK(ker_udp_ipv4_create_configured(&address, destination_mac, destination_ip,
        source_port, destination_port, 64, NULL, 0, NULL, 0, &out) == -EXDEV);
    CHECK(ker_udp_ipv4_create_configured_fields(&address, destination_mac,
        destination_ip, source_port, destination_port, 64, &fields, NULL, 0,
        NULL, 0, &out) == -EXDEV && out == (void *)(uintptr_t)0x1234);
    return NULL;
}

int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    CHECK(ker_packet_pool_init(&pool, "udp_configured", POOL_SIZE, 0,
        2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "udp_configured_skb") == 0);
    CHECK(ker_eth_device_init(&device, &context, "udp-cfg", 41, source_mac) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, source_ip, 24) == 0);
    success_vectors();
    failure_vectors();
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, foreign_worker, NULL) == 0 &&
        pthread_join(thread, NULL) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_SIZE &&
        ker_packet_pool_cleanup(&pool) == 0 && ker_memory_shutdown() == 0 &&
        rte_eal_cleanup() == 0);
    puts("configured UDP constructors: snapshot, wire checksums, rollback and ownership passed");
    return 0;
}
