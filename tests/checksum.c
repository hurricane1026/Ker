#include "check.h"
#include <ker/checksum.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/checksum.h>

/* Independent byte-at-a-time reference in network order. */
static uint32_t reference_sum(const uint8_t *data, size_t length)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < length; ++i)
        sum += (uint32_t)data[i] << ((i & 1) ? 0 : 8);
    return sum;
}

static uint16_t reference_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t network_value(uint16_t sum)
{
    uint8_t bytes[2];
    memcpy(bytes, &sum, 2);
    return (uint16_t)((uint16_t)bytes[0] << 8 | bytes[1]);
}

static void test_vectors(void)
{
    const uint8_t rfc1071[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint8_t ipv4[] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
                     0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7};
    uint16_t sum;
    CHECK(ker_inet_checksum(rfc1071, sizeof(rfc1071), &sum) == 0);
    CHECK(network_value(sum) == 0x220d);
    CHECK(ker_inet_checksum(ipv4, sizeof(ipv4), &sum) == 0);
    CHECK(network_value(sum) == 0xb861);
    memcpy(ipv4 + 10, &sum, 2);
    CHECK(ker_inet_checksum(ipv4, sizeof(ipv4), &sum) == 0);
    CHECK(sum == 0);
    ipv4[8]--;
    CHECK(ker_inet_checksum(ipv4, sizeof(ipv4), &sum) == 0);
    CHECK(sum != 0);
}

static void test_lengths_and_alignment(void)
{
    uint8_t bytes[1544];
    uint32_t random = 0x12345678;
    for (unsigned int pattern = 0; pattern < 3; ++pattern) {
        for (size_t i = 0; i < sizeof(bytes); ++i) {
            random = random * 1664525 + 1013904223;
            bytes[i] = pattern == 0 ? 0 : pattern == 1 ? 0xff : (uint8_t)(random >> 24);
        }
        for (size_t offset = 0; offset < 8; ++offset) {
            const uint8_t *data = bytes + offset;
            for (size_t length = 0; length <= 1536; ++length) {
                uint16_t sum;
                uint16_t expected = reference_fold(reference_sum(data, length));
                CHECK(ker_inet_checksum(data, length, &sum) == 0);
                CHECK(network_value(sum) == expected);
                CHECK(network_value(csum_fold(csum_partial(data, (int)length, 0))) == expected);
            }
            for (unsigned int ihl = 5; ihl <= 15; ++ihl)
                CHECK(network_value(ip_fast_csum(data, ihl)) ==
                      reference_fold(reference_sum(data, ihl * 4)));
            /* Fragment boundaries can be odd: csum_block_add must realign. */
            for (size_t split = 0; split <= 65; ++split) {
                __wsum a = csum_partial(data, (int)split, 0);
                __wsum b = csum_partial(data + split, 127 - (int)split, 0);
                CHECK(network_value(csum_fold(csum_block_add(a, b, (int)split))) ==
                      reference_fold(reference_sum(data, 127)));
                if (!(split & 1))
                    CHECK(network_value(csum_fold(csum_partial(data + split,
                          127 - (int)split, a))) == reference_fold(reference_sum(data, 127)));
            }
        }
    }
}

static void test_transport(void)
{
    const uint8_t src[4] = {192, 0, 2, 1};
    const uint8_t dst[4] = {198, 51, 100, 2};
    uint8_t bytes[UINT16_MAX + 8];
    for (size_t i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t)(i * 73 + 31);
    for (size_t offset = 0; offset < 8; ++offset) {
        for (size_t length = 0; length <= 1024; ++length) {
            uint8_t pseudo[12];
            uint16_t sum;
            memcpy(pseudo, src, 4);
            memcpy(pseudo + 4, dst, 4);
            pseudo[8] = 0;
            pseudo[9] = length & 1 ? 6 : 17;
            pseudo[10] = (uint8_t)(length >> 8);
            pseudo[11] = (uint8_t)length;
            CHECK(ker_ipv4_transport_checksum(src, dst, pseudo[9], bytes + offset, length, &sum) == 0);
            CHECK(network_value(sum) == reference_fold(reference_sum(pseudo, 12) +
                                                      reference_sum(bytes + offset, length)));
        }
    }
    uint16_t sum;
    uint8_t pseudo[12] = {192, 0, 2, 1, 198, 51, 100, 2, 0, 17, 0xff, 0xff};
    CHECK(ker_ipv4_transport_checksum(src, dst, 17, bytes, UINT16_MAX, &sum) == 0);
    CHECK(network_value(sum) == reference_fold(reference_sum(pseudo, 12) +
                                              reference_sum(bytes, UINT16_MAX)));
    /* UDP on-the-wire round trip; the checksum field is included on validation. */
    uint8_t udp[11] = {0x12, 0x34, 0x56, 0x78, 0, 11, 0, 0, 'a', 'b', 'c'};
    CHECK(ker_ipv4_transport_checksum(src, dst, 17, udp, sizeof(udp), &sum) == 0);
    memcpy(udp + 6, &sum, 2);
    CHECK(ker_ipv4_transport_checksum(src, dst, 17, udp, sizeof(udp), &sum) == 0);
    CHECK(sum == 0);
    udp[10] ^= 1;
    CHECK(ker_ipv4_transport_checksum(src, dst, 17, udp, sizeof(udp), &sum) == 0);
    CHECK(sum != 0);
}

static void test_partial_seeds(void)
{
    const uint32_t seeds[] = {0, 1, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff};
    uint8_t bytes[136];
    memset(bytes, 0xff, sizeof(bytes));
    for (size_t offset = 0; offset < 8; ++offset) {
        for (size_t length = 0; length <= 128; ++length) {
            for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i) {
                uint8_t seed_bytes[4];
                memcpy(seed_bytes, &seeds[i], 4);
                uint16_t expected = reference_fold(reference_sum(bytes + offset, length) +
                                                   reference_sum(seed_bytes, 4));
                CHECK(network_value(csum_fold(csum_partial(bytes + offset,
                      (int)length, seeds[i]))) == expected);
            }
        }
    }
}

static void test_errors(void)
{
    uint16_t result = 0x1234;
    const uint8_t address[4] = {0};
    CHECK(ker_inet_checksum(NULL, 1, &result) == -EINVAL);
    CHECK(result == 0x1234);
    CHECK(ker_inet_checksum(address, (size_t)INT_MAX + 1, &result) == -EOVERFLOW);
    CHECK(result == 0x1234);
    CHECK(ker_inet_checksum(address, 1, NULL) == -EINVAL);
    CHECK(ker_ipv4_transport_checksum(address, address, 17, address,
                                    (size_t)UINT16_MAX + 1, &result) == -EMSGSIZE);
    CHECK(result == 0x1234);
    CHECK(ker_ipv4_transport_checksum(NULL, address, 17, address, 1, &result) == -EINVAL);
    CHECK(ker_ipv4_transport_checksum(address, NULL, 17, address, 1, &result) == -EINVAL);
    CHECK(ker_ipv4_transport_checksum(address, address, 17, NULL, 1, &result) == -EINVAL);
    CHECK(ker_ipv4_transport_checksum(address, address, 17, address, 1, NULL) == -EINVAL);
    CHECK(ker_inet_checksum(NULL, 0, &result) == 0);
    CHECK(result == UINT16_MAX);
    CHECK(ker_ipv4_transport_checksum(address, address, 0, NULL, 0, &result) == 0);
    CHECK(result == UINT16_MAX);
    CHECK(ker_capabilities() & KER_CAP_CHECKSUM);
    CHECK(!(ker_capabilities() & (KER_CAP_DPDK_IO | KER_CAP_LINUX_STACK | KER_CAP_IPV4 | KER_CAP_UDP | KER_CAP_TCP)));
}

int main(void)
{
    test_vectors();
    test_lengths_and_alignment();
    test_transport();
    test_partial_seeds();
    test_errors();
    puts("checksum: vectors, alignment, carry, fragments and IPv4 pseudo-headers passed");
    return 0;
}
