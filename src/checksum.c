#include <ker/checksum.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/checksum.h>

int ker_inet_checksum(const void *data, size_t length, uint16_t *result)
{
    if (!result || (!data && length))
        return -EINVAL;
    if (length > INT_MAX)
        return -EOVERFLOW;
    *result = ip_compute_csum(data, (int)length);
    return 0;
}

int ker_ipv4_transport_checksum(const uint8_t src[4], const uint8_t dst[4],
    uint8_t protocol, const void *segment, size_t length, uint16_t *result)
{
    __be32 saddr, daddr;
    __wsum sum;
    if (!src || !dst || !result || (!segment && length))
        return -EINVAL;
    if (length > UINT16_MAX)
        return -EMSGSIZE;
    memcpy(&saddr, src, sizeof(saddr));
    memcpy(&daddr, dst, sizeof(daddr));
    sum = csum_partial(segment, (int)length, 0);
    *result = csum_tcpudp_magic(saddr, daddr, (uint32_t)length, protocol, sum);
    return 0;
}
