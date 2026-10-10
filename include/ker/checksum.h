#ifndef KER_CHECKSUM_H
#define KER_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>
#include <ker/ker.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internet checksum implemented by Linux lib/checksum.c.
 * Writes the complemented checksum in NETWORK BYTE ORDER: memcpy the result
 * into the packet, without htons(). Zero the packet checksum field first.
 * A checksummed valid packet produces zero. NULL data is allowed only for
 * zero length. Returns 0 or negative errno; failure leaves result unchanged.
 * length must fit INT_MAX. result must be non-NULL. */
KER_API int ker_inet_checksum(const void *data, size_t length, uint16_t *result);

/* IPv4 pseudo-header plus the supplied transport segment (header + payload).
 * src/dst contain four address bytes in network order; length <= UINT16_MAX.
 * protocol is the IP protocol number (e.g. 6 for TCP, 17 for UDP).
 * Result has the same byte order and error convention as ker_inet_checksum.
 * A computed UDP checksum of zero must be encoded as 0xffff by the caller;
 * this primitive does not implement UDP's checksum-omitted policy. */
KER_API int ker_ipv4_transport_checksum(const uint8_t src[4], const uint8_t dst[4],
    uint8_t protocol, const void *segment, size_t length, uint16_t *result);

#ifdef __cplusplus
}
#endif

#endif
