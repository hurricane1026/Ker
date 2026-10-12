#ifndef KER_RUNTIME_IPV4_FIELDS_H
#define KER_RUNTIME_IPV4_FIELDS_H
#include "runtime/skb.h"
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

/* Wire-order IPv4 profile copied into constructors. ds_field is an opaque byte;
 * identification is copied verbatim. frag_off permits exactly zero or DF;
 * MF, offsets, reserved bits and combinations are rejected. This does not
 * provide fragmentation, ID-generation, DSCP/ECN, or path-MTU policy. */
struct ker_ipv4_header_fields {
    uint8_t ds_field;
    __be16 identification;
    __be16 frag_off;
};

static inline int ker_ipv4_header_fields_validate(
    const struct ker_ipv4_header_fields *fields)
{
    if (!fields)
        return -EINVAL;
    if (fields->frag_off != 0 && fields->frag_off != htons(0x4000U))
        return -ENOTSUP;
    return 0;
}

static inline struct ker_ipv4_header_fields ker_ipv4_header_fields_snapshot(
    const struct ker_ipv4_header_fields *fields)
{
    return (struct ker_ipv4_header_fields){
        .ds_field = fields->ds_field,
        .identification = fields->identification,
        .frag_off = fields->frag_off
    };
}

static inline void ker_ipv4_header_fields_apply(uint8_t *ip,
    const struct ker_ipv4_header_fields *fields)
{
    ip[1] = fields->ds_field;
    memcpy(ip + 4, &fields->identification, sizeof(fields->identification));
    memcpy(ip + 6, &fields->frag_off, sizeof(fields->frag_off));
}
#endif
