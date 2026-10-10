#ifndef KER_COMPAT_LINUX_TYPES_H
#define KER_COMPAT_LINUX_TYPES_H

#include <stdint.h>
#include <linux/compiler.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;
typedef u16 __be16;
typedef u32 __be32;
typedef u16 __sum16;
typedef u32 __wsum;
typedef s64 ktime_t;
typedef u32 gfp_t;
typedef struct { int counter; } atomic_t;

_Static_assert(sizeof(unsigned short) == 2, "Linux checksum requires 16 bit short");
_Static_assert(sizeof(unsigned int) == 4, "Linux checksum requires 32 bit int");

#endif
