#ifndef KER_COMPAT_SKB_CONFIG_H
#define KER_COMPAT_SKB_CONFIG_H
#include <rte_common.h>
#include <limits.h>
#include <linux/compiler.h>
#if __SIZEOF_LONG__ != 8 || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error The initial linear skb slice requires a 64 bit little endian target
#endif
#if defined(CONFIG_MAX_SKB_FRAGS) && CONFIG_MAX_SKB_FRAGS != 17
#error Unsupported MAX_SKB_FRAGS configuration
#endif
#ifndef CONFIG_MAX_SKB_FRAGS
#define CONFIG_MAX_SKB_FRAGS 17
#endif
#define BITS_PER_LONG (__SIZEOF_LONG__ * CHAR_BIT)
#define SMP_CACHE_BYTES RTE_CACHE_LINE_SIZE
#define ALIGN(value, alignment) RTE_ALIGN_CEIL(value, alignment)
#define __bitwise
#define __aligned(value) __attribute__((aligned(value)))
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "kernel build invariant")
#define BUG() abort()
#define BUG_ON(condition) WARN_ON_ONCE(condition)
#define WARN_ON(condition) WARN_ON_ONCE(condition)
#define DEBUG_NET_WARN_ON_ONCE(condition) WARN_ON_ONCE(condition)
#endif
