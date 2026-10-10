#ifndef KER_COMPAT_LINUX_BITOPS_H
#define KER_COMPAT_LINUX_BITOPS_H
#include <linux/types.h>
static inline u32 ror32(u32 word, unsigned int shift)
{
    shift &= 31;
    return (word >> shift) | (word << ((32 - shift) & 31));
}
#endif
