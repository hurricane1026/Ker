#ifndef KER_COMPAT_ASM_BYTEORDER_H
#define KER_COMPAT_ASM_BYTEORDER_H
#include <endian.h>
/* libc defines both endian constants; kernel code tests their presence. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#undef __BIG_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#undef __LITTLE_ENDIAN
#else
#error Unsupported byte order for the Linux checksum port
#endif
#endif
