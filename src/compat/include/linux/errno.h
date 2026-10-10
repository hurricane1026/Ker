#ifndef KER_COMPAT_LINUX_ERRNO_H
#define KER_COMPAT_LINUX_ERRNO_H
/* Include Linux UAPI values directly: glibc's errno.h can itself include
 * linux/errno.h, so forwarding to errno.h here would create an include cycle. */
#include <asm-generic/errno.h>
#endif
