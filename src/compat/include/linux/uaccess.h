#ifndef KER_COMPAT_LINUX_UACCESS_H
#define KER_COMPAT_LINUX_UACCESS_H
#include <string.h>
#include <linux/types.h>
/* Deliberately unresolved. Any imported code that tries to use Linux user
 * copy semantics fails to link until fault handling is implemented. */
#define copy_from_user ker_linux_copy_from_user_unimplemented
#define copy_to_user ker_linux_copy_to_user_unimplemented
unsigned long copy_from_user(void *dst, const void *src, unsigned long bytes);
unsigned long copy_to_user(void *dst, const void *src, unsigned long bytes);
#endif
