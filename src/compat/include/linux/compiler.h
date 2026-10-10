#ifndef KER_COMPAT_LINUX_COMPILER_H
#define KER_COMPAT_LINUX_COMPILER_H

#include <stdbool.h>
#include <stddef.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define __force
#define __user
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))

/* Only scalar accesses needed by the imported trees are supported. These
 * operations do not make concurrent mutations of a tree safe. */
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define WRITE_ONCE(x, value) __atomic_store_n(&(x), (value), __ATOMIC_RELAXED)

#endif
