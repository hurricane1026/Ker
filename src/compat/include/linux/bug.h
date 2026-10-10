#ifndef KER_COMPAT_LINUX_BUG_H
#define KER_COMPAT_LINUX_BUG_H
#include <stdio.h>
#include <stdlib.h>
#include <linux/compiler.h>
/* Preserve upstream refcount saturation: report the first warning at each
 * call site and keep the counter saturated instead of aborting. */
#define WARN_ONCE(condition, ...) ({ \
    static bool ker_warned; \
    bool ker_warning = !!(condition); \
    if (ker_warning && !__atomic_exchange_n(&ker_warned, true, __ATOMIC_RELAXED)) \
        fprintf(stderr, __VA_ARGS__); \
    ker_warning; \
})
/* Invalid queue operations would corrupt memory. Fail deterministically in
 * release builds too, rather than continuing past a kernel warning. */
#define WARN_ON_ONCE(condition) ({ \
    bool ker_bad_condition = !!(condition); \
    if (unlikely(ker_bad_condition)) { \
        fprintf(stderr, "ker: kernel invariant failed at %s:%d: %s\n", \
                __FILE__, __LINE__, #condition); \
        abort(); \
    } \
    ker_bad_condition; \
})
#endif
