#ifndef KER_COMPAT_LINUX_BUG_H
#define KER_COMPAT_LINUX_BUG_H
#include <stdio.h>
#include <stdlib.h>
#include <linux/compiler.h>
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
