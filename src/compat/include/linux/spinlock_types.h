#ifndef KER_COMPAT_LINUX_SPINLOCK_TYPES_H
#define KER_COMPAT_LINUX_SPINLOCK_TYPES_H
#include <linux/types.h>
typedef struct { bool held; } spinlock_t;
#define DEFINE_SPINLOCK(name) spinlock_t name = { .held = false }
#endif
