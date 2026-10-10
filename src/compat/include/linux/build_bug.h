#ifndef KER_COMPAT_LINUX_BUILD_BUG_H
#define KER_COMPAT_LINUX_BUILD_BUG_H
#include <linux/compiler.h>
#define static_assert _Static_assert
#endif
