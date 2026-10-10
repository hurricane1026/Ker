#ifndef KER_COMPAT_LINUX_EXPORT_H
#define KER_COMPAT_LINUX_EXPORT_H
/* Kernel module export tables have no userspace counterpart. */
#define EXPORT_SYMBOL(symbol)
#define EXPORT_SYMBOL_GPL(symbol)
#endif
