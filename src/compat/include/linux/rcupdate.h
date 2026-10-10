#ifndef KER_COMPAT_LINUX_RCUPDATE_H
#define KER_COMPAT_LINUX_RCUPDATE_H
#include <linux/compiler.h>
/* Pointer publication only. Grace periods, readers and reclamation are NOT
 * implemented. The timer runtime exclusively owns its trees on one thread. */
#define rcu_assign_pointer(ptr, value) __atomic_store_n(&(ptr), (value), __ATOMIC_RELEASE)
#define rcu_dereference_raw(ptr) __atomic_load_n(&(ptr), __ATOMIC_ACQUIRE)
#endif
