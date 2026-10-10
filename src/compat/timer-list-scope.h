#ifndef KER_COMPAT_TIMER_LIST_SCOPE_H
#define KER_COMPAT_TIMER_LIST_SCOPE_H
/* Include only in kernel translation units, after their host headers. POSIX
 * already has timer_delete(timer_t); never redeclare or globally replace it in
 * the private interface header. Kernel function bodies remain unchanged. */
#define timer_delete ker_linux_timer_delete_native
#endif
