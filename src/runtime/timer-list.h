#ifndef KER_RUNTIME_TIMER_LIST_H
#define KER_RUNTIME_TIMER_LIST_H
#include "ker/linux_timer_list.h"
#include "runtime/timer.h"
/* Stable caller-owned adapter, typically embedded alongside a kernel object.
 * native points at its unchanged timer_list field. No Linux layout changes,
 * cb reuse, heap allocation, global timer wheel or cross-worker migration. */
struct ker_timer_list {
    struct timer_list *native;
    struct ker_timer backing;
    struct ker_runtime *runtime;
    struct hlist_head pending;
    unsigned int lcore;
    bool running;
    bool scoping;
};
/* Worker-local HZ=1000; initialized native storage must be zero. */
int ker_timer_list_init(struct ker_timer_list *, struct ker_runtime *, struct timer_list *,
    void (*)(struct timer_list *));
/* Empty, offline clock only; enables wrap-aware jiffies epochs without changing
 * the monotonic-ns scheduler. No bindings or pending generic timers allowed. */
int ker_timer_list_set_epoch(struct ker_runtime *, unsigned long origin);
int ker_timer_list_now(struct ker_timer_list *, unsigned long *ticks);
/* Linux 0/1 previous-pending semantics, negative errno on invalid public calls.
 * Native functions in a scope are fail-closed for invalid timer/horizon use. */
int ker_timer_list_mod(struct ker_timer_list *, unsigned long expires);
int ker_timer_list_delete(struct ker_timer_list *);
int ker_timer_list_shutdown(struct ker_timer_list *);
/* Scoped entry into unchanged kernel functions using this single native timer.
 * May call native mod/delete/reduce/pending and read jiffies. Callback delivery
 * installs the same scope automatically. No polling/reentrant call scope. */
typedef int (*ker_timer_list_fn)(void *);
int ker_timer_list_call(struct ker_timer_list *, ker_timer_list_fn, void *);
/* Requires not pending; callback may clean up its own inactive timer, then free
 * its enclosing object. Generic call scopes cannot destroy the adapter. */
int ker_timer_list_cleanup(struct ker_timer_list *);
#endif
