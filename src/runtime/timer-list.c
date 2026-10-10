#include "runtime/timer-list.h"
#include <rte_lcore.h>
#include <limits.h>
#include <errno.h>
#define NS_PER_TICK INT64_C(1000000)
struct firing { struct ker_timer_list *timer; bool removed; };
static _Thread_local struct ker_timer_list *active;
static _Thread_local struct firing *firing;
static int valid(struct ker_timer_list *timer)
{
    if (!timer || !timer->native || !timer->runtime) return -EINVAL;
    if (rte_lcore_id() != timer->lcore) return -EXDEV;
    if (!timer->runtime->native_owned || timer->runtime->native_lcore != timer->lcore ||
        timer->runtime->now_ns < 0 || (timer->native->flags & ~TIMER_PINNED)) return -EINVAL;
    BUG_ON(!!timer_pending(timer->native) != !!timer->backing.owner);
    return 0;
}
static unsigned long ticks(struct ker_runtime *runtime)
{
    return runtime->jiffies_base + (unsigned long)(runtime->now_ns / NS_PER_TICK);
}
unsigned long ker_linux_timer_jiffies(void)
{
    BUG_ON(valid(active));
    return ticks(active->runtime);
}
static int deadline(struct ker_timer_list *timer, unsigned long expires, int64_t *ns)
{
    unsigned long now = ticks(timer->runtime);
    if (time_before_eq(expires, now)) { *ns = timer->runtime->now_ns; return 0; }
    unsigned long delta = expires - now;
    int64_t base = timer->runtime->now_ns - timer->runtime->now_ns % NS_PER_TICK;
    if (delta > (unsigned long)((INT64_MAX - base) / NS_PER_TICK)) return -EOVERFLOW;
    *ns = base + (int64_t)delta * NS_PER_TICK;
    return 0;
}
static int modify(struct ker_timer_list *timer, unsigned long expires)
{
    if (!timer->native->function) return 0; /* Native shutdown forbids rearm. */
    int64_t ns; int error = deadline(timer, expires, &ns);
    if (error) return error;
    int pending = timer_pending(timer->native);
    if (pending && timer->native->expires == expires) return 1;
    BUG_ON(ker_timer_arm(timer->runtime, &timer->backing, ns));
    if (!pending) hlist_add_head(&timer->native->entry, &timer->pending);
    timer->native->expires = expires;
    return pending;
}
static int remove_timer(struct ker_timer_list *timer)
{
    int pending = ker_timer_cancel(&timer->backing);
    BUG_ON(pending < 0);
    if (pending) {
        hlist_del_init(&timer->native->entry);
        timer->native->entry.next = &timer->native->entry;
    }
    return pending;
}
static struct ker_timer_list *binding(struct timer_list *native)
{
    BUG_ON(!active || active->native != native || valid(active));
    return active;
}
void timer_init_key(struct timer_list *native, void (*callback)(struct timer_list *),
    unsigned int flags, const char *name, struct lock_class_key *key)
{
    BUG_ON(!active || active->native != native || !callback || (flags & ~TIMER_PINNED) || name || key);
    BUG_ON(active->backing.owner || active->running);
    *native = (struct timer_list){.function = callback, .flags = flags};
    INIT_HLIST_NODE(&native->entry);
    /* Inactive tag prevents a second binding after shutdown. pprev remains
     * NULL, so the original timer_pending predicate remains false. */
    native->entry.next = &native->entry;
}
int mod_timer(struct timer_list *native, unsigned long expires)
{
    int result = modify(binding(native), expires);
    BUG_ON(result < 0);
    return result;
}
int mod_timer_pending(struct timer_list *native, unsigned long expires)
{
    struct ker_timer_list *timer = binding(native);
    return timer_pending(native) ? mod_timer(timer->native, expires) : 0;
}
int timer_reduce(struct timer_list *native, unsigned long expires)
{
    binding(native);
    if (timer_pending(native) && time_after_eq(expires, native->expires)) return 1;
    return mod_timer(native, expires);
}
int ker_linux_timer_delete_native(struct timer_list *native) { return remove_timer(binding(native)); }
int timer_shutdown(struct timer_list *native)
{
    struct ker_timer_list *timer = binding(native);
    int result = remove_timer(timer);
    native->function = NULL;
    return result;
}
void add_timer(struct timer_list *native)
{
    binding(native); BUG_ON(timer_pending(native));
    (void)mod_timer(native, native->expires);
}
static void fire(struct ker_timer *backing, void *arg)
{
    struct ker_timer_list *timer = arg;
    /* ker_runtime_poll already detached the ordered node. Detach the native
     * membership before running an unchanged timer_list callback. */
    BUG_ON(backing != &timer->backing || backing->owner || !timer_pending(timer->native));
    hlist_del_init(&timer->native->entry);
    timer->native->entry.next = &timer->native->entry;
    BUG_ON(valid(timer) || !timer->native->function);
    struct ker_timer_list *previous = active;
    struct firing *outer = firing, frame = {.timer = timer};
    struct timer_list *native = timer->native;
    void (*callback)(struct timer_list *) = native->function;
    timer->running = true; active = timer; firing = &frame;
    callback(native);
    /* Cleanup can invalidate/free both timer containers; do not dereference
     * either after a callback that explicitly removed its inactive binding. */
    if (!frame.removed) timer->running = false;
    active = previous; firing = outer;
}
int ker_timer_list_init(struct ker_timer_list *timer, struct ker_runtime *runtime,
    struct timer_list *native, void (*callback)(struct timer_list *))
{
    if (!timer || !runtime || !native || !callback || runtime->now_ns < 0) return -EINVAL;
    if (timer->native || native->function || native->flags || native->expires ||
        native->entry.next || native->entry.pprev) return -EBUSY;
    unsigned int lcore = rte_lcore_id();
    if (lcore == LCORE_ID_ANY || (runtime->native_owned && runtime->native_lcore != lcore)) return -EXDEV;
    if (runtime->native_live == UINT_MAX) return -EOVERFLOW;
    *timer = (struct ker_timer_list){.native = native, .runtime = runtime, .lcore = lcore};
    ker_timer_init(&timer->backing, fire, timer);
    runtime->native_lcore = lcore; runtime->native_owned = true; runtime->native_live++;
    struct ker_timer_list *previous = active;
    active = timer; timer_setup(native, callback, TIMER_PINNED); active = previous;
    return 0;
}
int ker_timer_list_set_epoch(struct ker_runtime *runtime, unsigned long origin)
{
    if (!runtime || runtime->now_ns < 0) return -EINVAL;
    if (rte_lcore_id() == LCORE_ID_ANY || (runtime->native_owned && runtime->native_lcore != rte_lcore_id())) return -EXDEV;
    if (runtime->polling || runtime->native_live || timerqueue_getnext(&runtime->timers)) return -EBUSY;
    runtime->jiffies_base = origin;
    return 0;
}
int ker_timer_list_now(struct ker_timer_list *timer, unsigned long *result)
{
    int error = valid(timer);
    if (error) return error;
    if (!result) return -EINVAL;
    *result = ticks(timer->runtime);
    return 0;
}
int ker_timer_list_mod(struct ker_timer_list *timer, unsigned long expires)
{
    int error = valid(timer);
    return error ? error : modify(timer, expires);
}
int ker_timer_list_delete(struct ker_timer_list *timer)
{
    int error = valid(timer);
    return error ? error : remove_timer(timer);
}
int ker_timer_list_shutdown(struct ker_timer_list *timer)
{
    int error = valid(timer);
    if (error) return error;
    int result = remove_timer(timer);
    timer->native->function = NULL;
    return result;
}
int ker_timer_list_call(struct ker_timer_list *timer, ker_timer_list_fn fn, void *arg)
{
    int error = valid(timer);
    if (error) return error;
    if (!fn) return -EINVAL;
    if (timer->scoping || timer->running) return -EBUSY;
    struct ker_timer_list *previous = active;
    timer->scoping = true; active = timer;
    int result = fn(arg);
    active = previous; timer->scoping = false;
    return result;
}
int ker_timer_list_cleanup(struct ker_timer_list *timer)
{
    int error = valid(timer);
    if (error) return error;
    if (timer_pending(timer->native) || timer->scoping) return -EBUSY;
    if (timer->running) {
        if (!firing || firing->timer != timer || active != timer) return -EBUSY;
        firing->removed = true;
    }
    BUG_ON(!timer->runtime->native_live);
    timer->runtime->native_live--;
    *timer->native = (struct timer_list){0};
    *timer = (struct ker_timer_list){0};
    return 0;
}
