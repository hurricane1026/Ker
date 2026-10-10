#include "check.h"
#include "eal.h"
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include "runtime/timer-list.h"
#include "runtime/memory.h"
#include <linux/slab.h>
#include "compat/timer-list-scope.h"
struct object {
    struct timer_list native;
    struct ker_timer_list adapter;
    unsigned int calls;
    bool rearm, destroy, shutdown;
    struct object *other;
};
static unsigned int destroyed;
static int cancel_nested(void *arg)
{
    struct object *o = arg;
    CHECK(jiffies == 0);
    CHECK(timer_delete(&o->native) == 1);
    CHECK(ker_timer_list_cleanup(&o->adapter) == -EBUSY);
    return 0;
}
static void callback(struct timer_list *native)
{
    struct object *o = timer_container_of(o, native, native);
    struct ker_runtime *runtime = o->adapter.runtime;
    CHECK(!timer_pending(native));
    unsigned long now;
    CHECK(ker_timer_list_now(&o->adapter, &now) == 0 && jiffies == now);
    CHECK(ker_runtime_poll(runtime, runtime->now_ns, 1) == -EBUSY);
    CHECK(ker_runtime_cleanup(runtime) == -EBUSY);
    ++o->calls;
    if (o->rearm) CHECK(mod_timer(native, jiffies) == 0);
    if (o->shutdown) {
        CHECK(timer_shutdown(native) == (o->rearm ? 1 : 0));
        CHECK(mod_timer(native, jiffies + 1) == 0 && !timer_pending(native));
    }
    if (o->other) {
        CHECK(ker_timer_list_call(&o->other->adapter, cancel_nested, o->other) == 0);
        CHECK(jiffies == now); /* Nested scope restored the callback binding. */
    }
    if (o->destroy) {
        CHECK(ker_timer_list_cleanup(&o->adapter) == 0);
        ++destroyed;
        kfree(o);
    }
}
static void init(struct object *o, struct ker_runtime *runtime)
{
    CHECK(ker_timer_list_init(&o->adapter, runtime, &o->native, callback) == 0);
}
static void *wrong_worker(void *arg)
{
    struct object *o = arg;
    unsigned long now = 123;
    CHECK(ker_timer_list_now(&o->adapter, &now) == -EXDEV && now == 123);
    CHECK(ker_timer_list_mod(&o->adapter, 1) == -EXDEV);
    CHECK(ker_timer_list_delete(&o->adapter) == -EXDEV);
    CHECK(ker_timer_list_shutdown(&o->adapter) == -EXDEV);
    CHECK(ker_timer_list_cleanup(&o->adapter) == -EXDEV);
    CHECK(ker_timer_list_set_epoch(o->adapter.runtime, 0) == -EXDEV);
    return NULL;
}
static int native_operations(void *arg)
{
    struct object *o = arg;
    CHECK(ker_timer_list_cleanup(&o->adapter) == -EBUSY);
    CHECK(ker_timer_list_call(&o->adapter, native_operations, o) == -EBUSY);
    CHECK(mod_timer_pending(&o->native, jiffies + 10) == 0);
    timer_setup(&o->native, callback, 0);
    o->native.expires = jiffies + 10;
    add_timer(&o->native);
    CHECK(timer_pending(&o->native));
    CHECK(timer_reduce(&o->native, jiffies + 20) == 1);
    CHECK(o->native.expires == jiffies + 10);
    CHECK(timer_reduce(&o->native, jiffies + 5) == 1);
    CHECK(mod_timer_pending(&o->native, jiffies + 7) == 1);
    CHECK(timer_delete(&o->native) == 1 && timer_delete(&o->native) == 0);
    CHECK(mod_timer(&o->native, jiffies + 2) == 0);
    CHECK(timer_shutdown(&o->native) == 1);
    CHECK(mod_timer(&o->native, jiffies + 1) == 0 && !timer_pending(&o->native));
    return 42;
}
static void lifecycle(void)
{
    struct ker_runtime runtime;
    struct object o = {0}; struct ker_timer_list duplicate = {0};
    ker_runtime_init(&runtime);
    CHECK(ker_runtime_poll(&runtime, 5300000, 0) == 0);
    ker_memory_fail_after(0);
    init(&o, &runtime); /* Caller-owned storage never needs an allocation. */
    CHECK(ker_timer_list_init(&duplicate, &runtime, &o.native, callback) == -EBUSY);
    CHECK(ker_runtime_cleanup(&runtime) == -EBUSY);
    CHECK(ker_timer_list_set_epoch(&runtime, 10) == -EBUSY);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, wrong_worker, &o) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(ker_timer_list_mod(&o.adapter, 6) == 0);
    CHECK(ker_timer_list_mod(&o.adapter, 6) == 1);
    int64_t ns;
    CHECK(ker_runtime_next_deadline(&runtime, &ns) == 1 && ns == 6000000);
    CHECK(ker_timer_list_cleanup(&o.adapter) == -EBUSY);
    CHECK(ker_runtime_poll(&runtime, 5999999, 2) == 0);
    CHECK(ker_runtime_poll(&runtime, 6000000, 2) == 1 && o.calls == 1);
    CHECK(ker_timer_list_call(&o.adapter, native_operations, &o) == 42);
    CHECK(ker_timer_list_init(&duplicate, &runtime, &o.native, callback) == -EBUSY);
    CHECK(ker_timer_list_cleanup(&o.adapter) == 0 && !runtime.native_live);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
    ker_memory_fail_after(-1);
}
static void wrap_and_rearm(void)
{
    struct ker_runtime runtime; struct object o = {0};
    ker_runtime_init(&runtime);
    CHECK(ker_timer_list_set_epoch(&runtime, ULONG_MAX - 2) == 0);
    init(&o, &runtime);
    CHECK(time_after(1UL, ULONG_MAX - 2) && time_before(ULONG_MAX - 2, 1UL));
    CHECK(ker_timer_list_mod(&o.adapter, 1) == 0);
    CHECK(ker_runtime_poll(&runtime, 3999999, 1) == 0);
    CHECK(ker_runtime_poll(&runtime, 4000000, 1) == 1);
    unsigned long now; CHECK(ker_timer_list_now(&o.adapter, &now) == 0 && now == 1);
    o.rearm = true;
    CHECK(ker_timer_list_mod(&o.adapter, 0) == 0);
    CHECK(ker_runtime_poll(&runtime, 4000000, 3) == 3 && o.calls == 4);
    CHECK(timer_pending(&o.native));
    CHECK(ker_timer_list_delete(&o.adapter) == 1);
    CHECK(ker_timer_list_delete(&o.adapter) == 0);
    CHECK(ker_timer_list_cleanup(&o.adapter) == 0);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
}
static void horizon_and_destroy(void)
{
    struct ker_runtime runtime; struct object o = {0};
    ker_runtime_init(&runtime); init(&o, &runtime);
    CHECK(ker_timer_list_mod(&o.adapter, 1) == 0);
    unsigned long far = (unsigned long)(INT64_MAX / 1000000) + 1;
    CHECK(ker_timer_list_mod(&o.adapter, far) == -EOVERFLOW);
    CHECK(o.native.expires == 1 && o.adapter.backing.node.expires == 1000000);
    CHECK(ker_timer_list_shutdown(&o.adapter) == 1);
    CHECK(ker_timer_list_mod(&o.adapter, 2) == 0 && !timer_pending(&o.native));
    CHECK(ker_timer_list_cleanup(&o.adapter) == 0);
    struct object *heap = kzalloc(sizeof(*heap), GFP_KERNEL); CHECK(heap);
    init(heap, &runtime); heap->destroy = true;
    CHECK(ker_timer_list_mod(&heap->adapter, 0) == 0);
    CHECK(ker_runtime_poll(&runtime, 0, 1) == 1 && destroyed == 1);
    CHECK(!runtime.native_live && ker_memory_live_allocations() == 0);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
}
static void nested_and_shutdown(void)
{
    struct ker_runtime runtime; struct object a = {0}, b = {0};
    ker_runtime_init(&runtime); init(&a, &runtime); init(&b, &runtime);
    a.other = &b; a.rearm = true; a.shutdown = true;
    CHECK(ker_timer_list_mod(&a.adapter, 0) == 0);
    CHECK(ker_timer_list_mod(&b.adapter, 1) == 0);
    CHECK(ker_runtime_poll(&runtime, 0, 3) == 1);
    CHECK(a.calls == 1 && b.calls == 0 && !a.native.function);
    CHECK(ker_timer_list_cleanup(&a.adapter) == 0);
    CHECK(ker_timer_list_cleanup(&b.adapter) == 0);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
    /* Last tick near the ns horizon must not overflow arithmetic. */
    ker_runtime_init(&runtime); a = (struct object){0}; init(&a, &runtime);
    CHECK(ker_runtime_poll(&runtime, INT64_MAX - 1, 0) == 0);
    unsigned long now; CHECK(ker_timer_list_now(&a.adapter, &now) == 0);
    CHECK(ker_timer_list_mod(&a.adapter, now + 1) == -EOVERFLOW);
    CHECK(ker_timer_list_mod(&a.adapter, now) == 0);
    CHECK(ker_runtime_poll(&runtime, INT64_MAX, 1) == 1);
    CHECK(ker_timer_list_cleanup(&a.adapter) == 0);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
}
int main(void)
{
    ker_test_eal_init(); CHECK(ker_memory_init(0, 7) == 0);
    lifecycle(); wrap_and_rearm(); horizon_and_destroy(); nested_and_shutdown();
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    puts("timer list: native pending state, jiffies wrap, rearm budgets, ownership and self-destruction passed");
    return 0;
}
