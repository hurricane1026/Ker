#include "runtime/timer.h"

#include <errno.h>
#include <limits.h>
#include <time.h>

void ker_runtime_init(struct ker_runtime *runtime)
{
    timerqueue_init_head(&runtime->timers);
    runtime->now_ns = 0;
    runtime->polling = false;
}

void ker_timer_init(struct ker_timer *timer, ker_timer_callback callback, void *arg)
{
    timerqueue_init(&timer->node);
    timer->node.expires = 0;
    timer->owner = NULL;
    timer->callback = callback;
    timer->arg = arg;
}

int ker_timer_cancel(struct ker_timer *timer)
{
    if (!timer)
        return -EINVAL;
    if (!timer->owner)
        return 0;
    timerqueue_del(&timer->owner->timers, &timer->node);
    timer->owner = NULL;
    return 1;
}

int ker_timer_arm(struct ker_runtime *runtime, struct ker_timer *timer, int64_t deadline_ns)
{
    if (!runtime || !timer || !timer->callback || deadline_ns < 0)
        return -EINVAL;
    if (timer->owner && timer->owner != runtime)
        return -EXDEV;
    ker_timer_cancel(timer);
    timer->node.expires = deadline_ns;
    timer->owner = runtime;
    timerqueue_add(&runtime->timers, &timer->node);
    return 0;
}

int ker_runtime_poll(struct ker_runtime *runtime, int64_t now_ns, unsigned int budget)
{
    int count = 0;
    if (!runtime || now_ns < 0 || budget > INT_MAX)
        return -EINVAL;
    if (runtime->polling)
        return -EBUSY;
    if (now_ns < runtime->now_ns)
        return -EINVAL;
    runtime->now_ns = now_ns;
    runtime->polling = true;
    while ((unsigned int)count < budget) {
        struct timerqueue_node *node = timerqueue_getnext(&runtime->timers);
        struct ker_timer *timer;
        ker_timer_callback callback;
        void *arg;
        if (!node || node->expires > now_ns)
            break;
        timer = container_of(node, struct ker_timer, node);
        callback = timer->callback;
        arg = timer->arg;
        ker_timer_cancel(timer);
        callback(timer, arg);
        ++count;
    }
    runtime->polling = false;
    return count;
}

int ker_runtime_next_deadline(struct ker_runtime *runtime, int64_t *deadline_ns)
{
    struct timerqueue_node *node;
    if (!runtime || !deadline_ns)
        return -EINVAL;
    node = timerqueue_getnext(&runtime->timers);
    if (!node)
        return 0;
    *deadline_ns = node->expires;
    return 1;
}

int ker_runtime_cleanup(struct ker_runtime *runtime)
{
    struct timerqueue_node *node;
    if (!runtime)
        return -EINVAL;
    if (runtime->polling)
        return -EBUSY;
    while ((node = timerqueue_getnext(&runtime->timers)))
        ker_timer_cancel(container_of(node, struct ker_timer, node));
    return 0;
}

int ker_monotonic_ns(int64_t *now_ns)
{
    struct timespec ts;
    if (!now_ns)
        return -EINVAL;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return -errno;
    if (ts.tv_sec < 0 || ts.tv_sec > (INT64_MAX - ts.tv_nsec) / INT64_C(1000000000))
        return -EOVERFLOW;
    *now_ns = (int64_t)ts.tv_sec * INT64_C(1000000000) + ts.tv_nsec;
    return 0;
}
