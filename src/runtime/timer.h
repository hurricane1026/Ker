#ifndef KER_RUNTIME_TIMER_H
#define KER_RUNTIME_TIMER_H

#include <stddef.h>
#include <stdint.h>
#include <linux/timerqueue.h>

/* Internal, single-thread runtime. All operations on a runtime and its timers
 * must take place on its owning worker. Objects must be initialized once and
 * must not be copied or moved while queued. Deadlines are monotonic ns. */
struct ker_runtime {
    struct timerqueue_head timers;
    int64_t now_ns;
    bool polling;
    unsigned int native_lcore;
    bool native_owned;
    unsigned int native_live; /* bound ker_timer_list containers pin this clock */
    unsigned long jiffies_base;
};

struct ker_timer;
typedef void (*ker_timer_callback)(struct ker_timer *timer, void *arg);

struct ker_timer {
    struct timerqueue_node node;
    struct ker_runtime *owner;
    ker_timer_callback callback;
    void *arg;
};

void ker_runtime_init(struct ker_runtime *runtime);
/* Cancel pending timers without invoking callbacks. Never call from a callback. */
int ker_runtime_cleanup(struct ker_runtime *runtime);
void ker_timer_init(struct ker_timer *timer, ker_timer_callback callback, void *arg);
/* Rearms an existing timer; moving a pending timer to another runtime is EXDEV. */
int ker_timer_arm(struct ker_runtime *runtime, struct ker_timer *timer, int64_t deadline_ns);
/* Returns 1 if canceled, 0 if not queued. */
int ker_timer_cancel(struct ker_timer *timer);
/* Returns callbacks executed or negative errno. Reentrant polling is EBUSY.
 * A callback can cancel/rearm timers or free its own timer after firing.
 * budget limits callbacks even if they continuously rearm already-due timers. */
int ker_runtime_poll(struct ker_runtime *runtime, int64_t now_ns, unsigned int budget);
/* Returns 1 and writes the next deadline, or 0 for an empty queue. */
int ker_runtime_next_deadline(struct ker_runtime *runtime, int64_t *deadline_ns);
/* Returns 0 or negative errno; uses CLOCK_MONOTONIC. */
int ker_monotonic_ns(int64_t *now_ns);

#endif
