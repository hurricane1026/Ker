#include "check.h"
#include "runtime/timer.h"
#include <errno.h>
#include <limits.h>
#include <linux/rbtree_augmented.h>

static int check_tree(struct rb_node *node, struct rb_node *parent)
{
    if (!node)
        return 1;
    CHECK(rb_parent(node) == parent);
    if (rb_is_red(node)) {
        CHECK(!node->rb_left || rb_is_black(node->rb_left));
        CHECK(!node->rb_right || rb_is_black(node->rb_right));
    }
    int left = check_tree(node->rb_left, node);
    int right = check_tree(node->rb_right, node);
    CHECK(left == right);
    return left + !!rb_is_black(node);
}

static size_t check_queue(struct ker_runtime *runtime)
{
    struct rb_node *root = runtime->timers.rb_root.rb_root.rb_node;
    CHECK(!root || rb_is_black(root));
    check_tree(root, NULL);
    size_t count = 0;
    int64_t previous = -1;
    for (struct timerqueue_node *node = timerqueue_getnext(&runtime->timers);
         node; node = timerqueue_iterate_next(node)) {
        CHECK(node->expires >= previous);
        previous = node->expires;
        ++count;
    }
    return count;
}

struct record {
    int count;
    int64_t last;
};

static void record_timer(struct ker_timer *timer, void *arg)
{
    struct record *record = arg;
    CHECK(timer->owner == NULL);
    CHECK(!timerqueue_node_queued(&timer->node));
    CHECK(timer->node.expires >= record->last);
    record->last = timer->node.expires;
    ++record->count;
}

static void test_order_and_mutation(void)
{
    enum { COUNT = 511 };
    struct ker_runtime runtime, other;
    struct ker_timer timers[COUNT];
    struct record record = {0, -1};
    int64_t deadline;
    ker_runtime_init(&runtime);
    ker_runtime_init(&other);
    CHECK(ker_runtime_next_deadline(&runtime, &deadline) == 0);
    for (int i = 0; i < COUNT; ++i) {
        ker_timer_init(&timers[i], record_timer, &record);
        CHECK(ker_timer_arm(&runtime, &timers[i], (i * 137) % 101) == 0);
        CHECK(check_queue(&runtime) == (size_t)i + 1);
    }
    CHECK(ker_timer_arm(&other, &timers[0], 7) == -EXDEV);
    CHECK(timers[0].owner == &runtime);
    for (int i = 0; i < COUNT; ++i) {
        if (i % 3 == 0) {
            CHECK(ker_timer_cancel(&timers[i]) == 1);
            CHECK(ker_timer_cancel(&timers[i]) == 0);
        } else {
            CHECK(ker_timer_arm(&runtime, &timers[i], (i * 37) % 211) == 0);
        }
        check_queue(&runtime);
    }
    size_t pending = check_queue(&runtime);
    CHECK(pending == COUNT - (COUNT + 2) / 3);
    CHECK(ker_runtime_poll(&runtime, 211, 0) == 0);
    CHECK(check_queue(&runtime) == pending);
    while (check_queue(&runtime)) {
        int result = ker_runtime_poll(&runtime, 211, 7);
        CHECK(result > 0 && result <= 7);
    }
    CHECK(record.count == (int)pending);
    CHECK(ker_runtime_poll(&runtime, 210, 1) == -EINVAL);
    CHECK(ker_runtime_next_deadline(&runtime, &deadline) == 0);
    CHECK(ker_timer_arm(&runtime, &timers[0], INT64_MAX) == 0);
    CHECK(ker_runtime_next_deadline(&runtime, &deadline) == 1);
    CHECK(deadline == INT64_MAX);
    CHECK(ker_runtime_poll(&runtime, INT64_MAX - 1, 1) == 0);
    CHECK(ker_runtime_poll(&runtime, INT64_MAX, 1) == 1);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
}

struct rearm_state {
    struct ker_runtime *runtime;
    int count;
};

static void rearm(struct ker_timer *timer, void *arg)
{
    struct rearm_state *state = arg;
    ++state->count;
    CHECK(ker_runtime_poll(state->runtime, state->runtime->now_ns, 1) == -EBUSY);
    CHECK(ker_runtime_cleanup(state->runtime) == -EBUSY);
    CHECK(ker_timer_arm(state->runtime, timer, state->runtime->now_ns) == 0);
}

static void free_timer(struct ker_timer *timer, void *arg)
{
    int *count = arg;
    ++*count;
    free(timer);
}

static void cancel_other(struct ker_timer *timer, void *arg)
{
    (void)timer;
    CHECK(ker_timer_cancel(arg) == 1);
}

static void test_callbacks_and_cleanup(void)
{
    struct ker_runtime runtime;
    struct ker_timer timer, victim, canceler;
    struct rearm_state state = {&runtime, 0};
    struct record record = {0, -1};
    int freed = 0;
    ker_runtime_init(&runtime);
    ker_timer_init(&timer, rearm, &state);
    CHECK(ker_timer_arm(&runtime, &timer, 10) == 0);
    CHECK(ker_runtime_poll(&runtime, 9, 3) == 0);
    CHECK(ker_runtime_poll(&runtime, 10, 3) == 3);
    CHECK(state.count == 3);
    CHECK(check_queue(&runtime) == 1);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
    CHECK(timer.owner == NULL);
    CHECK(ker_timer_cancel(&timer) == 0);
    CHECK(check_queue(&runtime) == 0);
    ker_timer_init(&victim, record_timer, &record);
    ker_timer_init(&canceler, cancel_other, &victim);
    CHECK(ker_timer_arm(&runtime, &victim, 20) == 0);
    CHECK(ker_timer_arm(&runtime, &canceler, 11) == 0);
    CHECK(ker_runtime_poll(&runtime, 20, 5) == 1);
    CHECK(record.count == 0);
    struct ker_timer *heap = malloc(sizeof(*heap));
    CHECK(heap != NULL);
    ker_timer_init(heap, free_timer, &freed);
    CHECK(ker_timer_arm(&runtime, heap, 20) == 0);
    CHECK(ker_runtime_poll(&runtime, 20, 1) == 1);
    CHECK(freed == 1);
    CHECK(ker_runtime_cleanup(&runtime) == 0);
}

static void test_errors_and_clock(void)
{
    struct ker_runtime runtime;
    struct ker_timer timer;
    struct record record = {0, -1};
    int64_t a, b;
    ker_runtime_init(&runtime);
    ker_timer_init(&timer, NULL, NULL);
    CHECK(ker_timer_arm(&runtime, &timer, 1) == -EINVAL);
    ker_timer_init(&timer, record_timer, &record);
    CHECK(ker_timer_arm(NULL, &timer, 1) == -EINVAL);
    CHECK(ker_timer_arm(&runtime, NULL, 1) == -EINVAL);
    CHECK(ker_timer_arm(&runtime, &timer, -1) == -EINVAL);
    CHECK(ker_timer_cancel(NULL) == -EINVAL);
    CHECK(ker_runtime_poll(NULL, 0, 1) == -EINVAL);
    CHECK(ker_runtime_poll(&runtime, -1, 1) == -EINVAL);
    CHECK(ker_runtime_poll(&runtime, 0, UINT_MAX) == -EINVAL);
    CHECK(ker_runtime_next_deadline(NULL, &a) == -EINVAL);
    CHECK(ker_runtime_next_deadline(&runtime, NULL) == -EINVAL);
    CHECK(ker_runtime_cleanup(NULL) == -EINVAL);
    CHECK(ker_monotonic_ns(NULL) == -EINVAL);
    CHECK(ker_monotonic_ns(&a) == 0);
    CHECK(ker_monotonic_ns(&b) == 0);
    CHECK(a >= 0 && b >= a);
    CHECK(ker_runtime_poll(&runtime, b, 1) == 0);
}

int main(void)
{
    test_order_and_mutation();
    test_callbacks_and_cleanup();
    test_errors_and_clock();
    puts("timer: tree invariants, ordering, cancel, rearm, budget and lifetime passed");
    return 0;
}
