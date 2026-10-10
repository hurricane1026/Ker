#include "check.h"
#include <linux/refcount.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include "runtime/timer.h"
#include <errno.h>
#include <pthread.h>

static void test_counts(void)
{
    refcount_t refs = REFCOUNT_INIT(1);
    CHECK(refcount_read(&refs) == 1);
    CHECK(refcount_inc_not_zero(&refs));
    CHECK(refcount_read(&refs) == 2);
    CHECK(!refcount_dec_if_one(&refs));
    CHECK(refcount_dec_not_one(&refs));
    CHECK(refcount_read(&refs) == 1);
    CHECK(!refcount_dec_not_one(&refs));
    CHECK(refcount_dec_if_one(&refs));
    CHECK(!refcount_inc_not_zero(&refs));
    CHECK(!refcount_inc_not_zero_acquire(&refs));
    refcount_set_release(&refs, 1);
    CHECK(refcount_inc_not_zero_acquire(&refs));
    CHECK(!refcount_dec_and_test(&refs));
    CHECK(refcount_dec_and_test(&refs));
    refcount_set(&refs, INT_MAX);
    refcount_inc(&refs);
    CHECK(refcount_read(&refs) == (unsigned int)REFCOUNT_SATURATED);
    CHECK(!refcount_dec_and_test(&refs));
    CHECK(refcount_read(&refs) == (unsigned int)REFCOUNT_SATURATED);
    refcount_set(&refs, 0);
    refcount_inc(&refs);
    CHECK(refcount_read(&refs) == (unsigned int)REFCOUNT_SATURATED);
    refcount_set(&refs, 0);
    CHECK(!refcount_dec_and_test(&refs));
    CHECK(refcount_read(&refs) == (unsigned int)REFCOUNT_SATURATED);
}

static refcount_t concurrent = REFCOUNT_INIT(1);
static DEFINE_SPINLOCK(shared_lock);
static DEFINE_MUTEX(shared_mutex);
static unsigned int spin_count, mutex_count;
static void *worker(void *unused)
{
    (void)unused;
    CHECK(!ker_local_irq_disabled());
    for (int i = 0; i < 10000; ++i) {
        CHECK(refcount_inc_not_zero_acquire(&concurrent));
        spin_lock(&shared_lock);
        ++spin_count;
        spin_unlock(&shared_lock);
        mutex_lock(&shared_mutex);
        ++mutex_count;
        mutex_unlock(&shared_mutex);
        CHECK(!refcount_dec_and_test(&concurrent));
    }
    return NULL;
}

static void test_concurrent(void)
{
    pthread_t workers[4];
    for (int i = 0; i < 4; ++i)
        CHECK(pthread_create(&workers[i], NULL, worker, NULL) == 0);
    for (int i = 0; i < 4; ++i)
        CHECK(pthread_join(workers[i], NULL) == 0);
    CHECK(spin_count == 40000 && mutex_count == 40000);
    CHECK(refcount_read(&concurrent) == 1);
    CHECK(refcount_dec_and_test(&concurrent));
    mutex_destroy(&shared_mutex);
}

static void fired(struct ker_timer *timer, void *arg)
{
    (void)timer;
    ++*(int *)arg;
}
static void test_locks_and_dispatch(void)
{
    refcount_t refs = REFCOUNT_INIT(2);
    DEFINE_SPINLOCK(lock);
    struct mutex mutex;
    mutex_init(&mutex);
    CHECK(!refcount_dec_and_mutex_lock(&refs, &mutex));
    CHECK(refcount_dec_and_mutex_lock(&refs, &mutex));
    CHECK(!mutex_trylock(&mutex));
    mutex_unlock(&mutex);
    CHECK(mutex_trylock(&mutex));
    mutex_unlock(&mutex);
    mutex_destroy(&mutex);
    refcount_set(&refs, 2);
    CHECK(!refcount_dec_and_lock(&refs, &lock));
    CHECK(refcount_dec_and_lock(&refs, &lock));
    CHECK(!spin_trylock(&lock));
    spin_unlock(&lock);

    struct ker_runtime runtime;
    struct ker_timer timer;
    int callbacks = 0;
    ker_runtime_init(&runtime);
    ker_timer_init(&timer, fired, &callbacks);
    CHECK(ker_timer_arm(&runtime, &timer, 1) == 0);
    unsigned long outer, inner;
    local_irq_save(outer);
    local_irq_save(inner);
    CHECK(outer == 0 && inner == 1);
    CHECK(ker_runtime_poll(&runtime, 1, 1) == -EBUSY);
    CHECK(runtime.now_ns == 0 && callbacks == 0);
    refcount_set(&refs, 1);
    unsigned long flags = 99;
    CHECK(refcount_dec_and_lock_irqsave(&refs, &lock, &flags));
    CHECK(flags == 1 && ker_local_irq_disabled());
    spin_unlock_irqrestore(&lock, flags);
    local_irq_restore(inner);
    CHECK(ker_local_irq_disabled());
    local_irq_restore(outer);
    CHECK(!ker_local_irq_disabled());
    CHECK(ker_runtime_poll(&runtime, 1, 1) == 1 && callbacks == 1);
    refcount_set(&refs, 2);
    flags = 99;
    CHECK(!refcount_dec_and_lock_irqsave(&refs, &lock, &flags));
    CHECK(flags == 99 && !ker_local_irq_disabled());
}
int main(void)
{
    test_counts();
    test_concurrent();
    test_locks_and_dispatch();
    puts("refcount: saturation, threaded references, real locks and dispatch masking passed");
    return 0;
}
