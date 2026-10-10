#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/bug.h>
#include <errno.h>
#include <sched.h>

void ker_mutex_init(struct mutex *lock)
{
    WARN_ON_ONCE(pthread_mutex_init(&lock->native, NULL) != 0);
}
void ker_mutex_destroy(struct mutex *lock)
{
    WARN_ON_ONCE(pthread_mutex_destroy(&lock->native) != 0);
}
void ker_mutex_lock(struct mutex *lock)
{
    WARN_ON_ONCE(pthread_mutex_lock(&lock->native) != 0);
}
void ker_mutex_unlock(struct mutex *lock)
{
    WARN_ON_ONCE(pthread_mutex_unlock(&lock->native) != 0);
}
bool ker_mutex_trylock(struct mutex *lock)
{
    int error = pthread_mutex_trylock(&lock->native);
    if (error == EBUSY)
        return false;
    WARN_ON_ONCE(error != 0);
    return true;
}
void ker_spin_lock(spinlock_t *lock)
{
    while (!ker_spin_trylock(lock)) {
        while (__atomic_load_n(&lock->held, __ATOMIC_RELAXED))
            sched_yield();
    }
}
bool ker_spin_trylock(spinlock_t *lock)
{
    return !__atomic_test_and_set(&lock->held, __ATOMIC_ACQUIRE);
}
void ker_spin_unlock(spinlock_t *lock)
{
    __atomic_clear(&lock->held, __ATOMIC_RELEASE);
}
