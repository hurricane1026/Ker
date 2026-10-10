#ifndef KER_COMPAT_LINUX_MUTEX_H
#define KER_COMPAT_LINUX_MUTEX_H
#include <pthread.h>
#include <linux/types.h>
struct mutex { pthread_mutex_t native; };
#define DEFINE_MUTEX(name) struct mutex name = { .native = PTHREAD_MUTEX_INITIALIZER }
void ker_mutex_init(struct mutex *lock);
void ker_mutex_destroy(struct mutex *lock);
void ker_mutex_lock(struct mutex *lock);
void ker_mutex_unlock(struct mutex *lock);
bool ker_mutex_trylock(struct mutex *lock);
#define mutex_init(lock) ker_mutex_init(lock)
#define mutex_destroy(lock) ker_mutex_destroy(lock)
#define mutex_lock(lock) ker_mutex_lock(lock)
#define mutex_unlock(lock) ker_mutex_unlock(lock)
#define mutex_trylock(lock) ker_mutex_trylock(lock)
#endif
