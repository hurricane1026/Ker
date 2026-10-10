#ifndef KER_COMPAT_LINUX_ATOMIC_H
#define KER_COMPAT_LINUX_ATOMIC_H
#include <linux/types.h>
#define ATOMIC_INIT(value) { .counter = (value) }
static inline int atomic_read(const atomic_t *v)
{
    return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}
static inline void atomic_set(atomic_t *v, int value)
{
    __atomic_store_n(&v->counter, value, __ATOMIC_RELAXED);
}
static inline void atomic_set_release(atomic_t *v, int value)
{
    __atomic_store_n(&v->counter, value, __ATOMIC_RELEASE);
}
static inline int atomic_fetch_add_relaxed(int value, atomic_t *v)
{
    return __atomic_fetch_add(&v->counter, value, __ATOMIC_RELAXED);
}
static inline int atomic_fetch_sub_release(int value, atomic_t *v)
{
    return __atomic_fetch_sub(&v->counter, value, __ATOMIC_RELEASE);
}
/* Upstream also uses unsigned old-value variables. Signed/unsigned int may
 * alias, but Clang requires an explicit pointer cast for its atomic builtin. */
#define ker_atomic_try_cmpxchg(v, old, new_value, order) ({ \
    _Static_assert(__same_type(*(old), int) || __same_type(*(old), unsigned int), \
                   "atomic old value must be int or unsigned int"); \
    __atomic_compare_exchange_n(&(v)->counter, (int *)(old), (new_value), false, (order), __ATOMIC_RELAXED); \
})
#define atomic_try_cmpxchg_relaxed(v, old, new_value) \
    ker_atomic_try_cmpxchg(v, old, new_value, __ATOMIC_RELAXED)
#define atomic_try_cmpxchg_acquire(v, old, new_value) \
    ker_atomic_try_cmpxchg(v, old, new_value, __ATOMIC_ACQUIRE)
#define atomic_try_cmpxchg_release(v, old, new_value) \
    ker_atomic_try_cmpxchg(v, old, new_value, __ATOMIC_RELEASE)
static inline void smp_acquire__after_ctrl_dep(void)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
}
#endif
