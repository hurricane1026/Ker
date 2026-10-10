#ifndef KER_COMPAT_NEIGHBOR_CONFIG_H
#define KER_COMPAT_NEIGHBOR_CONFIG_H
#include <pthread.h>
#include <linux/container_of.h>
/* Real primitive adapters; selected neighbor operations are worker-serialized. */
typedef struct { pthread_rwlock_t native; } rwlock_t;
typedef spinlock_t raw_spinlock_t;
#define context_lock_struct(name) struct name
#define __randomize_layout
#define rcu_dereference(ptr) rcu_dereference_raw(ptr)
#define ker_neigh_for_each(pos, head) \
    for (struct hlist_node *ker_link = (head)->first; \
         ker_link && ((pos) = container_of(ker_link, __typeof__(*(pos)), hash), true); \
         ker_link = ker_link->next)
#endif
