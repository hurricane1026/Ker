#ifndef KER_COMPAT_LINUX_SPINLOCK_H
#define KER_COMPAT_LINUX_SPINLOCK_H
#include <linux/spinlock_types.h>
#include <linux/irqflags.h>
void ker_spin_lock(spinlock_t *lock);
void ker_spin_unlock(spinlock_t *lock);
bool ker_spin_trylock(spinlock_t *lock);
#define spin_lock_init(lock) __atomic_store_n(&(lock)->held, false, __ATOMIC_RELAXED)
#define spin_lock(lock) ker_spin_lock(lock)
#define spin_unlock(lock) ker_spin_unlock(lock)
#define spin_trylock(lock) ker_spin_trylock(lock)
#define spin_lock_irqsave(lock, flags) do { local_irq_save(flags); spin_lock(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { spin_unlock(lock); local_irq_restore(flags); } while (0)
#endif
