#ifndef KER_COMPAT_LINUX_IRQFLAGS_H
#define KER_COMPAT_LINUX_IRQFLAGS_H
#include <linux/types.h>
/* User-mode "local IRQ" masks ker callback dispatch on the calling thread.
 * It does not mask hardware IRQs or POSIX signals. Signal handlers must not
 * enter the stack or acquire its locks. */
unsigned long ker_local_irq_save(void);
void ker_local_irq_restore(unsigned long flags);
bool ker_local_irq_disabled(void);
#define local_irq_save(flags) ((flags) = ker_local_irq_save())
#define local_irq_restore(flags) ker_local_irq_restore(flags)
#endif
