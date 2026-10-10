#include <linux/irqflags.h>
#include <linux/bug.h>
static _Thread_local unsigned long ker_irq_mask;
unsigned long ker_local_irq_save(void)
{
    unsigned long previous = ker_irq_mask;
    ker_irq_mask = 1;
    return previous;
}
void ker_local_irq_restore(unsigned long flags)
{
    WARN_ON_ONCE(flags > 1);
    ker_irq_mask = flags;
}
bool ker_local_irq_disabled(void)
{
    return ker_irq_mask != 0;
}
