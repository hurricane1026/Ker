#ifndef KER_COMPAT_SKB_SUPPORT_H
#define KER_COMPAT_SKB_SUPPORT_H
#include "ker/linux_skb.h"
#include <rte_lcore.h>
#include <linux/bug.h>
/* There is no route state in this slice. Refuse it rather than dropping a
 * reference or pretending that dst ownership has been implemented. */
static inline void skb_dst_copy(struct sk_buff *dst, const struct sk_buff *src)
{
    BUG_ON(src->_skb_refdst != 0);
    dst->_skb_refdst = 0;
}
static inline unsigned int raw_smp_processor_id(void) { return rte_lcore_id(); }
static inline void skb_over_panic(struct sk_buff *skb, unsigned int size, void *addr)
{
    (void)skb; (void)size; (void)addr;
    BUG();
}
static inline void skb_under_panic(struct sk_buff *skb, unsigned int size, void *addr)
{
    (void)skb; (void)size; (void)addr;
    BUG();
}
#endif
