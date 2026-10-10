#ifndef KER_COMPAT_NAPI_CONFIG_H
#define KER_COMPAT_NAPI_CONFIG_H
#include <rte_config.h>
#include <linux/bug.h>
/* Private userspace configuration, not a running-kernel ABI. */
#if defined(NR_CPUS) && NR_CPUS != RTE_MAX_LCORE
#error Unsupported NAPI NR_CPUS configuration
#endif
#ifndef NR_CPUS
#define NR_CPUS RTE_MAX_LCORE
#endif
#define __private
#ifndef BIT
#define BIT(n) (1UL << (n))
#endif
#define try_cmpxchg(ptr, old, value) \
    __atomic_compare_exchange_n((ptr), (old), (value), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
static inline bool test_bit(unsigned int bit, const unsigned long *word)
{
    return !!(READ_ONCE(*word) & BIT(bit));
}
/* Real intrusive-list operations; mutations are serialized on one worker. */
static inline void INIT_LIST_HEAD(struct list_head *head) { head->next = head->prev = head; }
static inline bool list_empty(const struct list_head *head) { return head->next == head; }
static inline void list_add_tail(struct list_head *node, struct list_head *head)
{
    node->prev = head->prev; node->next = head;
    head->prev->next = node; head->prev = node;
}
static inline void list_del_init(struct list_head *node)
{
    node->prev->next = node->next; node->next->prev = node->prev;
    INIT_LIST_HEAD(node);
}
#endif
