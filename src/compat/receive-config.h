#ifndef KER_COMPAT_RECEIVE_CONFIG_H
#define KER_COMPAT_RECEIVE_CONFIG_H
#include <linux/container_of.h>
#include <linux/gfp.h>
#include <linux/errno.h>
/* Registry changes and dispatch serialize on one worker. This traversal uses
 * real list links, without providing kernel RCU or cross-worker publication. */
#define list_for_each_entry_rcu(pos, head, member) \
    for (struct list_head *ker_rx_link = (head)->next; \
         ker_rx_link != (head) && ((pos) = container_of(ker_rx_link, __typeof__(*(pos)), member), true); \
         ker_rx_link = ker_rx_link->next)
#endif
