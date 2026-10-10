#ifndef KER_COMPAT_ETHERNET_CONFIG_H
#define KER_COMPAT_ETHERNET_CONFIG_H
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <rte_byteorder.h>
#define __rcu
#define __percpu
#define __packed __attribute__((packed))
#define __counted_by(member)
#define BITS_TO_LONGS(bits) (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif
