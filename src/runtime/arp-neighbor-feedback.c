#include "runtime/arp-receive.h"
#include "runtime/neighbor-timer.h"
#include <rte_lcore.h>
#include <errno.h>
#include <string.h>

int ker_arp_rx_feedback_scope(struct ker_arp_receiver *, const struct ker_arp_message *);

int ker_arp_neighbor_feedback(struct ker_arp_receiver *receiver,
    struct ker_neighbor_monitor *monitor, const struct ker_arp_message *message, u32 flags)
{
    if (!receiver || !monitor || !message) return -EINVAL;
    int error = ker_arp_rx_feedback_scope(receiver, message);
    if (error) return error;
    if (!monitor->table || rte_lcore_id() != monitor->table->lcore) return -EXDEV;
    if (!receiver->address || !receiver->address->device || !receiver->address->native ||
        !monitor->table || !monitor->table->address || !monitor->entry ||
        monitor->table->address != receiver->address ||
        monitor->table->address->device != receiver->address->device)
        return -EXDEV;
    struct net_device *dev = receiver->address->device->native;
    if (!dev || dev != monitor->entry->dev || dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN)
        return -ENOTSUP;
    if (message->operation != ARPOP_REPLY || !message->sender_ip || !message->target_local ||
        ker_ipv4_address_is_local(receiver->address, message->target_ip) != 1 ||
        memcmp(message->target_mac, dev->dev_addr, ETH_ALEN))
        return -ENOTSUP;
    struct ker_neighbor_event current;
    error = ker_neighbor_monitor_snapshot(monitor, &current);
    if (error) return error;
    if (current.ip != message->sender_ip) return -ENOENT;
    return ker_neighbor_monitor_update(monitor, message->sender_mac, flags);
}
