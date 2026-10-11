#include "runtime/neighbor-timer.h"
#include "runtime/memory.h"
#include "runtime/arp.h"
#include "runtime/skb.h"
#include "runtime/arp-probe-port.h"
#include <rte_lcore.h>
#include <errno.h>

static _Thread_local struct ker_eth_device *probe_device;
static _Thread_local struct sk_buff *probe_skb;
static _Thread_local unsigned int rcu_depth;

struct net *dev_net(struct net_device *dev)
{
    (void)dev; ker_arp_capture_bug(); return NULL;
}
struct net *dev_net_rcu(const struct net_device *dev)
{
    if (!probe_device || rte_lcore_id() != probe_device->lcore) ker_arp_capture_bug();
#ifdef CONFIG_NET_NS
    return rcu_dereference_raw(dev->nd_net.net);
#else
    /* Ker's imported build has no CONFIG_NET_NS field or namespace service. */
    (void)dev;
    return NULL;
#endif
}
int inet_addr_type_dev_table(struct net *net, struct net_device *dev, __be32 ip)
{ (void)net; (void)dev; (void)ip; ker_arp_capture_bug(); return -1; }
bool inet_addr_onlink(struct in_device *in, __be32 target, __be32 source)
{ (void)in; (void)target; (void)source; ker_arp_capture_bug(); return false; }
void neigh_app_ns(struct neighbour *n) { (void)n; ker_arp_capture_bug(); }
void ker_arp_capture_bug(void) { BUG_ON(true); }
void ker_arp_probe_rcu_enter(void)
{
    BUG_ON(!probe_device || rte_lcore_id() != probe_device->lcore || rcu_depth == UINT_MAX);
    ++rcu_depth;
}
void ker_arp_probe_rcu_exit(void)
{
    BUG_ON(!probe_device || rte_lcore_id() != probe_device->lcore || !rcu_depth);
    --rcu_depth;
}
void ker_arp_probe_xmit(struct sk_buff *skb)
{
    BUG_ON(!probe_device || rcu_depth || !skb || skb->dev != probe_device->native || probe_skb);
    skb_reset_mac_header(skb); skb->mac_len = ETH_HLEN;
    probe_skb = skb;
}
struct net_device *ker_arp_probe_for_each_netdev(struct net *net)
{ (void)net; ker_arp_capture_bug(); return NULL; }

int ker_arp_probe_create(struct ker_neighbor_monitor *m,
    const struct ker_neighbor_event *event, struct sk_buff **result)
{
    if (!m || !event || !result) return -EINVAL;
    int error = ker_neighbor_monitor_probe_scope(m, event);
    if (error) return error;
    struct ker_neighbor_table *table = m->table;
    struct ker_ipv4_address *address = table->address;
    if (!address || !address->native || !address->device ||
        address->native->dev != address->device->native ||
        address->device->native->ip_ptr != address->native ||
        address->native->ifa_list == NULL || address->native->ifa_list->ifa_next ||
        address->native->ifa_list->ifa_dev != address->native ||
        address->native->ifa_list->ifa_local == 0 ||
        (address->native->ifa_list->ifa_flags & IFA_F_SECONDARY) ||
        address->native->ifa_list->ifa_scope != RT_SCOPE_UNIVERSE ||
        address->native->cnf.data[IPV4_DEVCONF_ARP_ANNOUNCE - 1] != 0 ||
        address->native->cnf.data[IPV4_DEVCONF_ROUTE_LOCALNET - 1] != 0 ||
        NEIGH_VAR(m->entry->parms, APP_PROBES) != 0 || event->ip != *(__be32 *)m->entry->primary_key)
        return -ENOTSUP;
    if (rte_lcore_id() != address->device->lcore || address->device->lcore != table->lcore)
        return -EXDEV;
    if (probe_device || probe_skb || rcu_depth) return -EBUSY;
    error = ker_arp_capture_begin(address->device);
    if (error) return error;
    probe_device = address->device;
    ker_linux_arp_solicit(m->entry);
    BUG_ON(rcu_depth);
    struct sk_buff *skb = probe_skb;
    probe_skb = NULL; probe_device = NULL;
    int allocation_error = ker_arp_capture_end();
    if (!skb) return allocation_error ? allocation_error : -ENOMEM;
    if (allocation_error) { BUG_ON(ker_skb_free(skb)); return allocation_error; }
    *result = skb;
    return 0;
}
