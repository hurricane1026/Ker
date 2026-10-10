#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include <linux/slab.h>
#include <linux/container_of.h>
#include <rte_lcore.h>
#include <errno.h>
#include <limits.h>
/* Both complete original objects share a single actual DPDK control allocation. */
struct address_state { struct in_device device; struct in_ifaddr interface; };
static int valid_device(struct ker_eth_device *device)
{
    if (!device || !device->native || !device->context || !device->context->descriptors) return -EINVAL;
    if (rte_lcore_id() != device->lcore || device->context->lcore != device->lcore) return -EXDEV;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    if (device->native->type != ARPHRD_ETHER) return -ENOTSUP;
    return 0;
}
static bool busy(struct ker_eth_device *device)
{
    return device->context->live || device->napi_live || device->protocol_live;
}
int ker_ipv4_address_init(struct ker_ipv4_address *address, struct ker_eth_device *device,
    __be32 local, unsigned int prefix)
{
    int error = valid_device(device);
    if (error) return error;
    if (!address || prefix > 32) return -EINVAL;
    if (address->native) return -EALREADY;
    if (device->native->ip_ptr || busy(device)) return -EBUSY;
    if (device->context->address_live == UINT_MAX) return -EOVERFLOW;
    unsigned int host = rte_be_to_cpu_32(local);
    if (!host || (host >> 24) == 127 || (host & 0xf0000000U) >= 0xe0000000U) return -EINVAL;
    struct address_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state) return -ENOMEM;
    struct in_device *in = &state->device;
    struct in_ifaddr *ifa = &state->interface;
    in->dev = device->native; refcount_set(&in->refcnt, 1); spin_lock_init(&in->mc_tomb_lock);
    ifa->ifa_dev = in; ifa->ifa_local = local; ifa->ifa_address = local;
    ifa->ifa_mask = inet_make_mask((int)prefix); ifa->ifa_prefixlen = (unsigned char)prefix;
    ifa->ifa_broadcast = local | ~ifa->ifa_mask;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE; ifa->ifa_flags = IFA_F_PERMANENT;
    ifa->ifa_valid_lft = ifa->ifa_preferred_lft = UINT32_MAX;
    memcpy(ifa->ifa_label, device->native->name, IFNAMSIZ);
    in->ifa_list = ifa;
    device->context->address_live++;
    *address = (struct ker_ipv4_address){.native = in, .device = device};
    rcu_assign_pointer(device->native->ip_ptr, in);
    return 0;
}
static int valid(struct ker_ipv4_address *address)
{
    if (!address || !address->native) return -EINVAL;
    int error = valid_device(address->device);
    if (error) return error;
    if (rcu_dereference_raw(address->device->native->ip_ptr) != address->native) return -EBUSY;
    return 0;
}
int ker_ipv4_address_contains(struct ker_ipv4_address *address, __be32 candidate)
{
    int error = valid(address);
    return error ? error : inet_ifa_match(candidate, address->native->ifa_list);
}
int ker_ipv4_address_is_local(struct ker_ipv4_address *address, __be32 candidate)
{
    int error = valid(address);
    return error ? error : candidate == address->native->ifa_list->ifa_local;
}
int ker_ipv4_address_cleanup(struct ker_ipv4_address *address)
{
    if (!address) return -EINVAL;
    if (!address->native) return 0;
    int error = valid(address);
    if (error) return error;
    if (busy(address->device) || refcount_read(&address->native->refcnt) != 1) return -EBUSY;
    /* There are no remote readers or grace periods: worker-only, offline. */
    rcu_assign_pointer(address->device->native->ip_ptr, NULL);
    address->native->dead = 1;
    address->device->context->address_live--;
    kfree(container_of(address->native, struct address_state, device));
    *address = (struct ker_ipv4_address){0};
    return 0;
}
