#include "runtime/neighbor.h"
#include "runtime/memory.h"
#include <linux/slab.h>
#include <rte_lcore.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
struct table_state { struct neigh_table table; struct neigh_hash_table hash; };
_Static_assert(offsetof(struct neighbour, primary_key) % sizeof(__be32) == 0, "IPv4 key alignment");
static int valid(struct ker_neighbor_table *table)
{
    if (!table || !table->native) return -EINVAL;
    if (rte_lcore_id() != table->lcore) return -EXDEV;
    struct net_device *dev = table->address->device->native;
    if (!dev || dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN) return -ENOTSUP;
    struct ker_memory_budget_stats stats;
    if (ker_memory_budget_stats(KER_MEMORY_CONTROL, &stats)) return -ESHUTDOWN;
    if (!table->address->native || table->address->native->arp_parms != &table->native->parms) return -ESHUTDOWN;
    return 0;
}
static unsigned int bucket(struct ker_neighbor_table *table, __be32 *ip)
{
    struct neigh_hash_table *hash = table->native->nht;
    return arp_hashfn(ip, table->address->device->native, hash->hash_rnd) >> (32 - hash->hash_shift);
}
int ker_neighbor_table_init(struct ker_neighbor_table *table, struct ker_ipv4_address *address,
    const char *name, unsigned int limit, unsigned int hash_bits)
{
    if (!table || !address || !address->native || !name || !*name || !limit || limit > INT_MAX ||
        !hash_bits || hash_bits > 16) return -EINVAL;
    if (table->native) return -EALREADY;
    int error = ker_ipv4_address_is_local(address, address->native->ifa_list->ifa_local);
    if (error < 0) return error;
    struct ker_eth_device *dev = address->device;
    if (address->native->arp_parms || dev->context->live || dev->napi_live || dev->protocol_live) return -EBUSY;
    if (refcount_read(&address->native->refcnt) >= INT_MAX) return -EOVERFLOW;
    struct table_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state) return -ENOMEM;
    state->hash.hash_heads = kcalloc(1U << hash_bits, sizeof(struct hlist_head), GFP_KERNEL);
    if (!state->hash.hash_heads) { kfree(state); return -ENOMEM; }
    struct kmem_cache *records = kmem_cache_create(name, NEIGH_ENTRY_SIZE(sizeof(struct neighbour) + sizeof(__be32)),
        SMP_CACHE_BYTES, SLAB_HWCACHE_ALIGN, NULL);
    if (!records) { kfree(state->hash.hash_heads); kfree(state); return -ENOMEM; }
    struct neigh_table *n = &state->table;
    n->family = AF_INET; n->protocol = rte_cpu_to_be_16(ETH_P_ARP); n->key_len = sizeof(__be32);
    n->entry_size = NEIGH_ENTRY_SIZE(sizeof(struct neighbour) + sizeof(__be32)); n->hash = arp_hashfn; n->key_eq = neigh_key_eq32;
    state->hash.hash_shift = hash_bits;
    /* Fixed odd multiplier for this bounded worker-local static table. No
     * security/randomness guarantee; input learning is not exposed. */
    state->hash.hash_rnd[0] = 0x9e3779b1U; n->nht = &state->hash;
    spin_lock_init(&n->lock); mutex_init(&n->phash_lock);
    INIT_LIST_HEAD(&n->parms_list); INIT_LIST_HEAD(&n->gc_list); INIT_LIST_HEAD(&n->managed_list);
    skb_queue_head_init(&n->proxy_queue);
    n->parms.dev = dev->native; n->parms.tbl = n;
    INIT_LIST_HEAD(&n->parms.list); refcount_set(&n->parms.refcnt, 1);
    refcount_inc(&address->native->refcnt);
    address->native->arp_parms = &n->parms;
    *table = (struct ker_neighbor_table){.native = n, .address = address, .records = records,
        .limit = limit, .lcore = rte_lcore_id()};
    return 0;
}
int ker_neighbor_add(struct ker_neighbor_table *table, __be32 ip, const unsigned char mac[6])
{
    int error = valid(table);
    if (error) return error;
    unsigned int host = rte_be_to_cpu_32(ip);
    if (!mac || !host || (host >> 24) == 127 || (host & 0xf0000000U) >= 0xe0000000U ||
        (mac[0] & 1) || !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5])) return -EINVAL;
    if (__neigh_lookup_noref(table->native, &ip, table->address->device->native)) return -EEXIST;
    if ((unsigned int)atomic_read(&table->native->entries) >= table->limit) return -ENOSPC;
    if (refcount_read(&table->native->parms.refcnt) >= INT_MAX) return -EOVERFLOW;
    struct neighbour *entry = kmem_cache_zalloc(table->records, GFP_ATOMIC);
    if (!entry) return -ENOMEM;
    error = pthread_rwlock_init(&entry->lock.native, NULL);
    if (error) { kmem_cache_free(table->records, entry); return -error; }
    entry->tbl = table->native; entry->parms = neigh_parms_clone(&table->native->parms);
    entry->dev = table->address->device->native; entry->nud_state = NUD_PERMANENT;
    refcount_set(&entry->refcnt, 1); memcpy(entry->primary_key, &ip, sizeof(ip)); memcpy(entry->ha, mac, ETH_ALEN);
    spin_lock_init(&entry->ha_lock.lock); spin_lock_init(&entry->hh.hh_lock.lock);
    skb_queue_head_init(&entry->arp_queue); INIT_LIST_HEAD(&entry->gc_list); INIT_LIST_HEAD(&entry->managed_list);
    struct hlist_head *head = &table->native->nht->hash_heads[bucket(table, &ip)];
    entry->hash.next = head->first; entry->hash.pprev = &head->first;
    if (head->first) head->first->pprev = &entry->hash.next;
    head->first = &entry->hash;
    atomic_inc(&table->native->entries);
    return 0;
}
int ker_neighbor_lookup(struct ker_neighbor_table *table, __be32 ip, struct neighbour **result)
{
    int error = valid(table);
    if (error) return error;
    if (!result) return -EINVAL;
    struct neighbour *entry = __neigh_lookup_noref(table->native, &ip, table->address->device->native);
    if (!entry) return -ENOENT;
    if (refcount_read(&entry->refcnt) >= INT_MAX) return -EOVERFLOW;
    *result = neigh_clone(entry);
    return 0;
}
static int reference(struct ker_neighbor_table *table, struct neighbour *entry)
{
    int error = valid(table);
    if (error) return error;
    if (!entry || entry->tbl != table->native || entry->dev != table->address->device->native ||
        refcount_read(&entry->refcnt) < 2) return -EINVAL;
    return 0;
}
int ker_neighbor_release(struct ker_neighbor_table *table, struct neighbour *entry)
{
    int error = reference(table, entry);
    if (error) return error;
    BUG_ON(refcount_dec_and_test(&entry->refcnt));
    return 0;
}
int ker_neighbor_mac(struct ker_neighbor_table *table, struct neighbour *entry, unsigned char mac[6])
{
    int error = reference(table, entry);
    if (error) return error;
    if (!mac) return -EINVAL;
    if (entry->nud_state != NUD_PERMANENT) return -ENOTSUP;
    neigh_ha_snapshot((char *)mac, entry, entry->dev);
    return 0;
}
int ker_neighbor_remove(struct ker_neighbor_table *table, __be32 ip)
{
    int error = valid(table);
    if (error) return error;
    struct neighbour *entry = __neigh_lookup_noref(table->native, &ip, table->address->device->native);
    if (!entry) return -ENOENT;
    if (refcount_read(&entry->refcnt) != 1 || entry->arp_queue.qlen || entry->arp_queue_len_bytes ||
        entry->timer.function || entry->output || entry->ops) return -EBUSY;
    *entry->hash.pprev = entry->hash.next;
    if (entry->hash.next) entry->hash.next->pprev = entry->hash.pprev;
    __neigh_parms_put(entry->parms);
    BUG_ON(pthread_rwlock_destroy(&entry->lock.native));
    entry->dead = 1; atomic_sub_return(1, &table->native->entries);
    kmem_cache_free(table->records, entry);
    return 0;
}
int ker_neighbor_table_cleanup(struct ker_neighbor_table *table)
{
    int error = valid(table);
    if (error) return error;
    if (atomic_read(&table->native->entries) || refcount_read(&table->native->parms.refcnt) != 1 ||
        table->address->device->context->live || table->address->device->napi_live ||
        table->address->device->protocol_live) return -EBUSY;
    table->address->native->arp_parms = NULL;
    BUG_ON(refcount_dec_and_test(&table->address->native->refcnt));
    struct table_state *state = container_of(table->native, struct table_state, table);
    kmem_cache_destroy(table->records); mutex_destroy(&state->table.phash_lock);
    kfree(state->hash.hash_heads); kfree(state);
    *table = (struct ker_neighbor_table){0};
    return 0;
}
