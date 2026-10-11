#include "runtime/neighbor.h"
#include "ker/linux_neighbor_update.h"
#include <linux/spinlock.h>

void ker_neighbor_update_seq_write_lock(seqlock_t *lock)
{
    spin_lock(&lock->lock);
    __atomic_fetch_add(&lock->seqcount.seqcount.sequence, 1U, __ATOMIC_SEQ_CST);
}

void ker_neighbor_update_seq_write_unlock(seqlock_t *lock)
{
    __atomic_fetch_add(&lock->seqcount.seqcount.sequence, 1U, __ATOMIC_SEQ_CST);
    spin_unlock(&lock->lock);
}

void ker_neighbor_update_restore_mac(struct neighbour *entry,
    const unsigned char mac[ETH_ALEN])
{
    ker_neighbor_update_seq_write_lock(&entry->ha_lock);
    memcpy(entry->ha, mac, ETH_ALEN);
    ker_neighbor_update_seq_write_unlock(&entry->ha_lock);
}
