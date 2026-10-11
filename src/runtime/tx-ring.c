#include "runtime/tx-ring.h"
#include <errno.h>
#include <limits.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <string.h>

#define KER_TX_RING_MAX_CAPACITY 65535U

int ker_tx_ring_init(struct ker_tx_ring *adapter, const char *name,
    unsigned int capacity, int socket_id)
{
    if (!adapter || !name || !name[0] || !capacity) return -EINVAL;
    if (capacity > KER_TX_RING_MAX_CAPACITY) return -EOVERFLOW;
    if (adapter->ring) return -EALREADY;
    unsigned int lcore = rte_lcore_id();
    if (lcore == LCORE_ID_ANY) return -EXDEV;

    rte_errno = 0;
    struct rte_ring *ring = rte_ring_create(name, capacity, socket_id,
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ring) return rte_errno ? -rte_errno : -ENOMEM;

    adapter->ring = ring;
    adapter->owner_lcore = lcore;
    return 0;
}

int ker_tx_ring_sink(struct rte_mbuf *chain, void *arg)
{
    struct ker_tx_ring *adapter = arg;
    if (!adapter || !adapter->ring || !chain) return -EINVAL;
    if (rte_lcore_id() != adapter->owner_lcore) return -EXDEV;

    int rc = rte_ring_sp_enqueue(adapter->ring, chain);
    if (rc == -ENOBUFS) return -EAGAIN;
    return rc;
}

int ker_tx_ring_take(struct ker_tx_ring *adapter, struct rte_mbuf **result)
{
    if (!adapter || !adapter->ring || !result) return -EINVAL;
    void *object = NULL;
    int rc = rte_ring_sc_dequeue(adapter->ring, &object);
    if (rc == -ENOENT) return 0;
    if (rc) return rc;
    if (!object) return -EIO;
    *result = object;
    return 1;
}

int ker_tx_ring_cleanup(struct ker_tx_ring *adapter)
{
    if (!adapter || !adapter->ring) return -EINVAL;
    if (rte_lcore_id() != adapter->owner_lcore) return -EXDEV;
    if (!rte_ring_empty(adapter->ring)) return -EBUSY;
    rte_ring_free(adapter->ring);
    memset(adapter, 0, sizeof(*adapter));
    return 0;
}
