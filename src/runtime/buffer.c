#include "runtime/buffer.h"
#include <rte_errno.h>
#include <rte_lcore.h>
#include <errno.h>
#include <string.h>

int ker_packet_pool_init(struct ker_packet_pool *pool, const char *name,
    unsigned int count, unsigned int cache_size, uint16_t data_room_size, int socket_id)
{
    if (!pool || pool->mbufs || !name || !count || data_room_size <= RTE_PKTMBUF_HEADROOM ||
        rte_lcore_id() == LCORE_ID_ANY)
        return -EINVAL;
    struct rte_mempool *mbufs = rte_pktmbuf_pool_create(name, count, cache_size, 0,
        data_room_size, socket_id);
    if (!mbufs)
        return -rte_errno;
    pool->mbufs = mbufs;
    return 0;
}
int ker_packet_pool_cleanup(struct ker_packet_pool *pool)
{
    if (!pool)
        return -EINVAL;
    if (!pool->mbufs)
        return 0;
    if (rte_mempool_in_use_count(pool->mbufs))
        return -EBUSY;
    rte_mempool_free(pool->mbufs);
    pool->mbufs = NULL;
    return 0;
}
struct rte_mbuf *ker_packet_alloc(struct ker_packet_pool *pool)
{
    return pool && pool->mbufs && rte_lcore_id() != LCORE_ID_ANY ? rte_pktmbuf_alloc(pool->mbufs) : NULL;
}
struct rte_mbuf *ker_packet_clone(struct ker_packet_pool *pool, struct rte_mbuf *packet)
{
    if (!pool || !pool->mbufs || !packet || packet->nb_segs != 1 || packet->next ||
        rte_lcore_id() == LCORE_ID_ANY)
        return NULL;
    return rte_pktmbuf_clone(packet, pool->mbufs);
}
void ker_packet_free(struct rte_mbuf *packet)
{
    if (packet)
        rte_pktmbuf_free(packet);
}
int ker_packet_make_writable(struct ker_packet_pool *pool, struct rte_mbuf **packet)
{
    if (!pool || !pool->mbufs || !packet || !*packet || rte_lcore_id() == LCORE_ID_ANY)
        return -EINVAL;
    struct rte_mbuf *old = *packet;
    if (old->nb_segs != 1 || old->next || RTE_MBUF_HAS_EXTBUF(old))
        return -ENOTSUP;
    if (RTE_MBUF_DIRECT(old) && rte_mbuf_refcnt_read(old) == 1)
        return 0;
    struct rte_mbuf *copy = rte_pktmbuf_copy(old, pool->mbufs, 0, UINT32_MAX);
    if (!copy)
        return -ENOMEM;
    if (copy->nb_segs != 1 || (uint32_t)old->data_off + old->data_len > copy->buf_len) {
        ker_packet_free(copy);
        return -ENOSPC;
    }
    memmove((uint8_t *)copy->buf_addr + old->data_off,
        rte_pktmbuf_mtod(copy, void *), old->data_len);
    copy->data_off = old->data_off;
    /* Preserve pulled headers as well as active packet bytes. */
    memcpy(copy->buf_addr, old->buf_addr, old->data_off);
    *packet = copy;
    ker_packet_free(old);
    return 0;
}
