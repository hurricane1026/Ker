#ifndef KER_RUNTIME_BUFFER_H
#define KER_RUNTIME_BUFFER_H
#include <rte_mbuf.h>
/* Native DPDK packet backing for the future skb adapter. No synthetic
 * sk_buff layout or independent payload refcounter is introduced. */
struct ker_packet_pool { struct rte_mempool *mbufs; };
/* Initialize pool to {0}. All users must be quiescent before cleanup. */
int ker_packet_pool_init(struct ker_packet_pool *pool, const char *name,
    unsigned int count, unsigned int cache_size, uint16_t data_room_size, int socket_id);
/* Refuses to destroy a pool while direct OR indirect mbufs are outstanding. */
int ker_packet_pool_cleanup(struct ker_packet_pool *pool);
struct rte_mbuf *ker_packet_alloc(struct ker_packet_pool *pool);
struct rte_mbuf *ker_packet_clone(struct ker_packet_pool *pool, struct rte_mbuf *packet);
void ker_packet_free(struct rte_mbuf *packet);
/* Single segment only for this initial bridge. COW preserves offsets and
 * packet bytes, replacing *packet only on success; failure retains ownership.
 * Shared descriptor references require the caller to own one reference. */
int ker_packet_make_writable(struct ker_packet_pool *pool, struct rte_mbuf **packet);
#endif
