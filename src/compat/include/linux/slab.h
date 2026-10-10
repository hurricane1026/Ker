#ifndef KER_COMPAT_LINUX_SLAB_H
#define KER_COMPAT_LINUX_SLAB_H
#include <linux/gfp.h>
#include <stddef.h>
#define ZERO_SIZE_PTR ((void *)16)
#define ZERO_OR_NULL_PTR(ptr) ((uintptr_t)(ptr) <= (uintptr_t)ZERO_SIZE_PTR)
#define SLAB_HWCACHE_ALIGN (1U << 4)
struct kmem_cache;
/* Heap allocations use the DPDK heap and GFP_KERNEL only. Fixed object caches
 * use rte_mempool and also support GFP_ATOMIC/NOWAIT without heap fallback.
 * Packet payloads use mbuf pools, not this general-purpose heap API. */
void *ker_kmalloc(size_t size, gfp_t flags);
void *ker_kzalloc(size_t size, gfp_t flags);
void *ker_kcalloc(size_t count, size_t size, gfp_t flags);
void *ker_krealloc(void *ptr, size_t size, gfp_t flags);
void ker_kfree(const void *ptr);
size_t ker_ksize(const void *ptr);
size_t ker_kmalloc_size_roundup(size_t size);
struct kmem_cache *ker_kmem_cache_create(const char *name, unsigned int size,
    unsigned int align, unsigned int flags, void (*ctor)(void *));
void ker_kmem_cache_destroy(struct kmem_cache *cache);
void *ker_kmem_cache_alloc(struct kmem_cache *cache, gfp_t flags);
void *ker_kmem_cache_zalloc(struct kmem_cache *cache, gfp_t flags);
void ker_kmem_cache_free(struct kmem_cache *cache, void *ptr);
unsigned int ker_kmem_cache_size(struct kmem_cache *cache);
#define kmalloc ker_kmalloc
#define kzalloc ker_kzalloc
#define kcalloc ker_kcalloc
#define krealloc ker_krealloc
#define kfree ker_kfree
#define ksize ker_ksize
#define kmalloc_size_roundup ker_kmalloc_size_roundup
#define kmem_cache_create ker_kmem_cache_create
#define kmem_cache_destroy ker_kmem_cache_destroy
#define kmem_cache_alloc ker_kmem_cache_alloc
#define kmem_cache_zalloc ker_kmem_cache_zalloc
#define kmem_cache_free ker_kmem_cache_free
#define kmem_cache_size ker_kmem_cache_size
#endif
