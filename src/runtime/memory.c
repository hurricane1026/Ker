#include "runtime/memory.h"
#include <linux/slab.h>
#include <linux/bug.h>
#include <linux/irqflags.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <errno.h>
#include <string.h>

#define KER_MEMORY_MAGIC UINT64_C(0x6b65726d656d6f72)
struct kmem_cache { struct rte_mempool *pool; unsigned int size; };
#define ATOMIC_CLASSES_MAX 8
struct atomic_pool {
    struct rte_mempool *pool;
    unsigned int size;
    unsigned int lcore;
    size_t in_use;
    size_t requests;
    size_t failures;
};
struct allocation {
    uint64_t magic;
    size_t capacity;
    size_t requested;
    void *base;
    struct kmem_cache *cache;
    struct atomic_pool *atomic_pool;
};
#define HEADER_SIZE RTE_CACHE_LINE_ROUNDUP(sizeof(struct allocation))
static _Thread_local bool initialized;
static _Thread_local int memory_socket;
static _Thread_local unsigned int object_count;
static _Thread_local unsigned int memory_lcore;
static _Thread_local struct atomic_pool atomic_pools[ATOMIC_CLASSES_MAX];
static _Thread_local size_t atomic_pool_count;
static bool worker_active(void)
{
    return initialized && rte_lcore_id() != LCORE_ID_ANY && rte_lcore_id() == memory_lcore;
}
static _Thread_local long fail_after = -1;
static size_t live_allocations;

int ker_memory_init(int socket_id, unsigned int cache_objects)
{
    if (initialized)
        return -EALREADY;
    if (rte_lcore_id() == LCORE_ID_ANY || rte_eal_process_type() != RTE_PROC_PRIMARY)
        return -EPERM;
    if (socket_id < SOCKET_ID_ANY || !cache_objects)
        return -EINVAL;
    if (socket_id != SOCKET_ID_ANY) {
        bool found = false;
        for (unsigned int i = 0; i < rte_socket_count(); ++i)
            found |= rte_socket_id_by_idx(i) == socket_id;
        if (!found)
            return -EINVAL;
    }
    memory_lcore = rte_lcore_id();
    memory_socket = socket_id;
    object_count = cache_objects;
    initialized = true;
    return 0;
}
int ker_memory_shutdown(void)
{
    if (initialized && !worker_active())
        return -EXDEV;
    if (ker_memory_live_allocations())
        return -EBUSY;
    /* Call only after all allocation/return users have quiesced. */
    for (size_t i = 0; i < atomic_pool_count; ++i) {
        rte_mempool_free(atomic_pools[i].pool);
        atomic_pools[i] = (struct atomic_pool){0};
    }
    atomic_pool_count = 0;
    initialized = false;
    fail_after = -1;
    return 0;
}
void ker_memory_fail_after(long count) { fail_after = count; }
size_t ker_memory_live_allocations(void)
{
    return __atomic_load_n(&live_allocations, __ATOMIC_ACQUIRE);
}
static bool should_fail(void)
{
    if (fail_after == 0)
        return true;
    if (fail_after > 0)
        --fail_after;
    return false;
}
static bool heap_flags(gfp_t flags)
{
    return worker_active() && !ker_local_irq_disabled() &&
        (flags & ~(__GFP_ZERO | __GFP_NOWARN)) == GFP_KERNEL;
}
size_t ker_kmalloc_size_roundup(size_t size)
{
    if (size > SIZE_MAX - (RTE_CACHE_LINE_SIZE - 1))
        return 0;
    return RTE_CACHE_LINE_ROUNDUP(size);
}
static struct allocation *header_of(const void *ptr)
{
    struct allocation *header = (struct allocation *)ptr - 1;
    WARN_ON_ONCE(header->magic != KER_MEMORY_MAGIC);
    return header;
}
static void *initialize_allocation(void *base, size_t capacity, size_t requested,
    struct kmem_cache *cache, gfp_t flags)
{
    void *ptr = (unsigned char *)base + HEADER_SIZE;
    struct allocation *header = (struct allocation *)ptr - 1;
    *header = (struct allocation){.magic = KER_MEMORY_MAGIC, .capacity = capacity,
        .requested = requested, .base = base, .cache = cache};
    if (flags & __GFP_ZERO)
        memset(ptr, 0, capacity);
    __atomic_add_fetch(&live_allocations, 1, __ATOMIC_RELAXED);
    return ptr;
}
int ker_memory_atomic_pools_init(const char *name,
    const struct ker_memory_pool_config *classes, size_t count)
{
    if (!worker_active() || ker_local_irq_disabled())
        return -EPERM;
    if (atomic_pool_count)
        return -EALREADY;
    if (!name || !*name || !classes || !count || count > ATOMIC_CLASSES_MAX)
        return -EINVAL;
    for (size_t i = 0; i < count; ++i) {
        if (!classes[i].size || classes[i].size % RTE_CACHE_LINE_SIZE ||
            classes[i].size > UINT32_MAX - HEADER_SIZE || !classes[i].objects ||
            classes[i].cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE ||
            (i && classes[i].size <= classes[i - 1].size))
            return -EINVAL;
    }
    int error = 0;
    for (size_t i = 0; i < count; ++i) {
        char pool_name[RTE_MEMPOOL_NAMESIZE];
        int length = snprintf(pool_name, sizeof(pool_name), "%s_%u_%zu", name, memory_lcore, i);
        if (length < 0 || (size_t)length >= sizeof(pool_name)) {
            error = -ENAMETOOLONG;
            break;
        }
        struct rte_mempool *pool = rte_mempool_create(pool_name, classes[i].objects,
            classes[i].size + HEADER_SIZE, classes[i].cache_size, 0,
            NULL, NULL, NULL, NULL, memory_socket, 0);
        if (!pool) {
            error = -rte_errno;
            break;
        }
        atomic_pools[i] = (struct atomic_pool){.pool = pool, .size = classes[i].size,
            .lcore = memory_lcore};
        ++atomic_pool_count;
    }
    if (error) {
        for (size_t i = 0; i < atomic_pool_count; ++i) {
            rte_mempool_free(atomic_pools[i].pool);
            atomic_pools[i] = (struct atomic_pool){0};
        }
        atomic_pool_count = 0;
    }
    return error;
}
int ker_memory_atomic_pool_stats(size_t index, struct ker_memory_pool_stats *stats)
{
    if (!worker_active())
        return -EPERM;
    if (!stats || index >= atomic_pool_count)
        return -EINVAL;
    struct atomic_pool *pool = &atomic_pools[index];
    *stats = (struct ker_memory_pool_stats){.size = pool->size, .objects = pool->pool->size,
        .in_use = __atomic_load_n(&pool->in_use, __ATOMIC_RELAXED),
        .requests = pool->requests, .failures = pool->failures};
    return 0;
}
static bool atomic_flags(gfp_t flags)
{
    gfp_t profile = flags & ~(__GFP_ZERO | __GFP_NOWARN);
    return worker_active() && (profile == GFP_ATOMIC || profile == (GFP_NOWAIT & ~__GFP_NOWARN));
}
void *ker_kmalloc(size_t size, gfp_t flags)
{
    bool atomic = atomic_flags(flags);
    if (!atomic && !heap_flags(flags))
        return NULL;
    if (!size)
        return ZERO_SIZE_PTR;
    size_t capacity = ker_kmalloc_size_roundup(size);
    if (!capacity || capacity > SIZE_MAX - HEADER_SIZE)
        return NULL;
    if (atomic) {
        for (size_t i = 0; i < atomic_pool_count; ++i) {
            struct atomic_pool *pool = &atomic_pools[i];
            if (size > pool->size)
                continue;
            void *base;
            ++pool->requests;
            /* Never steal from larger classes or fall back to heap. */
            if (should_fail() || rte_mempool_get(pool->pool, &base) != 0) {
                ++pool->failures;
                return NULL;
            }
            void *ptr = initialize_allocation(base, pool->size, size, NULL, flags);
            header_of(ptr)->atomic_pool = pool;
            __atomic_add_fetch(&pool->in_use, 1, __ATOMIC_RELAXED);
            return ptr;
        }
        return NULL;
    }
    if (should_fail())
        return NULL;
    void *base = rte_malloc_socket("ker_control", capacity + HEADER_SIZE,
                                  RTE_CACHE_LINE_SIZE, memory_socket);
    return base ? initialize_allocation(base, capacity, size, NULL, flags) : NULL;
}
void *ker_kzalloc(size_t size, gfp_t flags) { return ker_kmalloc(size, flags | __GFP_ZERO); }
void *ker_kcalloc(size_t count, size_t size, gfp_t flags)
{
    if (count && size > SIZE_MAX / count)
        return NULL;
    return ker_kzalloc(count * size, flags);
}
size_t ker_ksize(const void *ptr)
{
    return ZERO_OR_NULL_PTR(ptr) ? 0 : header_of(ptr)->capacity;
}
void ker_kfree(const void *ptr)
{
    if (ZERO_OR_NULL_PTR(ptr))
        return;
    struct allocation *header = header_of(ptr);
    WARN_ON_ONCE(header->cache != NULL);
    void *base = header->base;
    struct atomic_pool *pool = header->atomic_pool;
    if (pool)
        WARN_ON_ONCE(!worker_active());
    header->magic = 0;
    if (pool) {
        /* A foreign worker returns to the common ring, so its private cache
         * cannot strand objects when that thread unregisters. */
        if (memory_lcore == pool->lcore)
            rte_mempool_put(pool->pool, base);
        else
            rte_mempool_generic_put(pool->pool, &base, 1, NULL);
        __atomic_sub_fetch(&pool->in_use, 1, __ATOMIC_RELAXED);
    } else {
        rte_free(base);
    }
    __atomic_sub_fetch(&live_allocations, 1, __ATOMIC_RELEASE);
}
void *ker_krealloc(void *ptr, size_t size, gfp_t flags)
{
    if (!size) { ker_kfree(ptr); return ZERO_SIZE_PTR; }
    if (!heap_flags(flags) && !atomic_flags(flags))
        return NULL;
    if (ZERO_OR_NULL_PTR(ptr))
        return ker_kmalloc(size, flags);
    struct allocation *old = header_of(ptr);
    WARN_ON_ONCE(old->cache != NULL);
    if (size <= old->capacity) {
        if ((flags & __GFP_ZERO) && size > old->requested)
            memset((unsigned char *)ptr + old->requested, 0, size - old->requested);
        old->requested = size;
        return ptr;
    }
    void *new_ptr = ker_kmalloc(size, flags);
    if (!new_ptr)
        return NULL;
    memcpy(new_ptr, ptr, flags & __GFP_ZERO ? old->requested : old->capacity);
    ker_kfree(ptr);
    return new_ptr;
}
struct kmem_cache *ker_kmem_cache_create(const char *name, unsigned int size,
    unsigned int align, unsigned int flags, void (*ctor)(void *))
{
    if (!name || !size || ctor || (flags & ~SLAB_HWCACHE_ALIGN) ||
        (align && ((align & (align - 1)) || align > RTE_CACHE_LINE_SIZE)))
        return NULL;
    size_t capacity = ker_kmalloc_size_roundup(size);
    if (capacity > UINT32_MAX - HEADER_SIZE)
        return NULL;
    struct kmem_cache *cache = ker_kzalloc(sizeof(*cache), GFP_KERNEL);
    if (!cache)
        return NULL;
    cache->pool = rte_mempool_create(name, object_count, (unsigned int)(capacity + HEADER_SIZE),
        0, 0, NULL, NULL, NULL, NULL, memory_socket, 0);
    if (!cache->pool) { ker_kfree(cache); return NULL; }
    cache->size = size;
    return cache;
}
void ker_kmem_cache_destroy(struct kmem_cache *cache)
{
    if (!cache)
        return;
    WARN_ON_ONCE(rte_mempool_in_use_count(cache->pool) != 0);
    rte_mempool_free(cache->pool);
    ker_kfree(cache);
}
void *ker_kmem_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
    void *base;
    gfp_t profile = flags & ~(__GFP_ZERO | __GFP_NOWARN);
    if (!worker_active() || !cache ||
        (profile != GFP_KERNEL && profile != GFP_ATOMIC &&
         profile != (GFP_NOWAIT & ~__GFP_NOWARN)) || should_fail())
        return NULL;
    if (rte_mempool_generic_get(cache->pool, &base, 1, NULL) != 0)
        return NULL;
    return initialize_allocation(base, ker_kmalloc_size_roundup(cache->size), cache->size, cache, flags);
}
void *ker_kmem_cache_zalloc(struct kmem_cache *cache, gfp_t flags)
{
    return ker_kmem_cache_alloc(cache, flags | __GFP_ZERO);
}
void ker_kmem_cache_free(struct kmem_cache *cache, void *ptr)
{
    if (ZERO_OR_NULL_PTR(ptr))
        return;
    struct allocation *header = header_of(ptr);
    WARN_ON_ONCE(!cache || header->cache != cache || rte_lcore_id() == LCORE_ID_ANY);
    void *base = header->base;
    header->magic = 0;
    __atomic_sub_fetch(&live_allocations, 1, __ATOMIC_RELAXED);
    rte_mempool_generic_put(cache->pool, &base, 1, NULL);
}
unsigned int ker_kmem_cache_size(struct kmem_cache *cache) { return cache ? cache->size : 0; }
