#ifndef KER_RUNTIME_MEMORY_H
#define KER_RUNTIME_MEMORY_H
#include <stddef.h>
/* Call after successful EAL initialization, on the owning EAL worker. The
 * selected NUMA socket is thread local. No implicit libc fallback exists. */
int ker_memory_init(int socket_id, unsigned int cache_objects);
int ker_memory_shutdown(void);
void ker_memory_fail_after(long count);
size_t ker_memory_live_allocations(void);
#endif
