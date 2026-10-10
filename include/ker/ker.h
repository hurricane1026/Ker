#ifndef KER_KER_H
#define KER_KER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental API. These bits describe working runtime capabilities,
 * not the presence of third-party source trees. */
#define KER_CAP_DPDK_IO (UINT64_C(1) << 0)
#define KER_CAP_LINUX_STACK (UINT64_C(1) << 1)
#define KER_CAP_IPV4 (UINT64_C(1) << 2)
#define KER_CAP_UDP (UINT64_C(1) << 3)
#define KER_CAP_TCP (UINT64_C(1) << 4)

/* Returns a process-lifetime string; the caller must not free it. */
const char *ker_version(void);

/* Returns zero until a runtime backend has been implemented and validated. */
uint64_t ker_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif
