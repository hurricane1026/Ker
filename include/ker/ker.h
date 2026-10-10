#ifndef KER_KER_H
#define KER_KER_H

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define KER_API __attribute__((visibility("default")))
#else
#define KER_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental API. These bits describe implemented capabilities,
 * not the presence of third-party source trees. */
#define KER_CAP_DPDK_IO (UINT64_C(1) << 0)
#define KER_CAP_LINUX_STACK (UINT64_C(1) << 1)
#define KER_CAP_IPV4 (UINT64_C(1) << 2)
#define KER_CAP_UDP (UINT64_C(1) << 3)
#define KER_CAP_TCP (UINT64_C(1) << 4)
#define KER_CAP_CHECKSUM (UINT64_C(1) << 5)

/* Returns a process-lifetime string; the caller must not free it. */
KER_API const char *ker_version(void);

/* Protocol/IO bits remain unset until their runtime backends are validated. */
KER_API uint64_t ker_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif
