#ifndef KER_TEST_EAL_H
#define KER_TEST_EAL_H
#include "check.h"
#include <rte_eal.h>
#include <sched.h>
#include <unistd.h>
static inline void ker_test_eal_init(void)
{
    cpu_set_t allowed;
    CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) {}
    CHECK(cpu < CPU_SETSIZE);
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=ker-test-%ld", (long)getpid());
    char *args[] = {"ker-eal-test", mapping, prefix, "--no-huge", "--no-pci", "--no-shconf",
                   "--iova-mode=va", "--no-telemetry", "-m", "64"};
    CHECK(rte_eal_init((int)(sizeof(args) / sizeof(args[0])), args) >= 0);
}
#endif
