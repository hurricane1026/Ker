#ifndef KER_RUNTIME_ICMP_ECHO_SERVICE_H
#define KER_RUNTIME_ICMP_ECHO_SERVICE_H
#include "runtime/transport-receive.h"
#include "runtime/neighbor-timer.h"
#include "runtime/tx-export.h"

/* Zero-initialize stable service storage. Opt-in worker-local echo adapter;
 * enable/disable are owner-lcore operations outside receive dispatch. All
 * pointers must remain stable while enabled. The receiver, configured source
 * address, monitored explicit peer and bounded resolver must share one device,
 * context and lcore. Counters describe service admission and native output
 * submission; submission may queue for neighbor resolution. */
struct ker_icmp_echo_service {
    struct ker_transport_receiver *receiver;
    struct ker_neighbor_monitor *monitor;
    uint8_t ttl;
    unsigned int requests;
    unsigned int replies_submitted;
    unsigned int dropped;
    int last_error;
};

int ker_icmp_echo_service_enable(struct ker_icmp_echo_service *,
    struct ker_transport_receiver *, struct ker_neighbor_monitor *, uint8_t ttl);
/* Detaches the adapter and releases its wrapper pins. Replies already owned by
 * native neighbor resolution or the TX exporter remain queued there. */
int ker_icmp_echo_service_disable(struct ker_icmp_echo_service *);

#endif
