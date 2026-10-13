#ifndef KER_RUNTIME_ICMPV4_PMTU_H
#define KER_RUNTIME_ICMPV4_PMTU_H
#include "runtime/icmpv4-packet-view.h"
#include "runtime/neighbor-timer.h"

typedef uint64_t (*ker_icmpv4_pmtu_clock_fn)(void *);
/* Return 1 only when this exact quoted flow/packet was actually sent, 0 when
 * it is not evidence, or a negative errno on verifier failure. */
typedef int (*ker_icmpv4_pmtu_confirm_fn)(void *, __be32 local, __be32 peer,
    const struct ker_icmpv4_quoted_ipv4_view *);

struct ker_icmpv4_pmtu {
    struct ker_neighbor_monitor *monitor;
    ker_icmpv4_pmtu_clock_fn clock;
    void *clock_arg;
    ker_icmpv4_pmtu_confirm_fn confirm;
    void *confirm_arg;
    __be32 local, peer;
    uint32_t initial_mtu, current_mtu;
    uint64_t lifetime_ms, last_now_ms, expires_ms;
    bool clock_started, attached, busy;
};

int ker_icmpv4_pmtu_init(struct ker_icmpv4_pmtu *, struct ker_neighbor_monitor *,
    uint32_t initial_mtu, uint64_t lifetime_ms, ker_icmpv4_pmtu_clock_fn,
    void *clock_arg, ker_icmpv4_pmtu_confirm_fn, void *confirm_arg);
/* Return 1 when a verified notification lowers the cache, 0 for valid but
 * non-updating evidence, or a negative errno. */
int ker_icmpv4_pmtu_apply(struct ker_icmpv4_pmtu *,
    const struct ker_icmpv4_packet_view *outer,
    const struct ker_icmpv4_quoted_ipv4_view *quote);
int ker_icmpv4_pmtu_current_mtu(struct ker_icmpv4_pmtu *, uint32_t *);
int ker_icmpv4_pmtu_cleanup(struct ker_icmpv4_pmtu *);
#endif
