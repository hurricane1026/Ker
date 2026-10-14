#ifndef KER_RUNTIME_TCP_ACTIVE_H
#define KER_RUNTIME_TCP_ACTIVE_H
#include "runtime/neighbor.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"

enum ker_tcp_active_state { KER_TCP_ACTIVE_NONE, KER_TCP_ACTIVE_SYN,
    KER_TCP_ACTIVE_READY, KER_TCP_ACTIVE_RESET, KER_TCP_ACTIVE_FAILED };
/* Must supply a fresh unpredictable ISN, return 0 or negative errno, and not
 * block or mutate borrowed objects. Called under lifecycle/reentry protection. */
typedef int (*ker_tcp_active_isn_fn)(void *, __be16 peer_port, uint32_t *);
struct ker_tcp_active_config {
    __be16 local_port, peer_port;
    uint16_t window, mss;
    uint8_t ttl;
    uint64_t retry_ms, timeout_ms;
    ker_tcp_active_isn_fn next_isn;
    void *arg;
};
struct ker_tcp_active_snapshot {
    enum ker_tcp_active_state state;
    uint32_t local_isn, peer_isn;
    uint16_t send_mss, peer_window;
    int error, last_tx_error;
};
/* Caller owns zero-initialized stable storage until empty-only cleanup. One
 * active tuple per receiver, with a permanent configured IPv4 peer. This is
 * handshake-only: READY means the final ACK entered the bounded local TX path.
 * No stream API, FIN close, simultaneous open or negotiated options beyond MSS.
 * The peer/table, receiver and exporter stay pinned until cleanup. */
struct ker_tcp_active {
    struct ker_transport_receiver *receiver;
    struct ker_neighbor_table *neighbors;
    struct neighbour *peer;
    struct ker_tx_export *tx;
    __be32 peer_ip;
    struct ker_tcp_active_config config;
    struct ker_tcp_active_snapshot status;
    uint64_t now_ms, retry_ms, deadline_ms;
    bool busy, peer_known;
};
int ker_tcp_active_start(struct ker_tcp_active *, struct ker_transport_receiver *,
    struct ker_neighbor_table *, __be32 peer_ip, struct ker_tx_export *,
    const struct ker_tcp_active_config *, uint64_t now_ms);
/* Caller samples monotonic milliseconds and polls before RX, including idle
 * iterations. Fixed SYN retry interval and absolute deadline; no extension on
 * TX failure. Returns 1 for a retry/expiry action, 0 otherwise, negative errno
 * for invalid use; retry admission status is also exposed in last_tx_error. */
int ker_tcp_active_poll(struct ker_tcp_active *, uint64_t now_ms);
int ker_tcp_active_snapshot(struct ker_tcp_active *, struct ker_tcp_active_snapshot *);
/* Abort with RST; admission failure preserves state. Cleanup requires RESET or
 * FAILED and an empty exporter, including unrelated traffic sharing it. */
int ker_tcp_active_reset(struct ker_tcp_active *);
int ker_tcp_active_cleanup(struct ker_tcp_active *);
#endif
