#ifndef KER_RUNTIME_TCP_ACTIVE_H
#define KER_RUNTIME_TCP_ACTIVE_H
#include "runtime/neighbor.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"

enum ker_tcp_active_state { KER_TCP_ACTIVE_NONE, KER_TCP_ACTIVE_SYN,
    KER_TCP_ACTIVE_READY, KER_TCP_ACTIVE_RESET, KER_TCP_ACTIVE_FAILED,
    KER_TCP_ACTIVE_FIN_WAIT_1, KER_TCP_ACTIVE_FIN_WAIT_2, KER_TCP_ACTIVE_CLOSING,
    KER_TCP_ACTIVE_CLOSE_WAIT, KER_TCP_ACTIVE_LAST_ACK, KER_TCP_ACTIVE_TIME_WAIT,
    KER_TCP_ACTIVE_CLOSED };
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
    /* Optional caller-owned stable receive ring. Capacity must equal window.
     * NULL/zero preserves the handshake-only profile. */
    unsigned char *receive_buffer;
    uint16_t receive_capacity;
    /* Optional exclusive stable storage for one outstanding segment. */
    unsigned char *send_buffer;
    uint16_t send_capacity;
    /* Opt-in graceful close. Choose twice the deployment maximum segment
     * lifetime; zero preserves the legacy unsupported-FIN boundary. */
    uint64_t time_wait_ms;
};
struct ker_tcp_active_snapshot {
    enum ker_tcp_active_state state;
    uint32_t local_isn, peer_isn;
    uint16_t send_mss, peer_window;
    int error, last_tx_error;
    uint32_t receive_next;
    uint16_t receive_bytes;
    bool ack_pending;
    uint32_t send_unacknowledged, send_next;
    uint16_t send_bytes;
    bool peer_eof, local_fin, local_fin_acked;
};
/* Caller owns zero-initialized stable storage until empty-only cleanup. One
 * active tuple per receiver, with a permanent configured IPv4 peer.
 * READY means the final ACK entered the bounded local TX path. Optional receive
 * storage enables in-order data reception and one-segment sending, plus opt-in FIN close; no simultaneous
 * open or negotiated options beyond MSS.
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
    uint32_t receive_right;
    uint16_t receive_head, send_head;
    uint32_t send_right;
    uint64_t send_retry_ms, send_deadline_ms, send_backoff_ms;
    uint64_t close_deadline_ms, time_wait_deadline_ms;
    bool active_close, time_wait_saturated;
};
int ker_tcp_active_start(struct ker_tcp_active *, struct ker_transport_receiver *,
    struct ker_neighbor_table *, __be32 peer_ip, struct ker_tx_export *,
    const struct ker_tcp_active_config *, uint64_t now_ms);
/* Caller samples monotonic milliseconds and polls before RX, including idle
 * iterations. Fixed SYN retry interval and absolute deadline; no extension on
 * TX failure. READY retries data with exponential backoff/absolute timeout
 * and pending receive/window ACKs. Returns 1 for
 * a retry/expiry action, 0 otherwise, negative errno
 * for invalid use; retry admission status is also exposed in last_tx_error. */
int ker_tcp_active_poll(struct ker_tcp_active *, uint64_t now_ms);
int ker_tcp_active_snapshot(struct ker_tcp_active *, struct ker_tcp_active_snapshot *);
/* Abort with RST; admission failure preserves state. Cleanup requires RESET or
 * FAILED (or drained CLOSED) and an empty exporter, including shared traffic.
 * Abort cannot shorten TIME_WAIT. */
int ker_tcp_active_reset(struct ker_tcp_active *);
/* Copy up to capacity bytes, returning byte count or negative errno. Destination
 * must not overlap the receive ring. With graceful close, drain bytes before
 * a zero return reports EOF. Freeing space
 * schedules a window ACK, retried by poll. Reset/refusal invalidates unread data. */
int ker_tcp_active_read(struct ker_tcp_active *, void *destination, uint16_t capacity);
/* Copy/admit at most one MSS/window/buffer-sized segment, return accepted bytes.
 * A positive result means local admission, not peer delivery; snapshot send_bytes
 * tracks acknowledgment. EAGAIN if a segment is outstanding or window is zero.
 * Caller polls before writing; source must not overlap either private buffer. */
int ker_tcp_active_write(struct ker_tcp_active *, const void *source, uint16_t length);
/* Opt-in half-close; no outstanding data and a nonzero peer window required.
 * Successful FIN admission permanently disables writes. Poll handles FIN
 * retries and the absolute close timeout; cleanup waits for close completion. */
int ker_tcp_active_shutdown_write(struct ker_tcp_active *);
int ker_tcp_active_cleanup(struct ker_tcp_active *);
#endif
