#ifndef KER_RUNTIME_TCP_LISTENER_H
#define KER_RUNTIME_TCP_LISTENER_H
#include "runtime/neighbor.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"

/* Fixed-peer profile; optional bounded passive streams and FIN close. */
enum ker_tcp_request_state { KER_TCP_REQUEST_FREE, KER_TCP_REQUEST_SYN,
    KER_TCP_REQUEST_READY, KER_TCP_REQUEST_RESET, KER_TCP_REQUEST_FAILED,
    KER_TCP_REQUEST_FIN_WAIT_1, KER_TCP_REQUEST_FIN_WAIT_2,
    KER_TCP_REQUEST_CLOSING, KER_TCP_REQUEST_CLOSE_WAIT,
    KER_TCP_REQUEST_LAST_ACK, KER_TCP_REQUEST_TIME_WAIT,
    KER_TCP_REQUEST_CLOSED };
struct ker_tcp_request {
    uint64_t generation, retry_ms, deadline_ms;
    uint64_t send_retry_ms, send_deadline_ms, send_backoff_ms;
    uint64_t close_deadline_ms, time_wait_deadline_ms;
    uint32_t local_isn, peer_isn;
    uint32_t receive_next, receive_right;
    uint32_t send_unacknowledged, send_next, send_right;
    __be16 peer_port;
    uint16_t send_mss, receive_bytes, receive_head, peer_window, send_bytes, send_head;
    enum ker_tcp_request_state state;
    int error;
    bool accepted, ack_pending, peer_eof, local_fin, local_fin_acked;
    bool active_close, time_wait_saturated;
};
struct ker_tcp_listener;
struct ker_tcp_request_handle {
    const struct ker_tcp_listener *listener;
    size_t slot;
    uint64_t generation;
};
/* Called synchronously with lifecycle/reentry protection. Must provide a fresh
 * unpredictable ISN for this tuple; no built-in deterministic default exists.
 * Returns 0 or negative errno; must not block or mutate borrowed objects. */
typedef int (*ker_tcp_isn_fn)(void *, __be16 peer_port, uint32_t *);
struct ker_tcp_listener_config {
    __be16 port;
    uint16_t window, mss;
    uint8_t ttl;
    uint64_t retry_ms, timeout_ms;
    ker_tcp_isn_fn next_isn;
    void *arg;
    /* Optional flat arena: at least request_capacity * receive_capacity bytes,
     * one receive_capacity-byte ring per slot. Remains stable until cleanup. */
    unsigned char *receive_storage;
    size_t receive_storage_size;
    uint16_t receive_capacity;
    /* Optional flat arena: at least request_capacity * send_capacity bytes,
     * one retransmit ring per slot. Enables one outstanding send segment. */
    unsigned char *send_storage;
    size_t send_storage_size;
    uint16_t send_capacity;
    /* Opt-in bounded FIN close; requires both receive and send arenas. */
    uint64_t time_wait_ms;
};
struct ker_tcp_listener {
    struct ker_transport_receiver *receiver;
    struct ker_neighbor_table *neighbors;
    struct neighbour *peer;
    struct ker_tx_export *tx;
    struct ker_tcp_request *requests;
    struct ker_tcp_listener_config config;
    __be32 peer_ip;
    size_t capacity, count, cursor;
    uint64_t next_generation, now_ms;
    uint64_t timed_out, dropped_full;
    int last_tx_error;
    bool busy;
};
/* Stable zero-initialized listener and request storage. Peer must have a
 * permanent neighbor mapping; only its local-unicast IPv4 packets are served.
 * Uses caller-sampled monotonic milliseconds: poll before RX on each iteration.
 * Pins receiver, peer/table and exporter until empty-only cleanup. */
int ker_tcp_listener_init(struct ker_tcp_listener *, struct ker_transport_receiver *,
    struct ker_neighbor_table *, __be32 peer_ip, struct ker_tx_export *,
    struct ker_tcp_request *, size_t, const struct ker_tcp_listener_config *, uint64_t now_ms);
/* Fair scan with bounded work; returns number of inspected slots (including free slots).
 * Time rollback is rejected; retries preserve the initial sequence numbers.
 * Deadlines free unaccepted requests. RESET records are freed after TX drains. */
int ker_tcp_listener_poll(struct ker_tcp_listener *, uint64_t now_ms, unsigned int budget);
/* Returns 1 with one completed handshake, 0 if none, negative errno on error.
 * Output remains untouched unless 1 is returned. */
int ker_tcp_listener_accept(struct ker_tcp_listener *, struct ker_tcp_request_handle *);
int ker_tcp_listener_snapshot(struct ker_tcp_listener *, struct ker_tcp_request_handle,
    struct ker_tcp_request *);
/* Copy available passive-stream bytes. Requires opt-in storage and a live
 * accepted handle; destination must not overlap its receive ring. Returns
 * bytes copied, 0 at drained peer EOF, or -EAGAIN if empty before EOF. */
int ker_tcp_listener_read(struct ker_tcp_listener *, struct ker_tcp_request_handle,
    void *destination, uint16_t capacity);
/* Copy and admit up to one segment; return bytes locally admitted or negative
 * errno. Requires accepted send storage and a nonzero peer window. */
int ker_tcp_listener_write(struct ker_tcp_listener *, struct ker_tcp_request_handle,
    const void *source, uint16_t length);
/* Gracefully half-close the local send direction after all data is ACKed. */
int ker_tcp_listener_shutdown_write(struct ker_tcp_listener *, struct ker_tcp_request_handle);
/* Retire a CLOSED request after EOF is observed, bytes drained and TX is empty. */
int ker_tcp_listener_release(struct ker_tcp_listener *, struct ker_tcp_request_handle);
/* Abort with RST. Queue failure leaves the request unchanged; successful reset
 * invalidates the handle after poll observes an empty exporter. */
int ker_tcp_listener_reset(struct ker_tcp_listener *, struct ker_tcp_request_handle);
int ker_tcp_listener_cleanup(struct ker_tcp_listener *);
#endif
