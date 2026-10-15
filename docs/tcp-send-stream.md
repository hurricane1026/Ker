# Bounded active TCP sending

The private fixed-peer active profile accepts an optional caller-owned
`send_buffer`/`send_capacity`, stable and exclusive until cleanup. The send and
receive buffers must not overlap. `ker_tcp_active_write()` copies and admits up
to one segment, capped by negotiated MSS, usable peer window and buffer capacity.
The source must not overlap either private buffer. A positive result is local
TX admission; it does not claim delivery. Snapshot `send_bytes` reaches zero
only after a valid cumulative acknowledgment (or explicit abort/failure).

At most one segment is outstanding. Further writes return `-EAGAIN` until it is
fully acknowledged. Partial ACKs retire only the acknowledged prefix; retries
send the retained suffix at `send_unacknowledged`. `send_next` includes all
admitted bytes. ACKs outside that serial-number interval cannot free storage.
Only an ACK at the exact next receive sequence updates send progress and the
peer window edge, computed from that ACK's acknowledgment plus unscaled window.
ACK and incoming payload are processed together for full duplex. All outgoing
ACK-bearing data also commits the advertised local receive edge on admission.

Poll with a caller-sampled monotonic clock before RX and application writes,
including idle iterations. Each admitted write starts a fresh absolute
`timeout_ms` deadline. Retries begin after `retry_ms`, then double with saturated
arithmetic. Partial/duplicate ACKs and TX backpressure do not extend the deadline;
failed retransmission admission still advances the retry schedule. Expiry is
checked before receive acknowledgment or pending local ACK work, discards private
send/receive state, and reports `-ETIMEDOUT`. Caller-configured retry/timeout values
remain the policy when adaptive estimation is disabled (the default).

With `adaptive_rto`, ordinary DATA flights start at 1000 ms and use RFC 6298
RTT sampling with a 1000–60000 ms RTO range. A clean full-flight ACK updates the
integer fixed-point SRTT/RTTVAR estimator; partial advancing ACKs restart only the
remaining suffix timer without sampling. Successful retransmission applies Karn
exclusion and persists exponential backoff into later DATA flights until a fresh
clean sample updates the estimator. Failed retransmission admission backs off
that attempt without making the flight RTT-ineligible. SYN, FIN and the explicit
zero-window one-byte probe keep the fixed `retry_ms` policy. The absolute
`timeout_ms` deadline remains unchanged. See
[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html).

A zero peer window prevents new writes by default without starting a deadline or
copying. With `zero_window_probe` enabled, one application write may admit exactly
one real caller byte when no segment is outstanding. That byte uses the normal
copy, retransmit, backoff and fixed-deadline path; it is never synthesized or
hidden from the caller. An ACK that only reopens the window does not retire it;
only a cumulative ACK covering that byte does. This is bounded, application-driven
recovery and still terminates at the configured send deadline. It is not the
indefinite zero-window persist mechanism described in
[RFC 9293 §3.8.6.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.8.6.1).
Already-sent unacknowledged suffixes may still be retransmitted.
The single-segment flight limit is deliberately conservative; this profile does
not implement congestion-window growth, fast retransmit, SACK or public socket
capabilities. FIN/EOF/TIME_WAIT are opt-in; see
[normal FIN close](tcp-fin-close.md).

Valid peer RST and successfully admitted local reset discard retained bytes and
retry state. A failed local reset preserves both directions. Cleanup retains the
existing terminal-state and empty-exporter barrier. Upstream Linux and DPDK
sources are unchanged; byte construction, checksum and MSS helpers stay behind
Ker adapters.

`tcp-send` checks exporter admission rollback, capacity/MSS/window clipping,
wrong-sequence/stale/future/partial ACKs, zero-window updates, sequence wrap,
private retransmission copies, exponential retry and saturation, absolute timeout,
read-window reopening by data, full-duplex ACK+payload, reset and cleanup.
`tcp-send-host` uses a disposable TAP/network namespace and an independent Linux
server: Linux receives and verifies 8192 binary bytes, echoes them, and Ker
verifies every byte before an explicit RST. Legacy receive-stream, active/passive
handshake and UDP host tests remain separate.

`tcp-send-rto-host` delays a clean Linux ACK to learn an RTO above the floor,
drops a selected outbound DATA flight, and checks that its same-sequence/same-byte
retry waits for the learned RTO. It then checks Karn backoff and a later clean
flight sample before completing byte-exact transfer.

`tcp-persist` checks opt-in/default behavior, transactional one-byte admission,
zero-window ACK and reopened-window retries, deadline ordering and sequence wrap.
`tcp-persist-host` uses a small Linux receive buffer, drops the first eligible
nonzero-window ACK while the probe remains outstanding, and verifies later Linux
acknowledgment and byte-exact transfer.

See [receive stream](tcp-receive-stream.md), [active handshake](tcp-active.md),
and [host prerequisites](udp-host-interop.md).
