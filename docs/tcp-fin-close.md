# Active TCP half-close and normal FIN shutdown

Set `time_wait_ms` to opt into graceful closing on the private active profile;
receive storage is required. Choose the interval as twice the deployment's
maximum segment lifetime; the tests use 120000 ms. Zero keeps the prior explicit
unsupported-FIN/RST behavior and shutdown returns `-EOPNOTSUPP`.

`ker_tcp_active_shutdown_write()` admits FIN only when all application data has
been acknowledged and the peer window allows another sequence number. It returns
`-EAGAIN` for outstanding data or zero window. Admission failure changes neither
sequence nor close state. Successful admission consumes one sequence number and
permanently prevents further writes (`-EPIPE`). Reads remain available. FIN uses
the original sequence on exponential retries and shares the configured retry/
timeout policy with data; it cannot be silently replaced by a successful abort.

Peer FIN is consumed only at the contiguous receive boundary after data overlap
trimming and within the last admitted receive edge. Data+FIN retains data before
marking EOF and sending its cumulative ACK. ACK backpressure preserves bytes,
sequence and EOF; poll retries. Reads drain retained bytes before returning zero
for EOF, and failed/invalid reads leave output unchanged. Future FIN produces a
cumulative ACK without EOF. Duplicate FIN repairs ACK admission without consuming
sequence twice. A duplicate FIN may also carry a valid newer ACK of the local FIN.
New payload after peer EOF is discarded and cumulatively acknowledged.

Peer-first FIN enters CLOSE_WAIT: application writes are still allowed, so an
application can respond after peer EOF. Local shutdown then enters LAST_ACK and
an exact acknowledgment of the local FIN completes CLOSED. Locally initiated
shutdown follows FIN_WAIT_1 and FIN_WAIT_2; peer-first acknowledgment/FIN ordering
and simultaneous close are handled through independent FIN/ACK flags. CLOSING
retains the original FIN retry until acknowledged. The original local FIN
absolute deadline also bounds FIN_WAIT_2, so a late ACK cannot extend resource
lifetime. Expiry reports `-ETIMEDOUT` and discards private stream state before
processing a late packet.

When both directions complete an actively initiated close, TIME_WAIT begins.
The tuple, neighbor, receiver and exporter remain pinned until poll advances the
fixed configured interval. Duplicate FIN is acknowledged; packets, RST, repeated
ACKs and explicit abort cannot shorten or restart that interval. If deadline
addition saturates, TIME_WAIT is explicitly non-expiring—even at UINT64_MAX—so
unrepresentable lifetimes cannot allow early tuple reuse. Cleanup remains busy
in that boundary; applications should use a representable monotonic clock/range.

CLOSED retains unread receive bytes. Cleanup requires drained reads, no pending
ACK, acknowledged local FIN and an empty exporter (including shared traffic).
Applications must keep polling/draining TX after EOF and close completion. FIN
admission and ACK admission are local queue events; they are not proof that a
packet reached the link. RST abort stays separate from graceful close.

`tcp-close` checks FIN sequence wrap, admission/ACK backpressure, retransmission,
invalid ACKs, bounded FIN_WAIT_2, peer data+FIN and EOF, duplicate/overlap/future
FIN, CLOSE_WAIT writes, LAST_ACK, simultaneous/combined close, TIME_WAIT expiry,
saturated time, ignored RST/unsupported flags, and cleanup pins. Its saturated
time test restores an internal marker solely for fixture resource accounting;
there is no production API to bypass TIME_WAIT.

`tcp-close-host` uses a real Linux socket through disposable TAP/netns. Linux
sends 4096 binary bytes and shuts down its write direction. Ker verifies every
byte and EOF, sends 4096 verified bytes after peer EOF, then sends FIN. Linux sees
normal EOF; Ker reaches CLOSED via LAST_ACK. This host case uses peer-first close
and does not shorten or simulate TIME_WAIT. Timer/active-close paths are tested
with deterministic caller time. Existing active, receive, send and UDP host
checks remain independent. Upstream Linux/DPDK sources are unchanged.

This remains a bounded fixed-peer adapter: no out-of-order cache, persist probes,
adaptive RTT/RTO or full congestion-control engine is claimed. See
[send stream](tcp-send-stream.md), [receive stream](tcp-receive-stream.md), and
[host prerequisites](udp-host-interop.md).
