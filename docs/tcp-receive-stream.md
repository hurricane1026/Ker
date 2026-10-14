# Bounded TCP receive stream

The private active profile can now receive data into caller-owned storage.
Set `receive_buffer` and `receive_capacity` in `ker_tcp_active_config` before
start; capacity must equal the initial unscaled `window` (1–65535 bytes).
The storage must remain stable and exclusive to the connection until cleanup.
Leaving both fields zero retains the handshake-only profile.

Call `ker_tcp_active_read()` on the owning worker to copy available bytes.
It returns a positive count, `-EAGAIN` when READY has no data, or a negative
error. Reads do not block; destination must not overlap the ring. Poll with a
monotonic clock before RX, including idle iterations, and drain the exporter.
Reading frees storage and schedules an ACK advertising the reopened window.
Snapshot exposes retained bytes, next receive sequence and pending ACK state.

The adapter retains only the contiguous suffix at the next receive sequence.
It trims old duplicate bytes, clips at the right edge last admitted to TX, and
discards future gaps while sending cumulative ACKs. No out-of-order storage is
allocated. Sequence comparisons work across 32-bit wrap; capacity stays below
the serial half-space. The advertised window reflects unused ring capacity.
A read cannot authorize more incoming bytes until a new window ACK is admitted.

Retention precedes acknowledgment. If ACK enqueue fails, accepted bytes and
sequence progress remain intact and poll retries the ACK. Duplicates can also
repair a lost ACK without delivering bytes twice. Zero-window probes receive
cumulative ACKs. TX admission is local: callers still have to drain packets to
the link. The existing tuple validation, owner checks and lifetime pins apply.

Valid peer RST and successfully admitted explicit abort discard unread bytes.
FIN/data+FIN at the contiguous receive boundary (including old overlap) takes
an explicit unsupported RST path without retaining that segment's payload;
failed reset admission preserves existing data and state for retransmission.
There is no graceful EOF, congestion control, window scaling,
SACK, timestamp negotiation or public socket capability in this batch. This is
an incremental fixed-peer adapter, not a complete TCP stack. Optional sending
is described in [bounded active TCP sending](tcp-send-stream.md).
Upstream Linux and DPDK sources remain unchanged.

`tcp-stream` validates wire ACK/window values, sequence wrap, duplicate and
overlap trimming, gaps, right-edge clipping, zero window, ring wrap, invalid
ACK/RST, transactional reads, FIN and TX backpressure. `tcp-stream-host` uses a
real Linux server in a disposable TAP/network namespace: it sends 8192 binary
bytes through a 1024-byte receive ring. Ker intentionally holds the full ring
for 200 ms, reopens it by small reads, checks every byte, and ends with RST.
The legacy active/passive/UDP host tests continue separately.

See [active handshake](tcp-active.md) for setup/lifecycle and
[host prerequisites](udp-host-interop.md) for namespace requirements.
