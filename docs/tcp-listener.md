# Bounded TCP passive listener

`ker_tcp_listener` provides one private IPv4 listening port on one worker for
one explicitly configured peer IP and permanent Ethernet neighbor mapping.
It uses caller-owned bounded request storage and Ker-owned handshake state,
with the existing native Linux checksum/MSS parser, Ethernet classification,
neighbor table and bounded TX exporter. Upstream Linux and DPDK remain unchanged.

A valid payload-free SYN allocates a request only after its SYN-ACK is admitted
to the exporter. The listener advertises a configured unscaled window and MSS.
Optional caller-owned flat receive and send arenas enable bounded passive
streams. Each must cover `request_capacity * its_capacity` bytes and remain
stable until cleanup. Capacity is isolated per slot. Receive window is capped
by receive capacity; without receive storage, the prior handshake-only receive
behavior and configured window remain unchanged. Send storage enables the
accepted application to send one outstanding segment at a time.
Peer MSS parsing follows the imported Linux helper; an absent MSS uses 536,
capped by the configured MSS. ECE/CWR offers are declined. Window scaling,
SACK, timestamps, Fast Open and TCP authentication are not negotiated.

A caller-supplied ISN callback must return a fresh unpredictable sequence
number for each request. There is no deterministic default. The callback runs
under listener reentry protection and must not block or mutate borrowed objects.
The host integration test uses nonblocking `getrandom`; only deterministic
unit tests use a fixed sequence number to exercise wraparound.

Without receive storage, only a payload-free ACK completes the handshake. With
storage, the final ACK may carry payload, retained after the handshake is
established. `accept` returns each completed request once, with a
table/slot/generation handle. Snapshot errors leave output unchanged. Generation
exhaustion fails closed, and listener cleanup preserves the generation counter
for a subsequent initialization of the same object.

The application samples monotonic milliseconds and calls `poll` before RX on
each iteration, including idle iterations. Poll advances the stored clock,
rejects rollback, scans at most `min(budget, capacity)` slots fairly, and retries
SYN-ACK at the configured fixed interval. Retries retain the original ISNs and
never extend the absolute deadline. Duplicate SYNs do not trigger immediate
responses or extend deadlines. TX admission failures are available in
`last_tx_error`; capacity remains bounded. Expired requests cannot complete,
even if RX sees them before the next budgeted timeout scan.

`ker_tcp_listener_read` copies contiguous bytes from an accepted handle on the
owning worker. Each request has an isolated bounded ring. Old duplicate prefixes
are trimmed, and bytes beyond the last admitted window edge are clipped. By
default future gaps are discarded. Optional `reorder_storage` enables bounded
gap retention with one validity bit per receive-ring byte; its flat arena must
cover `request_capacity * ceil(receive_capacity / 8)` bytes, remain stable and
non-overlapping with the receive arena until cleanup, and is isolated by slot.
The first retained byte wins conflicting overlaps, and the first accepted
out-of-order FIN fixes the pending FIN sequence. Only contiguous bytes become
readable or advance the cumulative ACK. A FIN may wait behind a gap; it is
consumed once the missing bytes arrive, and bounds/discards retained bytes at or
after its sequence. Reads schedule a window ACK; the edge advances only after
exporter admission. Retained data and validity bits survive ACK backpressure
and poll retries pending ACKs fairly. `ker_tcp_listener_write` copies and admits at most
one segment, clipped by the peer MSS, advertised window and per-slot send
capacity. It returns the locally admitted byte count; an outstanding segment
or a zero usable send window returns `-EAGAIN` by default. The opt-in
`zero_window_probe` config admits exactly one real caller byte when there is no
flight and the usable send window is exactly zero. The byte is consumed only
after TX admission, then uses the ordinary one-flight retry and fixed timeout
policy. This provides bounded, application-triggered recovery; it is not an
indefinite RFC persist timer. Serial-negative/shrunk send edges remain blocked,
and `shutdown_write` still requires a nonzero usable window. The private copy
is retained for retransmission, and cumulative ACKs trim only the acknowledged
prefix. Pure ACKs
must match the current receive sequence; ACKs with payload may also update the
send window when their segment overlaps the receive edge and contributes new
bytes. Stale duplicates and future gaps cannot change send ACK/window state.
Retry intervals back off exponentially against a fixed absolute timeout. No
persist timer is used.

Graceful passive close is opt-in through nonzero `time_wait_ms`, which requires
both stream arenas. A peer FIN is acknowledged after all contiguous preceding
bytes are retained; reads return zero only after those bytes are drained. The
application may continue writing in CLOSE_WAIT, then call
`ker_tcp_listener_shutdown_write` after its outstanding data is acknowledged.
Local FIN retransmits against one absolute close deadline. Simultaneous close
enters a fixed-deadline TIME_WAIT; an exact duplicate FIN is re-ACKed without
extending that deadline. Call `ker_tcp_listener_release` after CLOSED and EOF
drain to retire the generation-safe handle. Without this option, FIN remains
explicitly unsupported and takes an RST path.

The receiver and exporter cannot be destroyed while a listener is attached.
A retained native neighbor reference pins the peer/table; caller storage must
remain stable and must not be edited while attached. Request retirement waits
for the exporter to drain queued frames. This is a conservative barrier across
that entire exporter, so unrelated traffic sharing it can delay retirement.

This profile supports opt-in bounded passive send/receive and FIN close, plus
explicit abort with RST. It does not support active connect, congestion control,
reassembly, ICMP correlation or cross-worker listener distribution.
With storage disabled, data remains rejected with `-EOPNOTSUPP` and an RST when
TX admission succeeds. `reset` is transactional on TX failure; its handle becomes stale when
poll observes the RESET request after TX drains. Full TCP transport and public
socket capabilities remain subsequent work.

`tcp-listener` tests control state, tuple/ACK checks, duplicate SYN behavior,
retries, absolute expiry, queue backpressure, callback reentry, output
transactionality, stale handles, generation exhaustion, per-slot isolation,
final-ACK data, sequence and ring wrap, clipping, default gap discard and opt-in
gap retention, conflicting overlaps, delayed FIN, and duplicates.
`tcp-host` runs the same listener against a real Linux `AF_INET/SOCK_STREAM`
client through TAP in a disposable user/network namespace. It requires an
actual ARP reply, a successful Linux `connect`/Ker `accept`, byte-verified
full-duplex transfer, peer-first and server-first half-close, and orderly EOF
after Ker's FIN. Its reorder mode holds the first client data segment, dispatches
the next higher-sequence segment first, verifies the listener retains it without
advancing the cumulative edge, then releases the first segment and verifies
promotion. The test has bounded waits and kills its child on
failure. Missing namespace/TAP facilities produce a CTest skip (exit 77), which
is not interoperability evidence.

```sh
ctest --test-dir /path/to/build -R '^(tcp-listener|tcp-host)$' --output-on-failure
```

See [UDP host interoperability](udp-host-interop.md) for the same TAP/namespace
prerequisites. Neither test changes persistent host interfaces or routes.

The independent [active handshake adapter](tcp-active.md) can share a receiver on a different local port.
