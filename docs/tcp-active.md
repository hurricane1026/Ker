# Bounded TCP active handshake

`ker_tcp_active` adds a private single-worker active open to the fixed-peer TCP
handshake profile. The caller configures a local port, peer IPv4/port, permanent
neighbor mapping, window, MSS, retry interval, absolute timeout and ISN callback.
One active tuple can attach to a transport receiver; a passive listener may
share that receiver on a different local port. Conflicting ports fail with
`-EADDRINUSE` in either initialization order.

Start pins the receiver, exporter and native neighbor reference before invoking
the callback. The callback must provide a fresh unpredictable ISN and return
zero or negative errno, without blocking or mutating borrowed objects. No
insecure default is supplied. SYN admission failure or callback failure rolls
back all pins and hooks; no connection remains attached. The host test uses
nonblocking `getrandom`, while unit tests intentionally use UINT32_MAX to
exercise sequence wrap.

The receiver validates IPv4/TCP checksums and filters the complete configured
tuple and local unicast destination. A SYN-ACK must acknowledge exactly ISN+1.
The final ACK acknowledges peer ISN+1 and enters the bounded exporter before
state becomes READY. READY indicates local ACK admission; the application must
continue polling TX to make wire progress. A duplicate matching SYN-ACK in
READY triggers another ACK, repairing a lost final ACK without restarting the
connection. Peer MSS is parsed through the original Linux helper and capped by
configured MSS; absent MSS uses 536 capped by that limit. The snapshot exposes
the peer's unscaled window and both ISNs.

The application samples monotonic milliseconds and polls before RX, including
idle iterations. Poll rejects rollback, retransmits SYN with unchanged ISN at
the configured fixed interval, and enforces the original absolute deadline.
Backpressure does not extend that deadline. `last_tx_error` records retry or
ACK admission failures. A final ACK queue failure leaves the connection in SYN
so a later SYN-ACK can retry; a late SYN-ACK cannot resurrect a timed-out open.
An ACK-less RST cannot cancel an active open. A valid acknowledged reset during
SYN reports `-ECONNREFUSED`; an exact-next-sequence reset after READY reports
`-ECONNRESET`.

The profile negotiates MSS only. Simultaneous open, ECN negotiation, window
scaling, SACK, timestamps, authentication, Fast Open,
congestion control and reassembly remain subsequent work. Graceful FIN close
is opt-in; see [half-close and FIN](tcp-fin-close.md). Without opt-in receive
storage, matching data is rejected. With graceful close disabled, FIN is rejected with
`-EOPNOTSUPP` and RST when TX admission succeeds. `reset` aborts explicitly;
admission failure preserves state. Cleanup requires RESET, FAILED or drained CLOSED and an empty exporter, conservatively including unrelated queued traffic sharing it.
Snapshot failures leave output unchanged. Caller-owned state stays stable and
must not be edited until cleanup. Upstream Linux/DPDK code and public socket
capabilities remain unchanged.

`tcp-active` exercises handshake sequence/ACK checks, wraparound, ignored
ACK-less/bad-ACK resets, correct reset refusal, duplicate SYN-ACK recovery,
absolute timeout, backpressure during start/retry/final ACK, rollback, callback
reentry, unsupported FIN/data and resource cleanup. It also verifies active and
passive routing on different ports and both conflict orders.

`tcp-active-host` runs against an independent Linux `AF_INET/SOCK_STREAM`
listener through TAP in a disposable user/network namespace. Linux must accept
`192.0.2.1:9000` on `192.0.2.2:8000`, and observe Ker's explicit abort as a reset.
The test requires a real ARP reply and has bounded waits/child cleanup. Missing
namespace/TAP facilities produce an explicit CTest skip (exit 77), which is not
interoperability evidence. Host networking outside the namespace is unchanged.

```sh
ctest --test-dir /path/to/build -R '^(tcp-active|tcp-active-host)$' --output-on-failure
```

See [TCP passive handshake](tcp-listener.md) and [UDP host prerequisites](udp-host-interop.md).

An opt-in receive ring now extends this profile: see [bounded receive stream](tcp-receive-stream.md). Without receive storage, incoming data remains explicitly unsupported. An optional
send buffer enables [bounded active TCP sending](tcp-send-stream.md).
