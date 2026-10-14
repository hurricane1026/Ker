# UDP interoperability with Linux

`udp-host` connects Ker's private UDP channel implementation to an independent
Linux `AF_INET/SOCK_DGRAM` endpoint through a nonblocking TAP descriptor. The
Python driver creates a fresh user and network namespace, configures
`kerhost0` as `192.0.2.2/24`, and passes its open TAP descriptor to the Ker test
process. Ker owns `192.0.2.1:9000`; the Linux socket owns `192.0.2.2:8000`.
No host interfaces, routes, or persistent TAP devices are changed.

The test sends a greeting from Ker to Linux, then checks Linux-to-Ker delivery
and Ker-to-Linux echoes for empty, binary, short, and 1472-byte payloads. Linux
resolves Ker's Ethernet address through Ker's ARP responder; the test requires
an actual ARP reply. Ker uses a configured peer MAC for its first transmission.
Linux validates Ker's IPv4/UDP checksums through its normal networking stack.
A 1473-byte Ker payload must return `-EMSGSIZE` at the 1500-byte IPv4 MTU.
Both processes have bounded waits; the driver terminates the child on failure.
Ker cleanup verifies that all packet buffers are returned.

After configuring a Debug build with DPDK and tests enabled:

```sh
cmake --build /path/to/build --target ker-udp-host-test
ctest --test-dir /path/to/build -R '^udp-host$' --output-on-failure
```

The test requires Linux, Python 3, `ip`, `unshare`, `/dev/net/tun`, and permission
to create user/network namespaces and a TAP device within them. CTest reports
an explicit skip (exit 77) when these facilities are unavailable. A skipped run
is not evidence of interoperability. No sudo is required on hosts that permit
unprivileged user namespaces. DPDK must remain available in the test process's
library search path.

This is a single-worker, fixed-peer, directly attached IPv4 integration test.
It does not add a public socket API or advertise real NIC, RSS, routing,
fragmentation, or general TAP runtime support. The TAP callbacks belong to the
test harness; Linux and DPDK sources remain unchanged. Cross-worker UDP and
ICMP behavior continues to be tested separately by `udp-flow` and `udp-error`.
