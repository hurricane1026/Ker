# Fixed flow steering

`ker_flow` provides a fixed, adapter-owned routing layer for IPv4/IPv6 TCP and
UDP packets. It does not implement TCP, UDP sockets, QUIC, a proxy, or a global
connection table. Worker-local Linux/network state stays owned by its worker;
the handoff moves one native DPDK mbuf reference and its parsed key only.

## Key and owner selection

The parser accepts a single-segment Ethernet-II mbuf. It supports IPv4 with
IHL=5 and IPv6 with the fixed 40-byte header, followed directly by TCP or UDP.
The adapter supplies a 64-bit network-domain value, which must be the same for
both directions of a flow and distinguish any VLAN, VRF, tunnel, or other
namespace that matters to the adapter. Ingress keys use destination as local;
egress keys use source as local. Address/port roles are preserved, so reverse
packets produce the same key without sorting endpoints.

The parser rejects VLAN/QinQ frames, stripped VLAN metadata, IPv4 options and
fragments, IPv6 extension headers, non-TCP/UDP protocols, multi-segment packets,
and malformed or truncated headers. Ethernet padding is allowed, while all IP
and transport bounds use declared lengths. Failures leave both the mbuf and
output key unchanged. Unsupported parse cases return `-ENOTSUP`; malformed or
truncated packets return `-EINVAL` or `-EMSGSIZE`.

Hash input is a documented byte sequence: big-endian domain, family, protocol,
16-byte local and remote addresses, then big-endian local and remote ports.
IPv4 addresses have twelve leading zero bytes. A seeded FNV-1a pass and fixed
64-bit avalanche produce a stable 32-bit hash; the low eight bits select one of
256 buckets. The immutable bucket map selects a compact worker index. An
optional bounded table of exact canonical keys overrides the bucket map. This
table is a generic policy hook for an adapter that already knows an owner; it
does not provide runtime UDP upstream source-port allocation, QUIC
connection-ID parsing, CID lookup, or migration. Parsing performs structural
length/protocol selection only; it does not validate IP/TCP/UDP checksums or
implement protocol state machines.

Fabric initialization copies the bucket map and special entries. Every attached
worker takes its own policy snapshot. Later caller mutation cannot alter owner
selection. Worker indices are independent of EAL lcore IDs; attach records the
actual lcore and enforces that only it may submit, resolve, poll, or detach that
context.

## Handoff and lifecycle

Each worker inbox is a bounded DPDK element ring with multi-producer enqueue and
single-consumer dequeue. Local-owner delivery calls the receive callback
synchronously. Remote submission enqueues one envelope. On success, the
callback or inbox owns exactly one mbuf reference and `*packet` is cleared. On
parse errors, an unattached owner, or a full ring, the caller retains its
reference. The receive callback owns the mbuf and borrows the key only for that
call. It must not detach the context, clean up its worker, or destroy its
argument storage.

`ker_worker_poll` drains at most `handoff_budget` inbox entries after timers and
before service, TX, and RX. Handoff continues when memory pressure pauses RX.
Callbacks run on the destination worker's lcore, where the adapter may then
create or access its lcore-owned state. The caller supplies receive policy;
this layer does not claim that other shared Linux or application state is
isolated or safe for cross-worker access.

Initialize the fabric and all workers, attach each worker in a serialized setup
phase, then use an external barrier before accepting submissions. For shutdown,
stop every producer and establish a producer-quiescence barrier first. Have each
owner drain its inbox, detach contexts on their owner lcores, establish another
barrier, then clean up the fabric and packet pool. An empty ring snapshot alone
does not prove that no producer can enqueue afterward. Cleanup returns `-EBUSY`
while a context remains attached or a ring contains packets; it never silently
drops queued ownership.

The implementation does not resize or rebalance the map, migrate active flows,
provide RCU/grace periods, preserve ordering across owner changes, parse
hardware-stripped VLAN identity, or make pre-existing global state worker-local.
The ring placement honors the configured socket; small policy snapshots use the
attaching thread's DPDK allocation socket.

## Flow steering verification

The DPDK test suite includes three focused regressions in addition to the parser
and lifecycle checks in `flow`:

- `flow-buckets` runs on one CPU with 1 through 64 logical workers. For each
  worker count it visits all 256 buckets using fixed, offline-generated UDP
  port/hash vectors, checks resolution from every context, and delivers packets
  in both directions through local and remote paths. It covers rotated
  distribution, every bucket assigned to the highest worker ID, and a 255:1
  skewed map, including workers with no assigned buckets. It also checks copied
  configuration ownership by overwriting the input table before attachment,
  rejects worker counts 0 and 65, and rejects an out-of-range owner at every
  table position. This exercises logical mapping limits, not 64 physical CPUs.
- `flow-matrix` runs on a single CPU. It checks independent IPv4/IPv6 TCP/UDP
  golden tuples with a nonuniform `bucket % 3` owner map, both packet
  directions, and every logical sender-to-owner local/remote path. Its expected
  key, full hash, and owner are fixed test vectors; it does not ask the routing
  implementation to produce its own expected result.
- `flow-multicore` captures the allowed CPU mask before EAL startup, pins and
  verifies the EAL thread plus two registered worker threads on distinct CPUs,
  and sends 9,216 unique packets through small bounded inboxes while all three
  workers produce and drain. It checks full frame bytes, parsed canonical keys,
  callback owner thread, and exactly-once delivery. CTest marks this test
  skipped (return code 77) only when fewer than three CPUs are available.

Run these tests with:

```sh
ctest --test-dir build -R '^flow-(buckets|matrix|multicore)$' --output-on-failure
```
