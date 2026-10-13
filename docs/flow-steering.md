# Fixed flow steering

`ker_flow` provides a fixed, adapter-owned routing layer for IPv4/IPv6 TCP and
UDP packets. It does not implement TCP, UDP sockets, QUIC, a proxy, or a global
connection table. Worker-local Linux/network state stays owned by its worker;
the handoff moves one native DPDK mbuf reference and its parsed key only.

## Key and owner selection

The parser accepts single- or multi-segment Ethernet-II mbuf chains. It supports
IPv4 with IHL 5–15 (20–60 header bytes) and IPv6 with the fixed 40-byte header,
followed directly by TCP or UDP. IPv4 options are opaque bytes: they do not enter
the flow key, and source-route or other option semantics are not implemented.
The encoded source/destination addresses determine the key.
The adapter supplies a 64-bit network-domain value, which must be the same for
both directions of a flow and distinguish any VLAN, VRF, tunnel, or other
namespace that matters to the adapter. Ingress keys use destination as local;
egress keys use source as local. Address/port roles are preserved, so reverse
packets produce the same key without sorting endpoints.

The parser rejects VLAN/QinQ frames, stripped VLAN metadata, IPv4
fragments, IPv6 extension headers, non-TCP/UDP protocols,
and malformed or truncated headers. Ethernet padding is allowed, while all IP
and transport bounds use declared lengths. Failures leave both the mbuf and
output key unchanged. Unsupported parse cases return `-ENOTSUP`; malformed or
truncated packets return `-EINVAL` or `-EMSGSIZE`.

Before reading any bytes, parsing checks the declared segment count against the
linked chain, buffer bounds for each segment, and the total packet length.
Empty segments are allowed. A bounded header prefix (at most 94 bytes) is read
without allocating or linearizing the complete packet. Parsing is read-only;
shared/indirect backing remains accepted when its geometry is valid. The caller
must keep the complete chain and backing stable during parsing. Successful
submission transfers the caller's reference to the whole chain; a downstream
adapter can impose stricter ownership requirements.

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

## Segmented ingress integration

`flow-chain` checks IPv4/IPv6 TCP/UDP keys across segment splits, malformed
geometry, and whole-chain handoff ownership. `fstack-flow-receive` then connects
segmented IPv4 TCP/UDP flow delivery to the existing Ethernet copy/classifier
and worker-local transport receiver. Its two logical workers have separate
packet pools, skb contexts, devices, and receive runtimes on one EAL thread.
It checks local delivery, remote worker-poll handoff, checksum rejection,
capacity-one inbox retry, and destination-pool exhaustion and recovery.

The test bridge copies the uniquely-owned direct chain into the owner's skb
context and releases the input chain before protocol dispatch. Its allocation
failure policy is explicitly to consume and count a drop. The flow callback
has already accepted ownership and cannot return a retry result; this does not
provide the RX-ring adapter's pending/cancel semantics. A production retrying
bridge would require separately bounded storage and lifecycle rules. Actual
transport validation remains IPv4-only; IPv6 coverage here is flow parsing and
handoff, not an IPv6 protocol stack.

## IPv4 options steering verification

`flow-ip-options` covers every IPv4 IHL from 5 through 15 for UDP/TCP and both
flow directions. Fixed keys/hashes remain independent of option bytes. Length
checks use the declared IPv4 header and packet sizes, so trailing Ethernet
padding cannot supply missing transport bytes. Segmentation tests include the
maximum-IHL ports and TCP data offset beyond the previous 74-byte prefix.

`fstack-flow-receive` runs its local/remote owner, inbox retry, and destination
allocation-failure cases with each option length. The owner checks the complete
IPv4 header checksum and the transport checksum; corrupting an options byte
passes structural steering but is dropped by protocol validation. The callback
compares accepted option bytes and header length after copying to the owner's
skb. These tests add no option interpretation, routing or source-route policy.

## Ring ingress to flow ownership

`ker_flow_ring` attaches a `ker_tx_ring` as the sole source of a flow context's
input stream. The adapter runs on that context's lcore; the source ring's sole
producer may run on another registered lcore. Domain and ingress/egress
interpretation are fixed at initialization. It can be installed as the worker's
RX callback, or explicitly polled with a bounded budget. Source producers supply
valid, normally freeable mbuf chains; malformed packet bytes are supported as
rejected input, but corrupt or cyclic mbuf ownership metadata is outside this
ring adapter's contract.

The source ring owns each accepted chain. Polling moves one chain into a single
pending slot, then submits it through normal hash/map owner selection. Successful
submission transfers ownership to the local callback or remote inbox. A full
owner inbox (`-ENOBUFS`), unattached owner (`-ESHUTDOWN`), or other operational
error leaves pending intact. The next poll retries it before dequeuing another
chain. This preserves this source's submission order; it does not impose a
global order across sources or destinations. Storage remains bounded by source
ring capacity, one pending chain, and the existing destination inbox capacity.

Recognized packet parse errors consume the chain and increment `last_dropped`.
`last_completed` counts accepted submissions plus consumed drops, not unsuccessful
retries. A poll with progress returns that count and records an error separately
in `last_error`; with no progress it returns the error. Zero budget preserves the
previous diagnostics. Dropping after owner-side protocol validation or allocation
failure remains the receive callback's policy, outside ingress statistics.

Attachment prevents manual source-ring reads, source-ring destruction, and flow
context detach. Initialization and cleanup require quiescent worker execution;
recursive polling/cancellation/cleanup during synchronous delivery is rejected.
Cancel transfers only the pending chain back to the caller. Cleanup requires no
pending chain and leaves unread source-ring entries untouched. Producers must be
externally quiesced before lifecycle changes. Multiple distinct source rings may
pin the same flow context; each ring has only one consumer.

`flow-ring` exercises admission, backpressure, cancellation and lifecycle rules.
The `fstack-flow-receive` integration now enqueues segmented IPv4 TCP/UDP packets
into a real source ring, polls the ingress worker, then polls the selected owner
for checksum validation. It retains the full options-length, checksum rejection,
full-inbox retry, and destination allocation-drop recovery matrix. This remains a
same-process software-ring path, not ethdev/NIC reception or a socket stack.

## Cross-CPU owner receive verification

`fstack-flow-concurrent-receive` joins the software-ring ingress and owner-side
protocol receive path on two distinct pinned CPUs. It captures the allowed CPU
mask before EAL pins the main thread; CTest skips with code 77 only if fewer than
two CPUs are available. Setup/affinity/registration failures otherwise fail the
test. The registered owner thread initializes and tears down its own worker,
packet pool, skb context, device, receive runtime, and flow attachment.

Immutable expected records cover identifiable segmented IPv4 TCP/UDP packets
and varying IPv4 options. The test verifies callback CPU/lcore, flow key, full
wire bytes, protocol payload, source-order delivery, and exactly-once consumption.
A capacity-one owner inbox is filled while the owner is paused, forcing ingress
to retain a second chain and leave the third in the source ring. After release,
the pending chain must precede later packets. Producer/owner progress is checked
before production completes; this is a correctness test, not a throughput claim.

Corrupt checksums are consumed without transport delivery. In a synchronized
phase the owner exhausts only its own pool, consumes an allocation-failure drop,
then releases the held buffers and accepts a later valid packet. Teardown occurs
after production stops and the path drains, with pending/inbox emptiness and pool
recovery checks. The receive callback retains its explicit allocation-drop
policy; this test adds no production retry API, NIC/RSS support, or socket state.

## Bounded owner receive adapter

`ker_flow_receive` composes a flow context, an owner-local bounded packet ring,
and the existing `ker_rx_ring` copy/dispatch adapter. Its flow callback queues
the transferred chain without allocating a destination skb. The owner runs
`ker_flow_receive_poll` from its worker service callback, so retry work is not
gated by the worker's RX admission policy.

The local ring has an exact configured capacity. A chain popped for copying is
retained as the RX adapter's single pending item on `-ENOMEM`, ahead of all
later queued chains. Storage is bounded by that capacity plus one pending chain
and the existing flow inbox. A full local ring consumes and frees the newly
delivered chain and records an overflow drop: the existing void flow callback
cannot return backpressure to the submitting worker. Successful flow submission
therefore means ownership transfer, not guaranteed protocol delivery.

The adapter owns its flow attachment and reserves the device/runtime binding
through the RX adapter's existing pins. Initialization and cleanup belong to
the owner lcore and require externally serialized setup/shutdown. Cleanup
requires an empty flow inbox, local ring and pending slot, no attached ingress
flow-ring adapter, and no active worker poll or protocol dispatch. Direct
detach of the owned flow context is blocked. Cancellation returns only the
pending chain; queued traffic must still be drained before cleanup.

Flow keys are used for owner selection and are not forwarded as transport
callback metadata. Packet decoding still uses the existing Ethernet/IPv4
receive path. This adapter adds owner-side allocation retry; the earlier
test-owned callbacks retain their explicit allocation-drop policy. It does not
implement sockets, TCP state, NIC/RSS, flow migration or lossless admission.
