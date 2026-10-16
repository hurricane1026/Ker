# Borrowed DPDK ethdev RX adapter

`ker_ethdev_rx` is a bounded Ker adapter for one already configured and started
DPDK RX queue. It calls `rte_eth_rx_burst` for at most one packet per unit of
worker budget, copies the received chain into a Ker skb, and passes it through
the existing Ethernet classifier and receive dispatcher. It adds no protocol
state or packet parsing of its own.

The caller owns port creation, queue setup, start/stop/close, and must guarantee
exclusive access to the borrowed queue across all APIs. The port and queue must
remain configured and started while attached, and all access must be quiesced
before cleanup. The adapter pins its Ker device and receive runtime and rejects
conflicting Ker RX-ring bindings; it cannot detect another external consumer of
the same DPDK queue.

The adapter is owner-lcore only. Each burst fetches at most one chain, and each
poll consumes no more than its budget. If copying fails for lack of destination pool memory, the adapter retains that
owned chain and retries it before fetching another packet. `cancel` transfers a
pending chain back to the caller; cleanup returns `-EBUSY` while one remains.
Malformed or unsupported frames are consumed and counted as drops. Queue
configuration, hardware capabilities, offloads, port lifecycle, and NIC
behavior remain caller/driver responsibilities.

`ker_ethdev_rx_init` keeps the unique-reference copy profile: direct segments
must have reference count one, and indirect chains are rejected. The explicit
`KER_ETHDEV_RX_COPY_IMMUTABLE_BORROWED` profile accepts shared direct segments
and valid DPDK indirect clones. The separate
`KER_ETHDEV_RX_COPY_IMMUTABLE_EXTERNAL` profile accepts valid attached DPDK
external-buffer segments and their external-buffer clones. Both profiles copy
bytes into Ker-owned skb storage. For the external profile, input must be a
valid native DPDK attachment; the caller guarantees that `buf_len` truthfully
bounds the external allocation and keeps descriptor fields, chain topology,
external storage, and shared-info stable and immutable until the adapter
consumes or returns its received reference. The adapter cannot verify the
actual capacity behind an opaque external pointer. Each external segment must
have a live descriptor reference, shared-info with a free callback, positive
external refcount, and valid data bounds. External-plus-indirect flags,
invalid geometry, and transformed RX metadata are rejected. Existing unique
and borrowed profiles continue to reject external buffers. The borrowed
profile accepts direct shared references and valid indirect clones; the caller
keeps their topology and bytes immutable, while the adapter owns the queue's
received reference. A sibling clone may retain backing without an extra
reference to the queued descriptor. These profiles copy bytes into Ker-owned
skb storage and do not transfer or modify other caller references. Pool
allocation `-ENOMEM` retains the adapter's chain reference for retry; `cancel`
returns that same reference.

The `ethdev-rx` test injects real mbuf chains through DPDK's `net_ring` PMD,
including an Ethernet header split across segments and actual `rte_pktmbuf_clone`
chains. It checks default unique-only rejection, borrowed direct/indirect copy,
parent and sibling lifetime, original-reference release before copying,
pool-pressure retry, cancellation, malformed/metadata rejection, worker-budget
FIFO, and binding exclusion. External-buffer coverage uses actual attached
multisegment buffers and `rte_pktmbuf_clone` through the PMD queue, then checks
that copied skb bytes outlive the final external-buffer callback. These Ker
tests add shared-reference behavior
beyond the pinned F-Stack free/fanout scenarios; those upstream cases do not
test indirect-clone RX. This is not a claim of physical-NIC, RSS, socket, or
full-stack support.

The `ethdev-rebind` regression exercises this caller-owned lifecycle on one
configured RX queue of a started `net_ring` port. A successor frame is queued
behind a pending packet before detach; after the pending packet is canceled,
cleanup releases Ker's binding pins but does not drain the successor. A later
adapter generation on the same queue receives the preserved frame before a new
frame. Callers that need generation isolation must quiesce and explicitly drain
or discard queued frames before rebinding, while keeping the port and its queue
pool alive. This test covers raw Ethernet classification
and IPv4-header checksum validation only; it does not exercise transport state
or TX. The pinned F-Stack registration roundtrip motivates the lifecycle case
but does not promise queue flushing.
