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
and valid DPDK indirect clones. The adapter owns the descriptor reference
received from the queue. The caller guarantees that the descriptors, chain
topology, and backing bytes remain immutable until the adapter consumes or
returns that reference; any independent backing references the caller needs
must remain live. A sibling clone can retain shared backing without requiring
an extra reference to the queued clone descriptor. This profile copies bytes
into Ker-owned skb
storage; it does not transfer or modify the caller's references. External
buffers, invalid clone/backing geometry, and transformed RX metadata remain
unsupported and are consumed as drops. Pool-allocation `-ENOMEM` retains the
adapter's chain reference for retry; `cancel` returns that same reference.

The `ethdev-rx` test injects real mbuf chains through DPDK's `net_ring` PMD,
including an Ethernet header split across segments and actual `rte_pktmbuf_clone`
chains. It checks default unique-only rejection, borrowed direct/indirect copy,
parent and sibling lifetime, original-reference release before copying,
pool-pressure retry, cancellation, malformed/metadata rejection, worker-budget
FIFO, and binding exclusion. These Ker tests add shared-reference behavior
beyond the pinned F-Stack free/fanout scenarios; those upstream cases do not
test indirect-clone RX. This is not a claim of physical-NIC, RSS, socket, or
full-stack support.
