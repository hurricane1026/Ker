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

The `ethdev-rx` test injects real mbuf chains through DPDK's `net_ring` PMD,
including an Ethernet header split across segments, and verifies worker-budget
polling, FIFO dispatch, pool-pressure retry, cancellation, and binding
exclusion. This is a Ker RX-adapter test, not a claim of physical-NIC, RSS,
socket, or full-stack support.
