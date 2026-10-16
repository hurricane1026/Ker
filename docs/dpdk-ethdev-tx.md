# Borrowed DPDK ethdev TX queue

`runtime/ethdev-tx.h` adapts the bounded skb copy exporter to one existing DPDK
TX queue. The caller configures and starts the port and queue before
`ker_ethdev_tx_init`, including enabling `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` at
port level, and remains responsible for stopping, reconfiguring, and closing
them. Do not stop or remove the borrowed port while the adapter is attached.
The port, queue, skb context, and adapter must remain alive until queued exports
are drained and `ker_ethdev_tx_cleanup` succeeds. The caller must quiesce other
ethdev access before cleanup. DPDK does not expose a portable started-state
query, so started-queue setup is a caller precondition.

The adapter is owner-lcore confined and uses `rte_eth_tx_burst` for one packet
chain per attempt. A return of one transfers the complete copied mbuf chain to
the PMD; zero returns `-EAGAIN`, leaving the exporter to retry without consuming
the caller's queued skb. Adapter cleanup pins the exporter against direct
cleanup and fails while packets remain pending. Only queues configured for
multisegment TX are accepted. Where the PMD reports a nonzero maximum number of
segments per packet, longer chains are rejected. Checksum, TSO, VLAN and other
TX offload metadata is rejected; this adapter
does not claim hardware checksum, segmentation, NIC, or full-stack capability.

Before each nonzero-budget adapter poll, the wrapper asks the PMD to reclaim all
completed TX mbufs with `rte_eth_tx_done_cleanup(..., 0)`. This lets drivers
that defer mbuf release return packet-pool entries before the exporter makes
its next copy. `-ENOTSUP` is recorded in `last_cleanup_error`, but normal TX
polling continues; callers using such a PMD must provide independent reclaim or
sufficient pool headroom. Other reclaim errors stop that poll and leave queued
skbs untouched. Use `ker_ethdev_tx_poll`; polling the embedded exporter directly
bypasses this reclamation step.

The deterministic `ethdev-tx` test uses DPDK's pinned `net_ring` PMD. It checks
the raw-send sizes represented by F-Stack's `test_ff_dpdk_raw_packet_send_basic`
and `test_ff_dpdk_raw_packet_send_multiseg`, exact copied bytes, FIFO order,
full-ring retry, packet-pool exhaustion/recovery, and the PMD TX packet count.
The test does not change caller port lifecycle or implement RX. Since `net_ring`
does not implement deferred cleanup, a separate controlled reclaim-callback
case exhausts the mbuf pool, releases one entry before the next copy, and proves
poll progress and reentry protection. Another case sends a successful prefix,
hits `-ENOMEM` on the next copy, then proves a later cleanup/poll resumes in
FIFO order. These controlled callbacks validate adapter ordering, not PMD
hardware cleanup behavior.

To build the isolated test dependency without changing the shared DPDK build or
installation, set `KER_DPDK_BUILD_DIR`, `KER_DPDK_PREFIX`, and
`KER_DPDK_DRIVERS=mempool/ring,net/ring` for `tools/build-dpdk.sh`, then point
`KER_DPDK_PKGCONFIG_DIR` at that prefix's `lib64/pkgconfig` during CMake
configuration.
