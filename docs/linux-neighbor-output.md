# Native output through monitored IPv4 neighbors

`ker_neighbor_monitor_output` connects a configured IPv4 packet to an existing
monitored neighbor and the bounded TX exporter. It imports the pinned Linux
`neigh_resolve_output`, `neigh_event_send`, and `neigh_event_send_probe` bodies
unchanged. The importer checks source hashes and records block provenance;
Linux and DPDK sources are not patched.

The supported neighbor states are REACHABLE, STALE, DELAY and PROBE. These
already have an administrator-provided or explicitly updated MAC. Native Linux
code updates the neighbor's `used` timestamp, changes STALE to DELAY through the
existing timer adapter, and rebuilds the Ethernet header from the neighbor's
current MAC. A later packet therefore observes an accepted neighbor MAC update.
The IPv4 packet and its transport payload are preserved during header rebuilding.

The caller supplies an owned, unique linear CHECKSUM_NONE IPv4 frame and an
initialized TX exporter on the same owner context. The configured source
address and peer destination must match the monitor. Unsupported skb geometry,
shared data, address mismatches, header cache paths and unresolved neighbor
states are rejected before native output runs.

Admission failure preserves the caller's packet. Once native output begins,
`*packet` becomes NULL and the packet is consumed even if TX enqueue fails.
Successful enqueue transfers it to the exporter; rejected enqueue frees it and
returns an error. A negative result alone is therefore not proof of retained
ownership. After enqueue, existing TX export allocation and sink-pressure retries
retain FIFO ownership independently of the neighbor monitor.

This is an explicit output operation on a known peer. It does not install a
route, choose a next hop, create or resolve an unknown neighbor, provide an
INCOMPLETE queue, or transmit to a NIC. FAILED/INCOMPLETE states remain unsupported.
Monitor cleanup still restores the administrator's original permanent mapping.
Public socket and network capability claims are unchanged.
