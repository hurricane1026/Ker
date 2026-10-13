# First-contact IPv4 neighbor discovery

The discovery monitor creates a bounded, worker-owned neighbor entry for an
explicit IPv4 peer without a supplied MAC address. It starts in NUD_NONE,
without a pending timer. The first admitted packet enters the existing native
Linux `neigh_resolve_output` and `__neigh_event_send` path, which changes the
entry to INCOMPLETE, queues the packet and requests ARP solicitation.

`ker_neighbor_monitor_discovery_init` binds the newly created entry to the
configured address, worker clock and TX exporter. The table must have positive
unresolved-queue and multicast-probe settings. An existing key is rejected;
initialization does not take over permanent entries or another monitor. Failed
initialization rolls back its entry and lifetime references.

The application still constructs and submits ARP from the probe callback with
`ker_arp_probe_create`. A valid reply processed by the existing worker ARP
receiver can update the INCOMPLETE entry and drain its native queue using the
learned MAC. Native retry exhaustion leaves FAILED; a later output can retry
through the same bounded resolver. Admission errors retain caller ownership,
while native entry consumes the packet. Queue eviction and exporter pressure
follow the [resolver contract](linux-neighbor-resolution.md).

A discovery monitor owns its table entry. Cleanup removes that entry after
queue, timer and reference checks; it does not turn a learned MAC into an
administrator-provided permanent mapping. The older monitor initialization
continues to restore its original permanent mapping on cleanup.

Entry allocation and binding are Ker adapter operations. Native Linux retains
control of event-send, probe timing, queueing, update and output; this does not
claim to import the complete `__neigh_create` or `arp_constructor` lifecycle.
There is no automatic destination lookup, route or next-hop selection, general
ARP learning, socket API or NIC transmission. The application explicitly picks
the peer and supplies the existing configured-source IPv4 packet profile.
