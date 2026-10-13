# Bounded re-resolution of monitored IPv4 neighbors

The resolver extends the monitored-neighbor output path to a previously
configured peer whose native reachability timer has reached FAILED. It uses
Linux's original `__neigh_event_send` to enter INCOMPLETE and hold packets in
`neighbour.arp_queue`. The imported `neigh_update_process_arp_queue` drains that
queue after a supported native update accepts a MAC. Upstream Linux and DPDK
sources remain unchanged.

For an explicitly selected peer with no configured MAC, the separate
[first-contact discovery initializer](linux-neighbor-discovery.md) creates a
NUD_NONE entry and binds this same resolver.

This is opt-in on a worker-owned monitor and TX exporter. Configure a positive
unresolved-queue byte limit offline with the neighbor table parameters, then
bind the exporter through `ker_neighbor_monitor_resolution_enable`. The limit
uses Linux `skb->truesize`, not payload length. Native overflow evicts the oldest
queued packets; a single packet exceeding the configured limit is rejected
before ownership transfer. The exporter remains pinned while resolution is
enabled so cleanup cannot invalidate the deferred output destination.

`ker_neighbor_monitor_resolve_output` accepts the same unique, linear,
CHECKSUM_NONE, configured-source IPv4 packet profile as resolved output. It
also admits FAILED and INCOMPLETE. Admission failure retains the caller's
packet; entering the native path clears the caller's slot. Native success may
mean that the packet is queued for resolution, rather than already exported.
Destination route metadata and unsupported header-cache paths remain rejected.

The existing application probe callback explicitly requests a packet with
`ker_arp_probe_create` and enqueues it for transmission. Native Linux determines
the timing, probe count and multicast solicitation; the adapter does not install
an automatic ARP transmitter. Probe clones stay internal to the native callback
lifecycle; the application receives copied event metadata. ARP construction retains the existing NULL-skb
source-selection boundary and uses the configured local address. Queued data
must already have that source; packet-driven source selection is not added.

An accepted reply delivered through the existing worker ARP feedback callback can update an INCOMPLETE entry and flush queued data in FIFO order
using its current MAC. Resolution success does not guarantee delivery: a full
TX exporter consumes and drops a flushed packet rather than retaining an
unbounded secondary queue.

Native retry exhaustion returns the entry to FAILED and frees pending packets.
Explicit cancellation returns queued ownership to the caller. Disable and
cleanup enforce the resolver's queue, timer and exporter lifetime boundaries.
After a clock-range error stops an INCOMPLETE timer, cancel its remaining queue
before cleanup; no artificial FAILED transition is made.
This resolver binding alone does not create peers. General ARP learning, route lookup, ICMP
unreachable generation, socket service and NIC transmission remain outside this profile.
