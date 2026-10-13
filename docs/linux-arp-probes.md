# Native Linux ARP probe packets

The neighbor timer probe callback can call `ker_arp_probe_create` to capture the
packet produced by pinned Linux `arp_solicit`, `arp_send_dst`, and
`inet_select_addr`. The importer verifies source hashes and records exact source
ranges in `provenance.json`; Linux files remain unchanged. The raw xmit boundary
captures the skb for the caller and never sends it to a NIC.

Call `ker_arp_device_setup` before installing a monitor. Packet creation is
available only for the exact event pointer passed during that monitor's native
probe callback, on its owning worker. A copied event, notification callback,
saved event, or call outside the callback is rejected. The returned skb belongs
to the caller and has its Ethernet and network header geometry initialized.
Failure leaves the output pointer unchanged.

The supported profile is a private Ethernet device with one primary static IPv4
address, `APP_PROBES=0`, `ARP_ANNOUNCE=0`, and
`ROUTE_LOCALNET=0`. Linux's native probe count selects unicast or broadcast ARP
request construction. The source address comes from the native local-address
selector. The default monitor has no queued skb; the
[known-peer resolver](linux-neighbor-resolution.md) admits its native queued
probe clone within the callback lifecycle; it does not expose that clone to
the application or add packet-driven source selection to ARP construction. FIB, VRF, namespace traversal, application
probes and other announcement policies are unsupported; adapter traps guard native
fallbacks that the validated profile cannot enter. ARP receive learning,
general neighbor learning and PMD transmission stay outside this boundary.
The resolver uses explicit receive-feedback callbacks for its existing peer.

The imported configuration has no `CONFIG_NET_NS` support, so its device
structure has no native namespace field. The adapter returns an unobserved null
placeholder from `dev_net_rcu`; the supported local-address selector does not
consume it, and namespace or FIB fallback consumers trap. Enabling namespace
support requires adding its native runtime semantics before broadening the
profile.

The actual-DPDK neighbor timer test checks packet bytes and skb geometry,
callback identity, unsupported profile rejection, allocation failure, output
preservation, ownership, and wrong-worker calls. `arp-probe-import` validates
the pinned source hashes and each recorded source slice.
