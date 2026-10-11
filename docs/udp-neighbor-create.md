# Neighbor-backed UDP construction

`ker_udp_ipv4_create_neighbor` constructs a packet only from the state already
owned by one worker: the neighbor table's configured IPv4 address and Ethernet
device, plus an existing `NUD_PERMANENT` destination entry. It snapshots the
local address, source MAC, destination MAC and skb context, releases the lookup
reference, then delegates packet construction and software checksums to the
existing UDP constructor.

The output slot remains unchanged on failure. Missing destinations return
`-ENOENT`; mappings outside the permanent-entry profile return `-ENOTSUP`.
The constructor does not resolve ARP, queue unresolved packets, select a source
address, inspect a FIB, route, or transmit through a NIC. Payload bytes are
copied by the underlying constructor and are borrowed only during the call.
