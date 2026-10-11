# Explicit TCP/IPv4 packet construction

`ker_tcp_ipv4_create` builds a caller-owned linear Ethernet + fixed IPv4 +
fixed TCP skb. Source/destination MAC addresses are copied literally; IPv4
addresses, TCP ports, sequence/acknowledgment values and window are supplied in
wire order. TTL must be nonzero. The caller supplies byte 13 TCP flags; the
constructor leaves data offset at five, all reserved/NS bits zero, and urgent
pointer zero. Requests with URG set fail with `-ENOTSUP`, because no urgent
pointer is accepted. Ports, window and sequence values may be zero. IPv4 ID,
DSCP/ECN and fragmentation fields are zero. Payload is borrowed only during
construction and copied into the skb.

IPv4 and TCP checksums use the original Linux software checksum primitives.
The TCP checksum is written as calculated, including a valid zero result; it
is not UDP's zero-to-`0xffff` mangling rule. The constructor sets packet
geometry for the existing Ethernet/export adapters and sets no TX offload
metadata. Oversize protocol lengths fail before allocation, while local backing
capacity and pool exhaustion are returned as allocation errors. The API does
not perform address policy, routing, TCP option handling/state, socket delivery,
NIC transmission or hardware offload.
