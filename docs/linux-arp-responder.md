# Bounded local IPv4 ARP responder

The opt-in `ker_arp_responder` connects the existing ARP receiver to the native
Linux ARP packet constructor and a bounded TX exporter. A supported request for
the configured local IPv4 address produces a unicast reply automatically;
application callbacks do not need to construct that reply.

Register the responder with its configured address, receive runtime and TX
exporter on the same owner context. Registration pins the address/device through
the receiver and pins the exporter until unregister succeeds. Replies already
queued in the exporter retain their ordinary TX ownership after unregister.

The supported profile accepts decoded ARPOP_REQUEST messages classified as
PACKET_HOST or PACKET_BROADCAST, with nonzero sender IPv4 address and a target
matching the configured local address. The receiver's existing Ethernet/IPv4
ARP and unicast-sender checks remain in force. Other requests, ARP replies,
address-detection requests with zero sender IP and nonlocal targets do not
produce a reply. Reply fields come from the configured local address/MAC and
the received sender tuple. This is not an authenticity check.

Linux `arp_create` constructs the reply unchanged. Successful enqueue transfers
ownership to the exporter. Allocation or enqueue failure reports a drop and
retains no hidden response queue; a later peer solicitation may retry. Once a
reply has entered the exporter, allocation or sink backpressure uses its
existing FIFO retry behavior. Unregister does not discard queued replies.

This is a Ker responder adapter over the existing native receive gate and
constructor. It does not import full Linux `arp_process`, learn sender mappings,
create proxy replies, select routes, implement DAD conflict handling, or send to
a NIC. Existing manual ARP receiver callbacks remain available separately.
