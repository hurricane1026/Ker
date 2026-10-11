# Worker TX copy export

`ker_tx_export` is a private, stable-address object initialized from `{0}` and
confined to the owning skb context's EAL worker. It wraps the bounded skb FIFO
with an explicit pending head. Admission checks the total packet and frozen
`truesize` byte budgets across both the FIFO and pending skb. It performs no
allocation or mutation of the caller's skb; successful enqueue transfers skb
ownership and clears the caller slot.

The object is used as `ker_worker_ops.tx`. Poll copies the pending skb (or
pops the FIFO head) to a direct mbuf, completing supported Internet
`CHECKSUM_PARTIAL` metadata in the copy with the existing software checksum
adapter. Other skb export limitations, including GSO, unsupported checksum
metadata and unsupported layouts, remain fail-closed. The synchronous sink
accepts only the copied mbuf when it returns zero. On any other result it must
accept nothing; negative backpressure retains the original skb for a later poll,
and a positive result is treated as `-EPROTO`. Once accepted, the adapter frees
the original skb. A successful prefix is irreversible and reported as the poll
return count, with any later error in `last_error`.

Cancellation returns the pending skb before a later FIFO entry and releases
its accounting charge once. Cleanup requires the FIFO and pending slot to be
empty; it never drops packets implicitly. Sink callbacks cannot reenter or
mutate the adapter. The sink is an application copy consumer: this adapter does
not implement an ethdev/NIC, wire transmission, hardware checksum offload, or
F-Stack's TX path.
