# TCP control view and native MSS parsing

The private TCP packet view exposes host-order sequence, acknowledgment,
window, urgent pointer, and nine control flag bits (including AccECN AE).
`end_sequence` wraps modulo 2^32 and includes payload length and sequence space
consumed by SYN and FIN. It describes the received segment; it does not approve
its flags, acknowledgment, or sequence for a connection state. Ports and the
checksum continue to use wire order. Bytes remain borrowed until skb mutation
or release, and the complete IPv4/TCP checksums are validated before any view
is returned.

`ker_tcp_syn_mss()` validates the same owned classified skb, requires SYN
(including SYN-ACK), and invokes the pinned Linux `tcp_parse_mss_option()` on a
private aligned copy of its TCP header/options. The original `struct tcphdr`
layout and parser body are imported verbatim. Ker supplies byte-order selection,
an unaligned big-endian read adapter, and a private symbol name; upstream Linux
files are not edited.

The MSS is host order. Zero means no usable MSS was found, so future connection
code must choose its default and apply path-MTU policy. A nonzero `user_mss`
caps the advertised value. Linux semantics are preserved: NOP and unknown
well-sized options are skipped, EOL or malformed/truncated options stop parsing,
zero MSS is ignored, and the last valid nonzero MSS before a stop wins. A
negative errno leaves the output unchanged; parsing never consumes or mutates
the skb.

The importer verifies SHA-256 hashes of every source file in
`src/compat/linux-tcp-mss-manifest.json` and records each extracted definition's
source offsets and hash. `tcp-mss-import` checks provenance, reproducibility,
and rejection of altered upstream input. `tcp-control` tests validated Ethernet
RX packets, wraparound, SYN/FIN sequence consumption, control flags, advertised
windows, MSS caps/duplicates/malformed options, checksum rejection, output
transactionality, and packet-pool cleanup.

```sh
ctest --test-dir /path/to/build -R '^(tcp-control|tcp-mss-import)$' --output-on-failure
```

This is the control-field and SYN MSS foundation for subsequent TCP work. It
adds no connection/listener/accept API, handshake state machine, retransmission,
congestion control, stream reassembly, or TCP public capability. Window scaling,
SACK, timestamps, TCP authentication, and Fast Open negotiation still require
separate adaptation and validation.

The next private passive-handshake profile is documented in [TCP listener](tcp-listener.md).
