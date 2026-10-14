#ifndef KER_RUNTIME_TCP_MSS_H
#define KER_RUNTIME_TCP_MSS_H
#include "runtime/tcp-packet-view.h"

/* Validate the owned, classified IPv4 TCP skb before running the original
 * Linux MSS parser on a private aligned header copy. Requires SYN (SYN-ACK
 * included). Returns zero on success and writes host-order MSS, or zero MSS
 * when no usable option precedes EOL/malformed input. A nonzero user_mss caps
 * the advertised value. Duplicate and malformed option handling follow Linux:
 * the last valid nonzero MSS before a parse stop wins. No default MSS, path
 * MTU policy, connection state, consumption or packet mutation is implied.
 * On negative errno, result is unchanged. */
int ker_tcp_syn_mss(struct ker_skb_context *, struct sk_buff *,
                    uint16_t user_mss, uint16_t *result);
#endif
