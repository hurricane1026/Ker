#ifndef KER_RUNTIME_TRANSPORT_RECEIVE_H
#define KER_RUNTIME_TRANSPORT_RECEIVE_H
#include "runtime/receive.h"
#include "runtime/udp-packet-view.h"
#include "runtime/tcp-packet-view.h"
#include "runtime/icmp-echo-packet-view.h"

enum ker_transport_protocol { KER_TRANSPORT_ICMP_ECHO = 1, KER_TRANSPORT_UDP = 17, KER_TRANSPORT_TCP = 6 };
struct ker_transport_message {
    enum ker_transport_protocol protocol;
    struct ker_ipv4_packet_view ipv4;
    union {
        struct ker_udp_packet_view udp;
        struct ker_tcp_packet_view tcp;
        struct ker_icmp_echo_packet_view icmp_echo;
    } packet;
};
/* Message and packet pointers are borrowed only for this synchronous call.
 * Callback must not retain, mutate, or free the message/views or skb and must
 * not use any view after return. The callback never owns an skb reference and
 * may return only NET_RX_SUCCESS or NET_RX_DROP. */
typedef int (*ker_transport_receive_fn)(const struct ker_transport_message *, void *);
struct ker_transport_receiver {
    struct ker_protocol_handler handler;
    ker_transport_receive_fn receive;
    void *arg;
    int validation_error; /* Last worker-local decode/admission error, or 0. */
};
/* Stable zero-initialized storage; pins device while registered. Only IPv4
 * UDP/TCP and ICMP echo request/reply views are delivered. A descriptor
 * shared by protocol fanout fails closed via the existing unique-owner view
 * checks. No socket, routing, fragment reassembly, ICMP control handling, TCP
 * state machine or NIC pipeline. */
int ker_transport_receiver_register(struct ker_transport_receiver *,
    struct ker_receive_runtime *, struct ker_eth_device *, ker_transport_receive_fn, void *);
int ker_transport_receiver_unregister(struct ker_transport_receiver *);
#endif
