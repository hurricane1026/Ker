#ifndef KER_RUNTIME_RECEIVE_H
#define KER_RUNTIME_RECEIVE_H
#include "ker/linux_receive.h"
#include "runtime/ethernet.h"

#define KER_RECEIVE_MAX_HANDLERS 256
struct ker_protocol_handler;
/* Each invocation owns ONE skb reference and must free or retain it on every
 * return path. Earlier handlers may share the descriptor; clone then COW to
 * modify packet data. Native packet_type and device pointers are borrowed for
 * the callback only. Return NET_RX_SUCCESS or NET_RX_DROP, not an errno. */
typedef int (*ker_protocol_fn)(struct sk_buff *, struct ker_protocol_handler *,
    struct net_device *original_device, void *arg);
struct ker_receive_runtime {
    struct list_head protocols[PTYPE_HASH_SIZE];
    struct ker_skb_context *context;
    unsigned int lcore;
    unsigned int live;
    unsigned int delivered;
    int callback_error;
    bool initialized;
    bool dispatching;
};
struct ker_protocol_handler {
    struct packet_type native;
    struct ker_receive_runtime *runtime;
    struct ker_eth_device *device; /* NULL: wildcard within this runtime */
    ker_protocol_fn receive;
    void *arg;
    bool registered;
};
struct ker_receive_result { unsigned int handlers; int status; };
/* Caller-owned, zero-initialized, stable storage. Every operation belongs to
 * one initialized worker. Runtime pins its context; bound handlers pin device.
 * No Linux dev_add_pack/RCU/netns/device registration implementation implied. */
int ker_receive_runtime_init(struct ker_receive_runtime *runtime, struct ker_skb_context *context);
int ker_receive_runtime_cleanup(struct ker_receive_runtime *runtime);
/* Specific Ethernet II protocols only; wire-order type. Last registered handler
 * matches first (Linux list insertion order). No ETH_P_ALL taps or list_func. */
int ker_protocol_register(struct ker_receive_runtime *runtime, struct ker_protocol_handler *handler,
    struct ker_eth_device *device, __be16 type, ker_protocol_fn receive, void *arg);
int ker_protocol_unregister(struct ker_protocol_handler *handler);
/* Input must be a unique descriptor from this runtime's context, already L2
 * classified on device. Validation failures preserve *skb/result. On dispatch
 * (including unhandled/drop), *skb becomes NULL and result describes delivery.
 * A callback contract violation returns -EPROTO AFTER consuming input; a
 * negative return alone is not evidence that the caller still owns the skb. */
int ker_receive_dispatch(struct ker_receive_runtime *runtime, struct ker_eth_device *device,
    struct sk_buff **skb, struct ker_receive_result *result);
#endif
