#include "runtime/icmp-echo-service.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/ethernet.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <arpa/inet.h>

static int service_valid(const struct ker_icmp_echo_service *service)
{
    return service && service->receiver && service->monitor ? 0 : -EINVAL;
}

static void count_event(unsigned int *count)
{
    if (*count != UINT_MAX)
        ++*count;
}

static int service_receive(void *, struct sk_buff *,
    const struct ker_transport_message *);

int ker_icmp_echo_service_enable(struct ker_icmp_echo_service *service,
    struct ker_transport_receiver *receiver, struct ker_neighbor_monitor *monitor,
    uint8_t ttl)
{
    if (!service || !receiver || !monitor || !ttl)
        return -EINVAL;
    if (service->receiver || service->monitor)
        return -EALREADY;
    if (!receiver->handler.registered || receiver->echo_service || !receiver->handler.runtime ||
        !receiver->handler.device || !receiver->handler.runtime->context)
        return -EINVAL;
    if (!monitor->entry || !monitor->table || !monitor->table->address ||
        !monitor->resolution_enabled || !monitor->resolution_tx)
        return -EINVAL;
    struct ker_eth_device *device = receiver->handler.device;
    if (receiver->handler.runtime->dispatching)
        return -EBUSY;
    if (receiver->handler.runtime->context != device->context ||
        monitor->table->address->device != device ||
        monitor->resolution_tx->queue.context != device->context ||
        monitor->table->lcore != device->lcore || monitor->timer.lcore != device->lcore ||
        rte_lcore_id() != device->lcore)
        return -EXDEV;
    if (!monitor->timer.runtime || monitor->timer.runtime->polling ||
        monitor->timer.running || monitor->timer.scoping ||
        monitor->resolution_tx->polling || monitor->busy)
        return -EBUSY;
    if (monitor->echo_service_refs == UINT_MAX)
        return -EOVERFLOW;

    service->receiver = receiver;
    service->monitor = monitor;
    service->ttl = ttl;
    service->requests = service->replies_submitted = service->dropped = 0;
    service->last_error = 0;
    receiver->echo_service = service;
    receiver->echo_service_receive = service_receive;
    monitor->echo_service_refs++;
    return 0;
}

int ker_icmp_echo_service_disable(struct ker_icmp_echo_service *service)
{
    int error = service_valid(service);
    if (error)
        return error;
    struct ker_transport_receiver *receiver = service->receiver;
    struct ker_neighbor_monitor *monitor = service->monitor;
    if (rte_lcore_id() != receiver->handler.runtime->lcore)
        return -EXDEV;
    if (receiver->echo_service != service || !monitor->echo_service_refs)
        return -EINVAL;
    if (receiver->handler.runtime->dispatching || monitor->busy ||
        monitor->timer.runtime->polling || monitor->timer.running ||
        monitor->timer.scoping || monitor->resolution_tx->polling)
        return -EBUSY;
    receiver->echo_service = NULL;
    receiver->echo_service_receive = NULL;
    monitor->echo_service_refs--;
    *service = (struct ker_icmp_echo_service){0};
    return 0;
}

static int receive_valid(struct ker_icmp_echo_service *service, struct sk_buff *skb,
    const struct ker_transport_message *message)
{
    struct ker_transport_receiver *receiver = service->receiver;
    struct ker_neighbor_monitor *monitor = service->monitor;
    struct ker_eth_device *device = receiver->handler.device;
    struct ker_ipv4_address *address = monitor->table->address;
    if (!skb || !message || message->protocol != KER_TRANSPORT_ICMP_ECHO ||
        message->packet.icmp_echo.type != 8)
        return -EINVAL;
    if (skb->pkt_type != PACKET_HOST)
        return -EHOSTUNREACH;
    if (message->ipv4.header_length != 20 || message->ipv4.header[8] == 0)
        return -ENOTSUP;
    if (message->ipv4.frag_off != 0 && message->ipv4.frag_off != htons(0x4000U))
        return -ENOTSUP;
    __be32 source, destination, peer;
    memcpy(&source, message->ipv4.header + 12, sizeof(source));
    memcpy(&destination, message->ipv4.header + 16, sizeof(destination));
    memcpy(&peer, monitor->entry->primary_key, sizeof(peer));
    if (source != peer)
        return -EHOSTUNREACH;
    int local = ker_ipv4_address_is_local(address, destination);
    if (local <= 0)
        return local < 0 ? local : -EHOSTUNREACH;
    const unsigned char *ethernet = skb->head + skb->mac_header;
    if (memcmp(ethernet, device->native->dev_addr, ETH_ALEN) != 0)
        return -EHOSTUNREACH;
    return 0;
}

static int service_receive(void *opaque,
    struct sk_buff *skb, const struct ker_transport_message *message)
{
    struct ker_icmp_echo_service *service = opaque;
    int error = service_valid(service);
    if (error)
        return error;
    count_event(&service->requests);
    error = receive_valid(service, skb, message);
    if (error)
        goto drop;

    struct ker_neighbor_monitor *monitor = service->monitor;
    struct ker_ipv4_address *address = monitor->table->address;
    __be32 peer_ip;
    memcpy(&peer_ip, message->ipv4.header + 12, sizeof(peer_ip));
    const struct ker_ipv4_header_fields fields = {0};
    struct sk_buff *reply = NULL;
    static const unsigned char zero_mac[ETH_ALEN] = {0};
    error = ker_icmp_echo_ipv4_create_configured_fields(address, zero_mac, peer_ip,
        message->packet.icmp_echo.identifier, message->packet.icmp_echo.sequence,
        0, service->ttl, &fields, NULL, 0,
        message->packet.icmp_echo.payload, message->packet.icmp_echo.payload_length, &reply);
    if (error)
        goto drop;
    error = ker_neighbor_monitor_resolve_output(monitor, &reply);
    if (reply)
        BUG_ON(ker_skb_free(reply));
    if (error)
        goto drop;
    count_event(&service->replies_submitted);
    service->last_error = 0;
    return 0;

drop:
    count_event(&service->dropped);
    service->last_error = error;
    return error;
}
