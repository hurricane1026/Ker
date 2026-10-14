#include "runtime/udp-flow.h"
#include "runtime/worker.h"
#include "runtime/ipv4-address.h"
#include "runtime/neighbor-timer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <rte_lcore.h>
#include <string.h>

int ker_udp_channel_open_owned(struct ker_udp_channel *channel,
    struct ker_udp_io *io, const struct ker_flow_context *flow,
    const struct ker_udp_flow_open_config *config,
    struct ker_udp_endpoint_handle *out)
{
    if (!channel || !io || !flow || !config || !out || !flow->attached ||
        !flow->worker || !flow->worker->initialized || !io->receiver ||
        !io->receiver->handler.device || !io->icmpv4 ||
        !io->icmpv4->monitor || !io->icmpv4->monitor->table ||
        !io->icmpv4->monitor->table->address ||
        !io->icmpv4->monitor->table->address->native ||
        !config->first_port || config->first_port > config->last_port ||
        !config->peer_port)
        return -EINVAL;
    if (rte_lcore_id() != flow->lcore || io->owner_lcore != flow->lcore)
        return -EXDEV;
    if (flow->delivering || io->busy)
        return -EBUSY;
    struct ker_eth_device *device = io->receiver->handler.device;
    if (!device->context || device->context->packets != flow->worker->packets)
        return -EXDEV;
    struct in_ifaddr *ifa = io->icmpv4->monitor->table->address->native->ifa_list;
    if (!ifa)
        return -EINVAL;
    struct ker_flow_key key = {
        .domain = config->domain, .family = 4, .protocol = 17,
        .remote_port = ntohs(config->peer_port)
    };
    memcpy(key.local + 12, &ifa->ifa_local, 4);
    memcpy(key.remote + 12, &config->peer_address, 4);
    bool found_owner = false;
    for (uint32_t port = config->first_port; port <= config->last_port; ++port) {
        key.local_port = (uint16_t)port;
        unsigned int owner;
        int error = ker_flow_owner(flow, &key, &owner);
        if (error)
            return error;
        if (owner != flow->worker_id)
            continue;
        found_owner = true;
        struct ker_udp_endpoint_handle handle;
        error = ker_udp_channel_open(channel, io, htons((uint16_t)port),
            config->slots, config->payloads, config->capacity,
            config->max_datagram, config->byte_limit, &handle);
        if (error == -EADDRINUSE)
            continue;
        if (error)
            return error;
        error = ker_udp_endpoint_connect(io->endpoints, handle,
            config->peer_address, config->peer_port);
        if (error) {
            int rollback = ker_udp_channel_close(channel);
            return rollback ? rollback : error;
        }
        *out = handle;
        return 0;
    }
    return found_owner ? -EADDRINUSE : -EADDRNOTAVAIL;
}
