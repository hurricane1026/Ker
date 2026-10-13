#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-receive.h"
#include "runtime/arp-responder.h"
#include "runtime/ethernet.h"
#include "runtime/icmp-echo-service.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/tcp-create.h"
#include "runtime/udp-create.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/neighbor.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include "ker/linux_neighbor_update.h"
#include <errno.h>
#include <net/checksum.h>

static struct ker_packet_pool apool, bpool;
static struct ker_skb_context actx, bctx;
static struct ker_eth_device adev, bdev;
static struct ker_ipv4_address aaddr, baddr;
static struct ker_receive_runtime art, brt;
static struct ker_arp_responder aresponder;
static struct ker_arp_receiver barp;
static struct ker_transport_receiver brx_transport, arx_transport;
static struct ker_neighbor_table bneighbors;
static struct ker_neighbor_monitor bmonitor;
static struct ker_icmp_echo_service service;
static struct ker_worker aworker, bworker;
static struct ker_tx_ring ab, ba;
static struct ker_rx_ring arx, brx;
static struct ker_tx_export atx, btx;
static const unsigned char amac[6] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const unsigned char bmac[6] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static const unsigned char broadcast[6] = {255, 255, 255, 255, 255, 255};
static const unsigned char payload[] = {0x00, 0x4b, 0x65, 0x72, 0xff};
static const __be16 identifier = 0x3412, sequence = 0x7856;
static __be32 aip, bip;
static unsigned int replies_seen, fallback_seen, udp_seen, tcp_seen, arp_feedback;

static int ring_sink(struct rte_mbuf *packet, void *arg)
{ return ker_tx_ring_sink(packet, arg); }
static int receive_echo(const struct ker_transport_message *message, void *arg)
{
    (void)arg;
    CHECK(message->protocol == KER_TRANSPORT_ICMP_ECHO);
    CHECK(message->packet.icmp_echo.type == 0 && message->packet.icmp_echo.code == 0);
    CHECK(message->ipv4.header_length == 20 && message->ipv4.header[8] == 37);
    CHECK(message->ipv4.header[1] == 0 && message->ipv4.header[4] == 0 &&
        message->ipv4.header[5] == 0 && message->ipv4.header[6] == 0 &&
        message->ipv4.header[7] == 0);
    CHECK(!memcmp(message->ipv4.header + 12, &bip, 4));
    CHECK(!memcmp(message->ipv4.header + 16, &aip, 4));
    CHECK(message->packet.icmp_echo.identifier == identifier);
    CHECK(message->packet.icmp_echo.sequence == sequence);
    CHECK(message->packet.icmp_echo.payload_length == sizeof(payload));
    CHECK(!memcmp(message->packet.icmp_echo.payload, payload, sizeof(payload)));
    ++replies_seen;
    return NET_RX_SUCCESS;
}
static int fallback(const struct ker_transport_message *message, void *arg)
{
    (void)arg;
    ++fallback_seen;
    if (message->protocol == KER_TRANSPORT_ICMP_ECHO) {
        CHECK(message->packet.icmp_echo.type == 0);
    } else if (message->protocol == KER_TRANSPORT_UDP) {
        CHECK(message->packet.udp.payload_length == sizeof(payload));
        CHECK(!memcmp(message->packet.udp.payload, payload, sizeof(payload)));
        ++udp_seen;
    } else if (message->protocol == KER_TRANSPORT_TCP) {
        CHECK(message->packet.tcp.payload_length == sizeof(payload));
        CHECK(!memcmp(message->packet.tcp.payload, payload, sizeof(payload)));
        ++tcp_seen;
    } else {
        CHECK(false);
    }
    return NET_RX_SUCCESS;
}
static int feedback(const struct ker_arp_message *message, void *arg)
{
    (void)arg;
    CHECK(message->operation == ARPOP_REPLY && message->sender_ip == aip &&
        message->target_ip == bip && message->target_local);
    ++arp_feedback;
    return ker_arp_neighbor_feedback(&barp, &bmonitor, message,
        NEIGH_UPDATE_F_OVERRIDE) ? NET_RX_DROP : NET_RX_SUCCESS;
}
static void send_probe(const struct ker_neighbor_event *event, void *arg)
{
    (void)arg;
    struct sk_buff *probe = NULL;
    CHECK(ker_arp_probe_create(&bmonitor, event, &probe) == 0 && probe);
    CHECK(ker_tx_export_enqueue(&btx, &probe) == 0 && !probe);
}
static int a_rx(void *arg, unsigned int budget) { (void)arg; return ker_rx_ring_poll(&arx, budget); }
static int b_rx(void *arg, unsigned int budget) { (void)arg; return ker_rx_ring_poll(&brx, budget); }
static int a_tx(void *arg, unsigned int budget) { (void)arg; return ker_tx_export_poll(&atx, budget); }
static int b_tx(void *arg, unsigned int budget) { (void)arg; return ker_tx_export_poll(&btx, budget); }
static struct ker_worker_result poll_worker(struct ker_worker *worker)
{
    struct ker_worker_result result = {0};
    CHECK(ker_worker_poll(worker, worker->timers.now_ns, &result) == 0);
    return result;
}
static void inject_request(struct sk_buff *packet)
{
    CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
    struct ker_worker_result result = poll_worker(&aworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&bworker);
    CHECK(result.rx == 1);
}
static void send_custom_request(__be32 source, __be32 destination,
    const unsigned char destination_mac[ETH_ALEN], const void *options,
    unsigned int options_length)
{
    const struct ker_ipv4_header_fields fields = {0};
    struct sk_buff *packet = NULL;
    CHECK(ker_icmp_echo_ipv4_create_fields(&actx, amac, destination_mac,
        source, destination, identifier, sequence, 8, 64, &fields,
        options, options_length, payload, sizeof(payload), &packet) == 0);
    inject_request(packet);
}
static void refresh_ip_checksum(struct sk_buff *packet)
{
    unsigned char *ip = packet->data + ETH_HLEN;
    ip[10] = ip[11] = 0;
    __sum16 checksum = csum_fold(csum_partial(ip, 20, 0));
    memcpy(ip + 10, &checksum, sizeof(checksum));
}
static void run(void)
{
    CHECK(ker_packet_pool_init(&apool, "echo_svc_a", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_packet_pool_init(&bpool, "echo_svc_b", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&actx, &apool, "echo_svc_actx") == 0);
    CHECK(ker_skb_context_init(&bctx, &bpool, "echo_svc_bctx") == 0);
    aip = rte_cpu_to_be_32(0xc0000201); bip = rte_cpu_to_be_32(0xc0000202);
    CHECK(ker_eth_device_init(&adev, &actx, "echo_svc_a", 1, amac) == 0);
    CHECK(ker_eth_device_init(&bdev, &bctx, "echo_svc_b", 2, bmac) == 0);
    CHECK(ker_arp_device_setup(&adev) == 0 && ker_arp_device_setup(&bdev) == 0);
    CHECK(ker_ipv4_address_init(&aaddr, &adev, aip, 24) == 0);
    CHECK(ker_ipv4_address_init(&baddr, &bdev, bip, 24) == 0);
    CHECK(ker_receive_runtime_init(&art, &actx) == 0);
    CHECK(ker_receive_runtime_init(&brt, &bctx) == 0);
    CHECK(ker_neighbor_table_init(&bneighbors, &baddr, "echo_svc_neighbors", 4, 2) == 0);
    struct ker_neighbor_config ncfg = {.retrans_ticks = 20, .reachable_ticks = 100,
        .delay_ticks = 30, .ucast_probes = 2, .mcast_probes = 2,
        .mcast_reprobes = 1, .queue_bytes = 16384};
    CHECK(ker_neighbor_configure(&bneighbors, &ncfg) == 0);
    CHECK(ker_tx_ring_init(&ab, "echo_svc_ab", 4, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_ring_init(&ba, "echo_svc_ba", 4, SOCKET_ID_ANY) == 0);
    CHECK(ker_tx_export_init(&atx, &actx, 8, 32768, ring_sink, &ab) == 0);
    CHECK(ker_tx_export_init(&btx, &bctx, 8, 32768, ring_sink, &ba) == 0);
    CHECK(ker_rx_ring_init(&arx, &ba, &adev, &art, 128) == 0);
    CHECK(ker_rx_ring_init(&brx, &ab, &bdev, &brt, 128) == 0);
    CHECK(ker_transport_receiver_register(&brx_transport, &brt, &bdev, fallback, NULL) == 0);
    CHECK(ker_transport_receiver_register(&arx_transport, &art, &adev, receive_echo, NULL) == 0);
    CHECK(ker_arp_responder_register(&aresponder, &art, &aaddr, &atx) == 0);
    CHECK(ker_arp_receiver_register(&barp, &brt, &baddr, feedback, NULL) == 0);
    struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1, .tx_budget = 1};
    struct ker_worker_ops aops = {.rx = a_rx, .tx = a_tx};
    struct ker_worker_ops bops = {.rx = b_rx, .tx = b_tx};
    CHECK(ker_worker_init(&aworker, &apool, &config, &aops) == 0);
    CHECK(ker_worker_init(&bworker, &bpool, &config, &bops) == 0);
    CHECK(ker_neighbor_monitor_discovery_init(&bmonitor, &bneighbors, &bworker.timers,
        &btx, aip, send_probe, NULL, NULL) == 0);
    CHECK(ker_icmp_echo_service_enable(&service, &brx_transport, &bmonitor, 37) == 0);
    CHECK(ker_transport_receiver_unregister(&brx_transport) == -EBUSY);
    CHECK(ker_neighbor_monitor_cleanup(&bmonitor) == -EBUSY);
    CHECK(ker_neighbor_monitor_resolution_disable(&bmonitor) == -EBUSY);

    struct sk_buff *request = NULL;
    const struct ker_ipv4_header_fields request_fields = {
        .ds_field = 0x2e, .identification = rte_cpu_to_be_16(0x1234),
        .frag_off = rte_cpu_to_be_16(0x4000)};
    CHECK(ker_icmp_echo_ipv4_create_configured_fields(&aaddr, bmac, bip, identifier,
        sequence, 8, 64, &request_fields, NULL, 0, payload, sizeof(payload), &request) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &request) == 0 && !request);
    struct ker_worker_result result = poll_worker(&aworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&bworker);
    CHECK(result.rx == 1 && result.tx == 0);
    CHECK(service.requests == 1 && service.replies_submitted == 1 && !service.dropped);
    CHECK(bmonitor.entry->arp_queue.qlen == 1);
    CHECK(ker_icmp_echo_service_disable(&service) == 0);
    CHECK(bmonitor.entry->arp_queue.qlen == 1 && btx.packets == 1);
    CHECK(btx.packets == 1); /* ARP probe waits on B's normal bounded exporter. */
    result = poll_worker(&bworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&aworker);
    CHECK(result.rx == 1 && result.tx == 0); /* A's production ARP responder. */
    CHECK(atx.packets == 1);
    result = poll_worker(&aworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&bworker);
    CHECK(result.rx == 1 && result.tx == 0); /* B applies scoped native ARP feedback. */
    CHECK(arp_feedback == 1 && btx.packets == 1);
    result = poll_worker(&bworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&aworker);
    CHECK(result.rx == 1 && result.tx == 0);
    CHECK(replies_seen == 1 && !btx.packets && !atx.packets);
    CHECK(ker_icmp_echo_service_enable(&service, &brx_transport, &bmonitor, 37) == 0);

    unsigned int old_requests = service.requests;
    unsigned int old_drops = service.dropped;
    send_custom_request(rte_cpu_to_be_32(0xc0000209), bip, bmac, NULL, 0);
    CHECK(service.requests == old_requests + 1 && service.dropped == old_drops + 1 &&
        service.last_error == -EHOSTUNREACH);
    send_custom_request(aip, rte_cpu_to_be_32(0xc0000209), bmac, NULL, 0);
    send_custom_request(aip, bip, broadcast, NULL, 0);
    static const unsigned char option_bytes[4] = {1, 1, 1, 1};
    send_custom_request(aip, bip, bmac, option_bytes, sizeof(option_bytes));
    CHECK(service.requests == old_requests + 4 && service.dropped == old_drops + 4 &&
        service.last_error == -ENOTSUP);

    struct sk_buff *bad_ttl = NULL;
    const struct ker_ipv4_header_fields zero_fields = {0};
    CHECK(ker_icmp_echo_ipv4_create_fields(&actx, amac, bmac, aip, bip,
        identifier, sequence, 8, 1, &zero_fields, NULL, 0,
        payload, sizeof(payload), &bad_ttl) == 0);
    bad_ttl->data[ETH_HLEN + 8] = 0;
    refresh_ip_checksum(bad_ttl);
    inject_request(bad_ttl);
    CHECK(service.requests == old_requests + 5 && service.dropped == old_drops + 5 &&
        service.last_error == -ENOTSUP);

    struct sk_buff *reserved = NULL;
    CHECK(ker_icmp_echo_ipv4_create_fields(&actx, amac, bmac, aip, bip,
        identifier, sequence, 8, 64, &zero_fields, NULL, 0,
        payload, sizeof(payload), &reserved) == 0);
    reserved->data[ETH_HLEN + 6] = 0x80;
    refresh_ip_checksum(reserved);
    inject_request(reserved);
    CHECK(service.requests == old_requests + 6 && service.dropped == old_drops + 6 &&
        service.last_error == -ENOTSUP);

    struct sk_buff *bad_checksum = NULL;
    CHECK(ker_icmp_echo_ipv4_create_fields(&actx, amac, bmac, aip, bip,
        identifier, sequence, 8, 64, &zero_fields, NULL, 0,
        payload, sizeof(payload), &bad_checksum) == 0);
    bad_checksum->data[ETH_HLEN + 20 + 8] ^= 1;
    inject_request(bad_checksum);
    CHECK(service.requests == old_requests + 6 && service.dropped == old_drops + 6 &&
        brx_transport.validation_error == -EBADMSG);

    struct sk_buff *pressure_request = NULL;
    CHECK(ker_icmp_echo_ipv4_create_configured(&aaddr, bmac, bip, identifier,
        sequence, 8, 64, NULL, 0, payload, sizeof(payload), &pressure_request) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &pressure_request) == 0 && !pressure_request);
    struct ker_worker_result pressure_result = poll_worker(&aworker);
    CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
    struct rte_mbuf *held[63];
    unsigned int held_count = 0;
    while (rte_mempool_avail_count(bpool.mbufs) > 1 && held_count < 63 &&
        (held[held_count] = ker_packet_alloc(&bpool)) != NULL)
        ++held_count;
    CHECK(held_count > 0 && rte_mempool_avail_count(bpool.mbufs) == 1);
    CHECK(ker_rx_ring_poll(&brx, 1) == 1 && brx.last_dropped == 1);
    CHECK(service.last_error == -ENOMEM && bmonitor.entry->arp_queue.qlen == 0 &&
        !service.replies_submitted);
    for (unsigned int i = 0; i < held_count; ++i)
        ker_packet_free(held[i]);

    for (unsigned int i = 0; i < btx.packet_limit; ++i) {
        struct sk_buff *filler = NULL;
        unsigned char *byte = NULL;
        CHECK(ker_skb_alloc(&bctx, 64, 128, &filler) == 0);
        CHECK(ker_skb_put(filler, 1, &byte) == 0);
        *byte = (unsigned char)i;
        CHECK(ker_tx_export_enqueue(&btx, &filler) == 0 && !filler);
    }
    old_requests = service.requests;
    old_drops = service.dropped;
    struct sk_buff *full_export_request = NULL;
    CHECK(ker_icmp_echo_ipv4_create_configured(&aaddr, bmac, bip, identifier,
        sequence, 8, 64, NULL, 0, payload, sizeof(payload), &full_export_request) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &full_export_request) == 0 && !full_export_request);
    pressure_result = poll_worker(&aworker);
    CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
    CHECK(ker_rx_ring_poll(&brx, 1) == 1);
    CHECK(service.requests == old_requests + 1 && service.dropped == old_drops + 1 &&
        service.last_error == -ENOSPC && btx.packets == btx.packet_limit);
    for (unsigned int i = 0; i < btx.packet_limit; ++i) {
        struct sk_buff *canceled = NULL;
        CHECK(ker_tx_export_cancel(&btx, &canceled) == 1 && canceled);
        BUG_ON(ker_skb_free(canceled));
    }

    /* A successful request after pressure clears last_error and proves the
     * service and monitored neighbor recovered without replacing the app. */
    send_custom_request(aip, bip, bmac, NULL, 0);
    CHECK(service.last_error == 0 && service.replies_submitted == 1);
    pressure_result = poll_worker(&bworker);
    CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
    pressure_result = poll_worker(&aworker);
    CHECK(pressure_result.rx == 1 && replies_seen == 2);

    struct sk_buff *fallback_packet = NULL;
    CHECK(ker_udp_ipv4_create_configured(&aaddr, bmac, bip,
        rte_cpu_to_be_16(41001), rte_cpu_to_be_16(41002), 64, NULL, 0,
        payload, sizeof(payload), &fallback_packet) == 0);
    inject_request(fallback_packet);
    CHECK(udp_seen == 1);
    CHECK(ker_tcp_ipv4_create_configured(&aaddr, bmac, bip,
        rte_cpu_to_be_16(42001), rte_cpu_to_be_16(42002), rte_cpu_to_be_32(1),
        0, rte_cpu_to_be_16(4096), 0x02, 64, NULL, 0, NULL, 0,
        payload, sizeof(payload), &fallback_packet) == 0);
    inject_request(fallback_packet);
    CHECK(tcp_seen == 1 && fallback_seen == 2);

    /* Type zero bypasses the service and remains visible to the app callback. */
    CHECK(ker_icmp_echo_ipv4_create_configured(&aaddr, bmac, bip, identifier,
        sequence, 0, 64, NULL, 0, payload, sizeof(payload), &request) == 0);
    CHECK(ker_tx_export_enqueue(&atx, &request) == 0 && !request);
    result = poll_worker(&aworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&bworker);
    CHECK(result.rx == 1 && fallback_seen == 3);

    CHECK(ker_icmp_echo_service_disable(&service) == 0);
    CHECK(ker_neighbor_monitor_cleanup(&bmonitor) == 0);
    CHECK(ker_arp_receiver_unregister(&barp) == 0);
    CHECK(ker_arp_responder_unregister(&aresponder) == 0);
    CHECK(ker_transport_receiver_unregister(&arx_transport) == 0);
    CHECK(ker_transport_receiver_unregister(&brx_transport) == 0);
    CHECK(ker_rx_ring_cleanup(&arx) == 0 && ker_rx_ring_cleanup(&brx) == 0);
    CHECK(ker_worker_cleanup(&bworker) == 0 && ker_worker_cleanup(&aworker) == 0);
    CHECK(ker_neighbor_table_cleanup(&bneighbors) == 0);
    CHECK(ker_tx_export_cleanup(&btx) == 0 && ker_tx_export_cleanup(&atx) == 0);
    CHECK(ker_tx_ring_cleanup(&ba) == 0 && ker_tx_ring_cleanup(&ab) == 0);
    CHECK(ker_receive_runtime_cleanup(&brt) == 0 && ker_receive_runtime_cleanup(&art) == 0);
    CHECK(ker_ipv4_address_cleanup(&baddr) == 0 && ker_ipv4_address_cleanup(&aaddr) == 0);
    CHECK(ker_eth_device_cleanup(&bdev) == 0 && ker_eth_device_cleanup(&adev) == 0);
    CHECK(ker_skb_context_cleanup(&bctx) == 0 && ker_skb_context_cleanup(&actx) == 0);
    CHECK(ker_packet_pool_cleanup(&bpool) == 0 && ker_packet_pool_cleanup(&apool) == 0);
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 64) == 0);
    run();
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
