#include "check.h"
#include "eal.h"
#include "runtime/icmpv4-pmtu.h"
#include "runtime/icmpv4-service.h"
#include "runtime/icmpv4-create.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include "runtime/neighbor.h"
#include "runtime/neighbor-timer.h"
#include "runtime/tx-export.h"
#include "runtime/udp-create.h"
#include "runtime/receive.h"
#include "runtime/transport-receive.h"
#include <errno.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static struct ker_runtime runtime_clock;
static struct ker_neighbor_monitor monitor;
static struct ker_tx_export tx;
static struct ker_receive_runtime receive_runtime;
static struct ker_transport_receiver receiver;
static struct ker_icmpv4_service service;
static struct ker_icmpv4_pmtu *event_pmtu;
static struct rte_mbuf *sent_packet;
static uint64_t now_ms;
static unsigned int confirmations;
static unsigned int clock_calls;
static bool trigger_clock_reentry;
static int reentry_disable_result, reentry_output_result;
static int event_result;
static int confirmation_result = 1;
static unsigned char sent_quote[28];
static const unsigned char local_mac[6] = {2, 0, 0, 0, 0, 1};
static const unsigned char peer_mac[6] = {2, 0, 0, 0, 0, 2};
static const unsigned char router_mac[6] = {2, 0, 0, 0, 0, 9};
static __be32 local_ip, peer_ip;
static __be32 router_ip;

static uint64_t clock_ms(void *arg)
{
    (void)arg;
    ++clock_calls;
    if (trigger_clock_reentry) {
        trigger_clock_reentry = false;
        reentry_disable_result = ker_neighbor_monitor_resolution_disable(&monitor);
        struct sk_buff *nested = (struct sk_buff *)(uintptr_t)1;
        reentry_output_result = ker_neighbor_monitor_output(&monitor, &tx, &nested);
        CHECK(nested == (struct sk_buff *)(uintptr_t)1);
    }
    return now_ms;
}
static int confirm_sent(void *arg, __be32 local, __be32 peer,
    const struct ker_icmpv4_quoted_ipv4_view *quote)
{
    (void)arg;
    CHECK(local == local_ip && peer == peer_ip && quote->flow_available &&
        quote->total_length > 1200 && quote->protocol == IPPROTO_UDP);
    ++confirmations;
    if (quote->quoted_length != sizeof(sent_quote) ||
        memcmp(quote->header, sent_quote, sizeof(sent_quote)))
        return 0;
    return confirmation_result;
}
static int fallback(const struct ker_transport_message *message, void *arg)
{ (void)message; (void)arg; return NET_RX_SUCCESS; }
static void pmtu_event(const struct ker_icmpv4_control_event *event, void *arg)
{
    (void)arg;
    CHECK(event->type == 3 && event->code == 4 && event->source == router_ip &&
        event->destination == local_ip && event->has_quote &&
        event->message.quoted_ipv4 == event->quote.header);
    event_result = ker_icmpv4_pmtu_apply(event_pmtu, &event->message, &event->quote);
}
static uint64_t service_clock(void *arg) { (void)arg; return now_ms; }
static int sink(struct rte_mbuf *packet, void *arg)
{
    (void)arg;
    CHECK(!sent_packet);
    sent_packet = packet;
    return 0;
}
static void probe_noop(const struct ker_neighbor_event *event, void *arg)
{ (void)event; (void)arg; }
static struct ker_icmpv4_packet_view frag_needed(uint16_t mtu,
    const struct ker_icmpv4_quoted_ipv4_view *quote)
{
    struct ker_icmpv4_packet_view view = {.header = quote->header,
        .type = 3, .code = 4, .payload = quote->header,
        .payload_length = quote->quoted_length};
    view.rest[2] = (unsigned char)(mtu >> 8); view.rest[3] = (unsigned char)mtu;
    return view;
}
static int output(struct sk_buff **skb)
{ return ker_neighbor_monitor_output(&monitor, &tx, skb); }

int main(void)
{
    ker_test_eal_init();
    local_ip = rte_cpu_to_be_32(0xc0000201U);
    peer_ip = rte_cpu_to_be_32(0xc0000202U);
    router_ip = rte_cpu_to_be_32(0xc0000209U);
    CHECK(ker_memory_init(SOCKET_ID_ANY, 8) == 0);
    CHECK(ker_packet_pool_init(&pool, "pmtu_packets", 63, 0, 2048, SOCKET_ID_ANY) == 0);
    CHECK(ker_skb_context_init(&context, &pool, "pmtu_skbs") == 0);
    CHECK(ker_eth_device_init(&device, &context, "pmtu_eth", 1, local_mac) == 0);
    device.native->mtu = 1500;
    CHECK(ker_arp_device_setup(&device) == 0);
    CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
    CHECK(ker_neighbor_table_init(&table, &address, "pmtu_neighbors", 2, 1) == 0);
    struct ker_neighbor_config config = {.retrans_ticks=20, .reachable_ticks=100,
        .delay_ticks=30, .ucast_probes=2, .mcast_probes=2, .mcast_reprobes=1,
        .queue_bytes=8192};
    CHECK(ker_neighbor_configure(&table, &config) == 0);
    CHECK(ker_neighbor_add(&table, peer_ip, peer_mac) == 0);
    ker_runtime_init(&runtime_clock);
    CHECK(ker_neighbor_monitor_init(&monitor, &table, &runtime_clock, peer_ip,
        probe_noop, NULL, NULL) == 0);
    CHECK(ker_tx_export_init(&tx, &context, 4, SIZE_MAX, sink, NULL) == 0);
    CHECK(ker_neighbor_monitor_resolution_enable(&monitor, &tx) == 0);
    CHECK(ker_receive_runtime_init(&receive_runtime, &context) == 0);
    CHECK(ker_transport_receiver_register(&receiver, &receive_runtime, &device,
        fallback, NULL) == 0);

    struct ker_icmpv4_pmtu pmtu = {0};
    now_ms = 100;
    CHECK(ker_icmpv4_pmtu_init(&pmtu, &monitor, 1500, 1000,
        clock_ms, NULL, confirm_sent, NULL) == 0);
    unsigned int after_init_clock_calls = clock_calls;
    CHECK(ker_icmpv4_pmtu_init(&pmtu, &monitor, 1400, 1000,
        clock_ms, NULL, confirm_sent, NULL) == -EALREADY);
    CHECK(clock_calls == after_init_clock_calls && monitor.output_mtu_ctx == &pmtu);
    CHECK(ker_neighbor_monitor_cleanup(&monitor) == -EBUSY);
    struct ker_icmpv4_service_config service_config = {.ttl=64, .burst=4,
        .refill_ms=100, .monotonic_ms=service_clock, .event=pmtu_event,
        .event_arg=NULL};
    CHECK(ker_icmpv4_service_enable(&service, &receiver, &monitor, &service_config) == 0);
    event_pmtu = &pmtu;
    unsigned char real_payload[1300] = {0};
    const struct ker_ipv4_header_fields sent_fields = {.frag_off=rte_cpu_to_be_16(0x4000)};
    struct sk_buff *sent_skb = NULL;
    CHECK(ker_udp_ipv4_create_configured_fields(&address, peer_mac, peer_ip,
        rte_cpu_to_be_16(0x1234), rte_cpu_to_be_16(0x5678), 64, &sent_fields,
        NULL, 0, real_payload, sizeof(real_payload), &sent_skb) == 0);
    CHECK(output(&sent_skb) == 0 && !sent_skb);
    CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
    unsigned char quote_bytes[28];
    const unsigned char *sent_wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
    memcpy(quote_bytes, sent_wire + ETH_HLEN, sizeof(quote_bytes));
    memcpy(sent_quote, quote_bytes, sizeof(sent_quote));
    ker_packet_free(sent_packet); sent_packet = NULL;
    struct ker_icmpv4_quoted_ipv4_view quote;
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote_bytes, sizeof(quote_bytes), &quote) == 0);
    struct ker_icmpv4_packet_view outer = frag_needed(1200, &quote);
    unsigned char rest[4] = {0, 0, 4, 0xb0};
    struct sk_buff *incoming = NULL;
    CHECK(ker_icmpv4_ipv4_create(&context, router_mac, local_mac, router_ip,
        local_ip, 3, 4, rest, 64, quote_bytes, sizeof(quote_bytes), &incoming) == 0);
    struct rte_mbuf *incoming_mbuf = NULL;
    CHECK(ker_skb_to_mbuf(incoming, &incoming_mbuf) == 0);
    CHECK(ker_skb_free(incoming) == 0);
    incoming = NULL;
    CHECK(ker_eth_receive(&device, incoming_mbuf, &incoming) == 0 && incoming);
    struct ker_receive_result receive_result;
    event_result = 0;
    int dispatch_error = ker_receive_dispatch(&receive_runtime, &device, &incoming, &receive_result);
    CHECK(dispatch_error == 0);
    CHECK(!incoming && receive_result.handlers == 1 && receive_result.status == NET_RX_SUCCESS);
    CHECK(event_result == 1 && service.events_delivered == 1 && confirmations == 1);
    unsigned int owner = table.lcore;
    unsigned int before_wrong_owner = clock_calls;
    table.lcore = owner + 1;
    uint32_t unchanged_mtu = 777;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &unchanged_mtu) == -EXDEV &&
        unchanged_mtu == 777 && clock_calls == before_wrong_owner);
    CHECK(monitor.output_mtu(monitor.output_mtu_ctx, &unchanged_mtu) == -EXDEV &&
        unchanged_mtu == 777 && clock_calls == before_wrong_owner);
    table.lcore = owner;
    outer = frag_needed(67, &quote);
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == -ERANGE && confirmations == 1);
    uint32_t mtu = 0;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1200);

    struct sk_buff *skb = NULL;
    unsigned char payload[1300] = {0}, original[ETH_HLEN + 20 + 8 + sizeof(payload)];
    CHECK(ker_udp_ipv4_create_configured(&address, peer_mac, peer_ip,
        rte_cpu_to_be_16(1234), rte_cpu_to_be_16(4321), 64, NULL, 0,
        payload, sizeof(payload), &skb) == 0);
    CHECK(skb->len == sizeof(original));
    memcpy(original, skb->data, sizeof(original));
    trigger_clock_reentry = true;
    CHECK(output(&skb) == -EMSGSIZE && skb && monitor.output_mtu_ctx == &pmtu &&
        reentry_disable_result == -EBUSY && reentry_output_result == -EBUSY);
    CHECK(!monitor.busy && !pmtu.busy);
    CHECK(output(&skb) == -EMSGSIZE && skb && !memcmp(original, skb->data, sizeof(original)));

    /* A valid but unconfirmed quotation cannot change the cached path. */
    confirmation_result = 0;
    outer = frag_needed(1100, &quote);
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == 0);
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1200);
    confirmation_result = 1;
    /* Matching addresses with an unsent transport tuple are not evidence. */
    quote_bytes[20] ^= 1;
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == 0);
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1200);
    quote_bytes[20] ^= 1;
    /* An increase is ignored without asking the sent-packet verifier. */
    outer = frag_needed(1300, &quote);
    unsigned int before = confirmations;
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == 0 && confirmations == before);
    outer = frag_needed(0, &quote); /* RFC 1191 plateau fallback: 1006 < quoted 1328 */
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == 1);
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1006);
    quote_bytes[6] = 0; /* DF evidence is mandatory */
    outer = frag_needed(900, &quote);
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == -EINVAL);
    quote_bytes[6] = 0x40;
    memcpy(quote_bytes + 16, &local_ip, 4);
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == -EACCES);
    memcpy(quote_bytes + 16, &peer_ip, 4);
    CHECK(ker_icmpv4_quoted_ipv4_view_init(quote_bytes, sizeof(quote_bytes), &quote) == 0);
    now_ms += 1000;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1500);
    CHECK(output(&skb) == 0 && !skb);
    CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
    ker_packet_free(sent_packet); sent_packet = NULL;
    outer = frag_needed(68, &quote);
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == 1);
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 68);
    now_ms += 1000;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &mtu) == 0 && mtu == 1500);
    now_ms = UINT64_MAX - 500;
    outer = frag_needed(1200, &quote);
    unsigned int before_overflow = confirmations;
    CHECK(ker_icmpv4_pmtu_apply(&pmtu, &outer, &quote) == -ERANGE &&
        confirmations == before_overflow + 1);
    unchanged_mtu = 777;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &unchanged_mtu) == 0 && unchanged_mtu == 1500);
    now_ms = 1100;
    unchanged_mtu = 777;
    CHECK(ker_icmpv4_pmtu_current_mtu(&pmtu, &unchanged_mtu) == -ERANGE && unchanged_mtu == 777);
    CHECK(ker_icmpv4_service_disable(&service) == 0);
    CHECK(ker_transport_receiver_unregister(&receiver) == 0);
    CHECK(ker_receive_runtime_cleanup(&receive_runtime) == 0);
    CHECK(ker_neighbor_monitor_resolution_disable(&monitor) == 0);
    CHECK(ker_icmpv4_pmtu_cleanup(&pmtu) == 0);
    CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
    CHECK(ker_neighbor_remove(&table, peer_ip) == 0);
    CHECK(ker_tx_export_cleanup(&tx) == 0);
    CHECK(ker_neighbor_table_cleanup(&table) == 0);
    CHECK(ker_ipv4_address_cleanup(&address) == 0);
    CHECK(ker_eth_device_cleanup(&device) == 0);
    CHECK(ker_skb_context_cleanup(&context) == 0);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
    return 0;
}
