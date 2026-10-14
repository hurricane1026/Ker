#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/icmpv4-create.h"
#include "runtime/icmpv4-service.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include "runtime/neighbor.h"
#include "runtime/neighbor-timer.h"
#include "runtime/receive.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/udp-endpoint.h"
#include "runtime/udp-error.h"
#include "runtime/udp-io.h"
#include <errno.h>
#include <limits.h>
#include <net/checksum.h>

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table table;
static struct ker_runtime timer_runtime;
static struct ker_neighbor_monitor monitor;
static struct ker_neighbor_monitor second_monitor;
static struct ker_tx_export tx;
static struct ker_receive_runtime receive_runtime;
static struct ker_transport_receiver receiver;
static struct ker_icmpv4_service service;
static struct ker_udp_endpoint_table endpoints;
static struct ker_udp_endpoint endpoint_slots[2];
static struct ker_udp_error_tracker errors;
static struct ker_udp_error_record records[8];
static struct ker_udp_error_peer peers[2];
static struct ker_udp_error_event queue_events[2];
static struct ker_udp_io io;
static struct ker_udp_io_peer io_peers[2];
static struct ker_udp_io idle_io;
static struct ker_udp_io_peer idle_io_peers[1];
static struct ker_udp_channel channel;
static struct ker_udp_channel_slot channel_slots[2];
static unsigned char channel_payloads[2 * 64];
static struct rte_mbuf *sent_packet;
static uint64_t now_ms = 100;
static bool reject_once = true;
static bool rollback_once, trigger_clock_reentry;
static bool trigger_tx_reentry, tx_reentry_polling;
static int clock_tx_result;
static unsigned int skip_clock_reentry;
static unsigned int clock_step_countdown;
static uint64_t clock_step_target;
static struct ker_udp_endpoint_handle active_handle;
static int clock_reentry_tracker, clock_reentry_endpoint,
    clock_reentry_service, clock_reentry_init, clock_reentry_pmtu,
    clock_reentry_observer;
static unsigned int legacy_events;
static const unsigned char local_mac[6] = {2, 0, 0, 0, 0, 1};
static const unsigned char peer_mac[6] = {2, 0, 0, 0, 0, 2};
static const unsigned char router_mac[6] = {2, 0, 0, 0, 0, 9};
static __be32 local_ip, peer_ip, router_ip;
static __be32 second_peer_ip;

static uint64_t clock_ms(void *arg)
{
  (void)arg;
  if (trigger_clock_reentry && skip_clock_reentry) {
    --skip_clock_reentry;
    return now_ms;
  }
  if (trigger_clock_reentry) {
    trigger_clock_reentry = false;
    clock_reentry_tracker = ker_udp_error_tracker_cleanup(&errors);
    clock_reentry_endpoint = ker_udp_endpoint_close(&endpoints, active_handle);
    clock_reentry_service = ker_icmpv4_service_disable(&service);
    clock_reentry_init = ker_udp_error_tracker_init(&errors, &service,
        &endpoints, records, 8, peers, 2, 2, clock_ms, NULL, 1000);
    if (peers[0].tracker == &errors) {
      clock_reentry_pmtu = ker_icmpv4_pmtu_cleanup(&peers[0].pmtu);
      clock_reentry_observer = ker_tx_export_observer_detach(&tx,
          &peers[0].tx_observer);
    }
  }
  if (trigger_tx_reentry) {
    trigger_tx_reentry = false;
    tx_reentry_polling = true;
    clock_tx_result = ker_tx_export_poll(&tx, 2);
    tx_reentry_polling = false;
  }
  if (clock_step_countdown && --clock_step_countdown == 0)
    now_ms = clock_step_target;
  return now_ms;
}
static int fallback(const struct ker_transport_message *m, void *arg)
{ (void)m; (void)arg; return NET_RX_SUCCESS; }
static void legacy_event(const struct ker_icmpv4_control_event *event, void *arg)
{ (void)arg; CHECK(event->has_quote); ++legacy_events; }
static void probe_noop(const struct ker_neighbor_event *event, void *arg)
{ (void)event; (void)arg; }
static int sink(struct rte_mbuf *packet, void *arg)
{
  (void)arg;
  if (tx_reentry_polling) {
    ker_packet_free(packet);
    return 0;
  }
  if (reject_once) { reject_once = false; return -EAGAIN; }
  CHECK(!sent_packet);
  sent_packet = packet;
  if (rollback_once) {
    rollback_once = false;
    --now_ms;
  }
  return 0;
}

static void dispatch_error(const unsigned char *quote, size_t quote_length,
                           uint8_t type, uint8_t code, uint16_t mtu)
{
  unsigned char rest[4] = {0};
  if (type == 3 && code == 4) {
    rest[2] = (unsigned char)(mtu >> 8);
    rest[3] = (unsigned char)mtu;
  }
  unsigned char padded_quote[28];
  const unsigned char *quoted = quote;
  size_t create_length = quote_length;
  if (quote_length < sizeof(padded_quote)) {
    memcpy(padded_quote, quote, quote_length);
    memset(padded_quote + quote_length, 0, sizeof(padded_quote) - quote_length);
    quoted = padded_quote;
    create_length = sizeof(padded_quote);
  }
  struct sk_buff *incoming = NULL;
  CHECK(ker_icmpv4_ipv4_create(&context, router_mac, local_mac, router_ip,
      local_ip, type, code, rest, 64, quoted, create_length, &incoming) == 0);
  if (quote_length < create_length) {
    CHECK(ker_skb_trim(incoming, ETH_HLEN + 20 + 8 + quote_length) == 0);
    unsigned char *ip = incoming->data + ETH_HLEN;
    ip[2] = (unsigned char)((20 + 8 + quote_length) >> 8);
    ip[3] = (unsigned char)(20 + 8 + quote_length);
    ip[10] = ip[11] = 0;
    __sum16 ip_sum = csum_fold(csum_partial(ip, 20, 0));
    memcpy(ip + 10, &ip_sum, sizeof(ip_sum));
    unsigned char *icmp = ip + 20;
    icmp[2] = icmp[3] = 0;
    __sum16 icmp_sum = csum_fold(csum_partial(icmp,
        (int)(8 + quote_length), 0));
    memcpy(icmp + 2, &icmp_sum, sizeof(icmp_sum));
  }
  struct rte_mbuf *wire = NULL;
  CHECK(ker_skb_to_mbuf(incoming, &wire) == 0);
  CHECK(ker_skb_free(incoming) == 0);
  incoming = NULL;
  CHECK(ker_eth_receive(&device, wire, &incoming) == 0 && incoming);
  struct ker_receive_result result;
  CHECK(ker_receive_dispatch(&receive_runtime, &device, &incoming, &result) == 0);
  CHECK(!incoming);
  if (quote_length >= 28)
    CHECK(result.handlers == 1 && result.status == NET_RX_SUCCESS);
  else
    CHECK(result.handlers == 1 && result.status == NET_RX_DROP);
}

static void fix_ip_checksum(unsigned char *quote)
{
  quote[10] = quote[11] = 0;
  __sum16 checksum = csum_fold(csum_partial(quote, 20, 0));
  memcpy(quote + 10, &checksum, sizeof(checksum));
}

int main(void)
{
  ker_test_eal_init();
  local_ip = rte_cpu_to_be_32(0xc0000201U);
  peer_ip = rte_cpu_to_be_32(0xc0000202U);
  second_peer_ip = rte_cpu_to_be_32(0xc0000203U);
  router_ip = rte_cpu_to_be_32(0xc0000209U);
  CHECK(ker_memory_init(SOCKET_ID_ANY, 64) == 0);
  CHECK(ker_packet_pool_init(&pool, "udp_error_packets", 63, 0, 2048,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&context, &pool, "udp_error_skbs") == 0);
  CHECK(ker_eth_device_init(&device, &context, "udp_error_eth", 1,
                            local_mac) == 0);
  device.native->mtu = 1500;
  CHECK(ker_arp_device_setup(&device) == 0);
  CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
  CHECK(ker_neighbor_table_init(&table, &address, "udp_error_neighbors", 2,
                                1) == 0);
  struct ker_neighbor_config config = {.retrans_ticks=20,
      .reachable_ticks=100, .delay_ticks=30, .ucast_probes=2,
      .mcast_probes=2, .mcast_reprobes=1, .queue_bytes=8192};
  CHECK(ker_neighbor_configure(&table, &config) == 0);
  CHECK(ker_neighbor_add(&table, peer_ip, peer_mac) == 0);
  ker_runtime_init(&timer_runtime);
  CHECK(ker_neighbor_monitor_init(&monitor, &table, &timer_runtime, peer_ip,
      probe_noop, NULL, NULL) == 0);
  CHECK(ker_tx_export_init(&tx, &context, 8, SIZE_MAX, sink, NULL) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&monitor, &tx) == 0);
  CHECK(ker_receive_runtime_init(&receive_runtime, &context) == 0);
  CHECK(ker_transport_receiver_register(&receiver, &receive_runtime, &device,
      fallback, NULL) == 0);
  struct ker_icmpv4_service_config service_config = {.ttl=64, .burst=4,
      .refill_ms=100, .monotonic_ms=clock_ms, .event=legacy_event};
  CHECK(ker_icmpv4_service_enable(&service, &receiver, &monitor,
                                  &service_config) == 0);
  CHECK(ker_udp_endpoint_table_enable(&endpoints, &receiver, &service,
      endpoint_slots, 2) == 0);
  struct ker_udp_endpoint_handle handle;
  __be16 local_port = rte_cpu_to_be_16(1234);
  __be16 peer_port = rte_cpu_to_be_16(4321);
  CHECK(ker_udp_endpoint_bind_ex(&endpoints, rte_cpu_to_be_16(1233),
      fallback, NULL, &active_handle) == 0);
  trigger_clock_reentry = true;
  CHECK(ker_udp_error_tracker_init(&errors, &service, &endpoints, records,
      8, peers, 2, 2, clock_ms, NULL, 1000) == 0);
  CHECK(clock_reentry_tracker == -EBUSY && clock_reentry_endpoint == -EBUSY &&
        clock_reentry_service == -EBUSY && clock_reentry_init == -EBUSY);
  CHECK(ker_udp_endpoint_close(&endpoints, active_handle) == 0);
  CHECK(ker_udp_io_init(&io, &receiver, &service, &endpoints, io_peers, 2,
                        64) == 0);
  CHECK(ker_udp_io_attach_error_tracker(&io, &errors) == 0);
  CHECK(ker_udp_io_init(&idle_io, &receiver, &service, &endpoints,
      idle_io_peers, 1, 64) == 0);
  CHECK(ker_udp_io_attach_error_tracker(&idle_io, &errors) == 0);
  CHECK(errors.io_refs == 2);
  CHECK(ker_udp_error_tracker_cleanup(&errors) == -EBUSY);
  CHECK(ker_udp_io_register_peer(&io, &monitor) == 0);
  unsigned int monitor_adapter_refs = monitor.udp_adapter_refs;
  monitor.udp_adapter_refs = UINT_MAX;
  CHECK(ker_udp_io_register_peer(&idle_io, &monitor) == -EOVERFLOW);
  CHECK(idle_io.peer_count == 0 && errors.peers[0].registration_refs == 1);
  monitor.udp_adapter_refs = monitor_adapter_refs;
  errors.peers[0].registration_refs = UINT_MAX;
  CHECK(ker_udp_io_register_peer(&idle_io, &monitor) == -EOVERFLOW);
  CHECK(idle_io.peer_count == 0 && errors.peers[0].registration_refs == UINT_MAX &&
        monitor.udp_adapter_refs == monitor_adapter_refs);
  errors.peers[0].registration_refs = 1;
  CHECK(ker_udp_io_register_peer(&idle_io, &monitor) == 0);
  CHECK(errors.peers[0].registration_refs == 2 &&
        monitor.udp_adapter_refs == monitor_adapter_refs + 1);
  CHECK(ker_neighbor_monitor_resolution_disable(&monitor) == -EBUSY);
  CHECK(ker_neighbor_add(&table, second_peer_ip, peer_mac) == 0);
  CHECK(ker_neighbor_monitor_init(&second_monitor, &table, &timer_runtime,
      second_peer_ip, probe_noop, NULL, NULL) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&second_monitor, &tx) == 0);
  second_monitor.udp_adapter_refs = UINT_MAX - 1;
  CHECK(ker_udp_io_register_peer(&io, &second_monitor) == -EOVERFLOW);
  CHECK(second_monitor.udp_adapter_refs == UINT_MAX - 1 &&
        errors.peer_count == 1 && io.peer_count == 1);
  second_monitor.udp_adapter_refs = 0;
  CHECK(ker_udp_io_register_peer(&io, &second_monitor) == 0);
  CHECK(ker_udp_channel_open(&channel, &io, local_port, channel_slots,
      channel_payloads, 2, 64, sizeof(channel_payloads), &handle) == 0);
  active_handle = handle;
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, peer_ip, peer_port) == 0);
  CHECK(ker_udp_channel_attach_errors(&channel, queue_events, 2) == 0);
  CHECK(ker_udp_io_detach_error_tracker(&io) == -EBUSY);
  CHECK(ker_udp_io_unregister_peer(&idle_io, &monitor) == 0 &&
        errors.peers[0].registration_refs == 1 &&
        monitor.udp_adapter_refs == monitor_adapter_refs &&
        errors.peers[0].pmtu.attached &&
        errors.peers[0].tx_observer.attached);
  CHECK(ker_udp_io_detach_error_tracker(&idle_io) == 0 && errors.io_refs == 1 &&
        errors.peer_count == 2 && errors.queue_count == 1);
  CHECK(ker_udp_io_detach_error_tracker(&idle_io) == -ENOENT);
  CHECK(ker_udp_io_cleanup(&idle_io) == 0);

  unsigned char payload[16] = {0};
  const unsigned char *wire = NULL;
  trigger_clock_reentry = true;
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(clock_reentry_tracker == -EBUSY && clock_reentry_endpoint == -EBUSY &&
        clock_reentry_service == -EBUSY && clock_reentry_init == -EBUSY &&
        clock_reentry_pmtu == -EBUSY && clock_reentry_observer == -EBUSY &&
        peers[0].pmtu.attached && peers[0].tx_observer.attached);
  CHECK(ker_tx_export_poll(&tx, 1) == -EAGAIN && !sent_packet);
  CHECK(records[0].state == KER_UDP_ERROR_RESERVED);
  unsigned char quote[28];
  memcpy(quote, tx.pending->data + ETH_HLEN, sizeof(quote));
  trigger_tx_reentry = true;
  dispatch_error(quote, sizeof(quote), 3, 3, 0);
  struct ker_udp_error_event event;
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 0 &&
        legacy_events == 1 && records[0].state == KER_UDP_ERROR_SENT &&
        clock_tx_result == 1);
  dispatch_error(quote, sizeof(quote), 3, 3, 0);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 1 &&
        event.error == ECONNREFUSED);
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  trigger_tx_reentry = true;
  struct ker_udp_error_token reentry_token = {0};
  CHECK(ker_udp_error_reserve(&errors, channel.endpoint, &monitor, local_ip,
      local_port, peer_ip, peer_port, sizeof(payload), &reentry_token) == 0);
  CHECK(ker_udp_error_cancel(&errors, reentry_token) == 0);
  CHECK(clock_tx_result == 2 && records[0].state == KER_UDP_ERROR_TOMBSTONE &&
        records[1].state == KER_UDP_ERROR_SENT &&
        !records[1].accepted_pending && !records[1].skb &&
        !records[1].skb_identity && records[2].state == KER_UDP_ERROR_SENT &&
        !records[2].accepted_pending && !records[2].skb &&
        !records[2].skb_identity);

  unsigned char altered[28];
  memcpy(altered, quote, sizeof(altered));
  altered[20] ^= 1;
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[4] ^= 1;
  fix_ip_checksum(altered);
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[2] ^= 1;
  fix_ip_checksum(altered);
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[24] ^= 1;
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[26] ^= 1;
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[6] = altered[7] = 0;
  fix_ip_checksum(altered);
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  memcpy(altered, quote, sizeof(altered));
  altered[10] ^= 1;
  dispatch_error(altered, sizeof(altered), 3, 3, 0);
  dispatch_error(quote, sizeof(quote) - 1, 3, 3, 0);
  CHECK(channel.error_queue.count == 0);
  CHECK(event.error == ECONNREFUSED && event.type == 3 && event.code == 3 &&
      event.local_address == local_ip && event.peer_address == peer_ip &&
      event.reporter_address == router_ip && event.local_port == local_port &&
      event.peer_port == peer_port && event.incarnation != 0);
  CHECK(records[0].state == KER_UDP_ERROR_TOMBSTONE && !records[0].monitor &&
        !records[0].endpoint.table);
  __be16 consumed_id = records[0].identification;
  errors.next_identification = ntohs(consumed_id);
  struct ker_udp_error_token reuse_token = {0};
  CHECK(ker_udp_error_reserve(&errors, channel.endpoint, &monitor, local_ip,
      local_port, peer_ip, peer_port, sizeof(payload), &reuse_token) == 0);
  CHECK(reuse_token.identification != consumed_id);
  CHECK(ker_udp_error_cancel(&errors, reuse_token) == 0);

  /* Recycled descriptor addresses cannot claim a dropped reservation. */
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  struct sk_buff *tracked = NULL, *spoof = NULL;
  CHECK(ker_tx_export_cancel(&tx, &tracked) == 1 && tracked);
  uint64_t tracked_identity = ker_skb_identity(tracked);
  struct rte_mbuf *duplicate = NULL;
  CHECK(ker_skb_to_mbuf(tracked, &duplicate) == 0 && duplicate);
  struct ker_udp_error_record *tracked_record = NULL;
  for (size_t i = 0; i < 8; ++i)
    if (records[i].state == KER_UDP_ERROR_RESERVED && records[i].skb == tracked &&
        records[i].skb_identity == tracked_identity)
      tracked_record = &records[i];
  CHECK(tracked_record);
  CHECK(ker_skb_free(tracked) == 0);
  tracked = NULL;
  CHECK(ker_skb_copy_from_mbuf_chain(&context, duplicate, 0, &spoof) == 0 && spoof);
  for (unsigned int i = 0; spoof != tracked_record->skb && i < 64; ++i) {
    CHECK(ker_skb_free(spoof) == 0);
    spoof = NULL;
    CHECK(ker_skb_copy_from_mbuf_chain(&context, duplicate, 0, &spoof) == 0 && spoof);
  }
  ker_packet_free(duplicate);
  CHECK(spoof == tracked_record->skb &&
        ker_skb_identity(spoof) != tracked_record->skb_identity);
  CHECK(ker_tx_export_enqueue(&tx, &spoof) == 0 && !spoof);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  CHECK(tracked_record->state == KER_UDP_ERROR_RESERVED &&
        !tracked_record->accepted_pending);
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  CHECK(ker_udp_error_resync(&errors) == 0);

  /* An accepted packet from a stale endpoint incarnation retains its ID. */
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  struct ker_udp_error_record *stale_accepted = NULL;
  for (size_t i = 0; i < 8; ++i)
    if (records[i].state == KER_UDP_ERROR_RESERVED && records[i].skb)
      stale_accepted = &records[i];
  CHECK(stale_accepted);
  __be16 stale_accepted_id = stale_accepted->identification;
  CHECK(ker_udp_endpoint_disconnect(&endpoints, handle) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, peer_ip, peer_port) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  CHECK(stale_accepted->state == KER_UDP_ERROR_TOMBSTONE &&
        stale_accepted->identification == stale_accepted_id && !stale_accepted->monitor &&
        !stale_accepted->endpoint.table && !stale_accepted->skb);
  uint64_t stale_expiry = stale_accepted->expires_ms;
  CHECK(stale_expiry == now_ms + errors.lifetime_ms);
  errors.next_identification = ntohs(stale_accepted_id);
  struct ker_udp_error_token stale_reuse = {0};
  CHECK(ker_udp_error_reserve(&errors, channel.endpoint, &monitor, local_ip,
      local_port, peer_ip, peer_port, sizeof(payload), &stale_reuse) == 0);
  CHECK(stale_reuse.identification != stale_accepted_id);
  CHECK(ker_udp_error_cancel(&errors, stale_reuse) == 0);
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  CHECK(ker_udp_error_resync(&errors) == 0);

  /* Events already queued for an old connection incarnation are discarded. */
  CHECK(ker_udp_sendto(&channel, peer_ip, rte_cpu_to_be_16(4322), payload,
                       sizeof(payload)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  dispatch_error(quote, sizeof(quote), 3, 3, 0);
  CHECK(channel.error_queue.count == 1);
  CHECK(channel.error_queue.events[channel.error_queue.head].peer_port ==
        rte_cpu_to_be_16(4322));
  CHECK(ker_udp_endpoint_disconnect(&endpoints, handle) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, peer_ip,
      rte_cpu_to_be_16(4322)) == 0);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 0 &&
        channel.error_queue.count == 0);

  /* A registered peer other than the ICMP service's control peer is matched
   * by its exact sent quote before legacy peer filtering. */
  unsigned int before_peer_two_legacy = legacy_events;
  CHECK(ker_udp_sendto(&channel, second_peer_ip, rte_cpu_to_be_16(9000),
                       payload, sizeof(payload)) == 0);
  trigger_clock_reentry = true;
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  CHECK(clock_reentry_tracker == -EBUSY && clock_reentry_endpoint == -EBUSY &&
        clock_reentry_service == -EBUSY && clock_reentry_init == -EBUSY &&
        clock_reentry_pmtu == -EBUSY && clock_reentry_observer == -EBUSY);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  dispatch_error(quote, sizeof(quote), 3, 1, 0);
  CHECK(legacy_events == before_peer_two_legacy);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 1 &&
        event.error == EHOSTUNREACH && event.peer_address == second_peer_ip &&
        event.peer_port == rte_cpu_to_be_16(9000));

  unsigned char jumbo[1300] = {0};
  CHECK(ker_udp_send(&channel, jumbo, sizeof(jumbo)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  trigger_clock_reentry = true;
  skip_clock_reentry = 1; /* Skip tracker read_now; enter PMTU error_clock. */
  dispatch_error(quote, sizeof(quote), 3, 4, 1200);
  CHECK(!trigger_clock_reentry && !skip_clock_reentry);
  CHECK(clock_reentry_tracker == -EBUSY && clock_reentry_endpoint == -EBUSY &&
        clock_reentry_service == -EBUSY && clock_reentry_init == -EBUSY &&
        clock_reentry_pmtu == -EBUSY && clock_reentry_observer == -EBUSY);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 1);
  CHECK(event.error == EMSGSIZE && event.pmtu_status == 1 &&
        event.next_hop_mtu == 1200);

  /* The PMTU helper samples its clock after observe_control's initial read.
   * Evidence expiring on that second sample cannot install PMTU or enqueue. */
  unsigned char near_mtu[1100] = {0};
  CHECK(ker_udp_send(&channel, near_mtu, sizeof(near_mtu)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  __be16 expiring_id;
  memcpy(&expiring_id, quote + 4, sizeof(expiring_id));
  struct ker_udp_error_record *expiring = NULL;
  for (size_t i = 0; i < 8; ++i)
    if (records[i].state == KER_UDP_ERROR_SENT &&
        records[i].identification == expiring_id)
      expiring = &records[i];
  CHECK(expiring);
  uint64_t expiry = expiring->expires_ms;
  uint32_t pmtu_before_expiry = peers[0].pmtu.current_mtu;
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  now_ms = expiry - 1;
  clock_step_target = expiry;
  clock_step_countdown = 2;
  dispatch_error(quote, sizeof(quote), 3, 4, 1000);
  CHECK(!clock_step_countdown);
  CHECK(now_ms == expiry);
  CHECK(expiring->state == KER_UDP_ERROR_TOMBSTONE);
  CHECK(channel.error_queue.count == 0);
  /* Refresh may restore the old cache at its own expiry, but this report's
   * 1000-byte candidate must not be installed from expired evidence. */
  CHECK(peers[0].pmtu.current_mtu != 1000 &&
        (peers[0].pmtu.current_mtu == pmtu_before_expiry ||
         peers[0].pmtu.current_mtu == peers[0].pmtu.initial_mtu));
  CHECK(ker_udp_send(&channel, jumbo, sizeof(jumbo)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  now_ms += 1000;
  CHECK(ker_udp_send(&channel, jumbo, sizeof(jumbo)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  ker_packet_free(sent_packet);
  sent_packet = NULL;

  /* A zero-MTU type 3/code 4 report selects the RFC legacy plateau and
   * publishes the effective value while retaining the successful apply
   * status. The MTU-derived UDP payload boundary is 1006 - IPv4/UDP 28. */
  CHECK(ker_udp_send(&channel, jumbo, sizeof(jumbo)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  dispatch_error(quote, sizeof(quote), 3, 4, 0);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 1);
  CHECK(event.error == EMSGSIZE && event.pmtu_status == 1 &&
        event.next_hop_mtu == 1006);
  unsigned char plateau_over[979] = {0};
  unsigned char plateau_fit[978] = {0};
  CHECK(ker_udp_send(&channel, plateau_over, sizeof(plateau_over)) ==
        -EMSGSIZE);
  CHECK(ker_udp_send(&channel, plateau_fit, sizeof(plateau_fit)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  ker_packet_free(sent_packet);
  sent_packet = NULL;

  /* The per-channel queue drops excess errors without growing its storage. */
  unsigned char overflow_quotes[3][28];
  for (size_t i = 0; i < 3; ++i) {
    CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
    CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
    wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
    memcpy(overflow_quotes[i], wire + ETH_HLEN, sizeof(overflow_quotes[i]));
    ker_packet_free(sent_packet);
    sent_packet = NULL;
  }
  CHECK(memcmp(overflow_quotes[0] + 4, overflow_quotes[1] + 4, 2) != 0 &&
        memcmp(overflow_quotes[0] + 4, overflow_quotes[2] + 4, 2) != 0 &&
        memcmp(overflow_quotes[1] + 4, overflow_quotes[2] + 4, 2) != 0);
  for (size_t i = 0; i < 3; ++i)
    dispatch_error(overflow_quotes[i], sizeof(overflow_quotes[i]), 3, 0, 0);
  CHECK(channel.error_queue.count == 2 && channel.error_queue.dropped == 1);
  CHECK(ker_udp_endpoint_disconnect(&endpoints, handle) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, peer_ip, peer_port) == 0);
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  dispatch_error(quote, sizeof(quote), 3, 3, 0);
  CHECK(channel.error_queue.count == 1 && channel.error_queue.dropped == 1);
  CHECK(ker_udp_channel_recv_error(&channel, &event) == 1 &&
        event.error == ECONNREFUSED && event.peer_port == peer_port &&
        channel.error_queue.count == 0 && channel.error_queue.dropped == 1);

  /* Reservations are not evicted while queued for output; resync releases
   * them only after the TX exporter has been drained. */
  now_ms += 1001;
  errors.next_identification = ntohs(consumed_id);
  reuse_token = (struct ker_udp_error_token){0};
  CHECK(ker_udp_error_reserve(&errors, channel.endpoint, &monitor, local_ip,
      local_port, peer_ip, peer_port, sizeof(payload), &reuse_token) == 0);
  CHECK(reuse_token.identification == consumed_id);
  CHECK(ker_udp_error_cancel(&errors, reuse_token) == 0);
  for (size_t i = 0; i < 8; ++i)
    CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == -ENOSPC);
  for (size_t i = 0; i < 8; ++i) {
    struct sk_buff *cancelled = NULL;
    CHECK(ker_tx_export_cancel(&tx, &cancelled) == 1 && cancelled);
    CHECK(ker_skb_free(cancelled) == 0);
  }
  CHECK(ker_udp_error_resync(&errors) == 0);
  for (size_t i = 0; i < 8; ++i)
    CHECK(records[i].state == KER_UDP_ERROR_FREE);

  /* A synchronous TX-admission error must cancel its reservation even if
   * native output consumes the skb while returning ENOSPC. */
  for (size_t i = 0; i < 8; ++i) {
    struct ker_ipv4_header_fields fields = {
        .identification = htons((uint16_t)(i + 100)),
        .frag_off = htons(0x4000)};
    struct sk_buff *untracked = NULL;
    CHECK(ker_udp_ipv4_create_fields(&context, local_mac, peer_mac, local_ip,
        peer_ip, local_port, peer_port, 64, &fields, NULL, 0, payload,
        sizeof(payload), &untracked) == 0);
    CHECK(ker_tx_export_enqueue(&tx, &untracked) == 0 && !untracked);
  }
  monitor.resolution_error = 0;
  int immediate_error = ker_udp_send(&channel, payload, sizeof(payload));
  CHECK(immediate_error < 0);
  CHECK(monitor.resolution_error == -ENOSPC && tx.packets == 8);
  for (size_t i = 0; i < 8; ++i)
    CHECK(records[i].state == KER_UDP_ERROR_FREE);
  for (size_t i = 0; i < 8; ++i) {
    struct sk_buff *untracked = NULL;
    CHECK(ker_tx_export_cancel(&tx, &untracked) == 1 && untracked);
    CHECK(ker_skb_free(untracked) == 0);
  }

  /* The sink acceptance clock is checked too; rollback discards evidence. */
  rollback_once = true;
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  size_t rollback_slot = 0;
  while (rollback_slot < 8 && records[rollback_slot].state == KER_UDP_ERROR_FREE)
    ++rollback_slot;
  CHECK(rollback_slot < 8);
  uint64_t before_rollback = now_ms;
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  CHECK(records[rollback_slot].state == KER_UDP_ERROR_TOMBSTONE &&
        records[rollback_slot].expires_ms >= before_rollback);
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  now_ms = before_rollback;

  /* Expiry arithmetic overflow also fails closed after sink acceptance. */
  now_ms = UINT64_MAX - 500;
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  size_t overflow_slot = 0;
  while (overflow_slot < 8 && records[overflow_slot].state == KER_UDP_ERROR_FREE)
    ++overflow_slot;
  CHECK(overflow_slot < 8);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  CHECK(records[overflow_slot].state == KER_UDP_ERROR_TOMBSTONE &&
        records[overflow_slot].expires_ms == UINT64_MAX &&
        records[overflow_slot].expiry_saturated);
  ker_packet_free(sent_packet);
  sent_packet = NULL;

  /* A delayed quote from a sent packet cannot target a new slot generation
   * after close and rebind, even when its ledger lifetime has not elapsed. */
  errors.lifetime_ms = 100;
  now_ms = UINT64_MAX - 500;
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  wire = rte_pktmbuf_mtod(sent_packet, const unsigned char *);
  memcpy(quote, wire + ETH_HLEN, sizeof(quote));
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  struct ker_udp_endpoint_handle old_handle = channel.endpoint;
  CHECK(ker_udp_channel_close(&channel) == 0);
  CHECK(ker_udp_channel_open(&channel, &io, local_port, channel_slots,
      channel_payloads, 2, 64, sizeof(channel_payloads), &handle) == 0);
  CHECK(handle.generation != old_handle.generation);
  CHECK(ker_udp_channel_attach_errors(&channel, queue_events, 2) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, peer_ip, peer_port) == 0);
  dispatch_error(quote, sizeof(quote), 3, 3, 0);
  CHECK(channel.error_queue.count == 0);
  CHECK(ker_udp_error_recv(&errors, old_handle, &event) == -ESTALE);
  CHECK(ker_udp_send(&channel, payload, sizeof(payload)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && sent_packet);
  struct ker_udp_error_record *stale_record = NULL;
  for (size_t i = 0; i < 8; ++i)
    if (records[i].state == KER_UDP_ERROR_SENT &&
        records[i].endpoint.generation == channel.endpoint.generation)
      stale_record = &records[i];
  CHECK(stale_record);
  __be16 stale_id = stale_record->identification;
  ker_packet_free(sent_packet);
  sent_packet = NULL;
  CHECK(ker_udp_channel_close(&channel) == 0);
  CHECK(ker_udp_io_unregister_peer(&io, &monitor) == 0);
  CHECK(monitor.udp_adapter_refs == 0);
  CHECK(stale_record->state == KER_UDP_ERROR_TOMBSTONE &&
        stale_record->identification == stale_id && !stale_record->monitor &&
        !stale_record->endpoint.table);

  CHECK(ker_udp_io_unregister_peer(&io, &second_monitor) == 0);
  CHECK(ker_udp_io_detach_error_tracker(&io) == 0);
  CHECK(ker_udp_error_tracker_cleanup(&errors) == -EBUSY);
  CHECK(stale_record->state == KER_UDP_ERROR_TOMBSTONE);
  now_ms = UINT64_MAX;
  /* An exact UINT64_MAX expiry is still expirable; overflow saturation is
   * explicitly sticky and keeps cleanup blocked. */
  stale_record->expires_ms = UINT64_MAX;
  stale_record->expiry_saturated = false;
  CHECK(ker_udp_error_tracker_cleanup(&errors) == -EBUSY);
  CHECK(stale_record->state == KER_UDP_ERROR_FREE);
  CHECK(records[overflow_slot].state == KER_UDP_ERROR_TOMBSTONE &&
        records[overflow_slot].expiry_saturated);
  /* This direct reset is test-fixture cleanup after proving fail-closed
   * behavior; production has no API to clear a saturated anti-replay ID. */
  records[overflow_slot] = (struct ker_udp_error_record){0};
  CHECK(ker_udp_error_tracker_cleanup(&errors) == 0);
  CHECK(ker_udp_io_cleanup(&io) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&service) == 0);
  CHECK(ker_transport_receiver_unregister(&receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&receive_runtime) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&monitor) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&monitor) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&second_monitor) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&second_monitor) == 0);
  CHECK(ker_neighbor_remove(&table, peer_ip) == 0);
  CHECK(ker_neighbor_remove(&table, second_peer_ip) == 0);
  CHECK(ker_tx_export_cleanup(&tx) == 0);
  CHECK(ker_neighbor_table_cleanup(&table) == 0);
  CHECK(ker_ipv4_address_cleanup(&address) == 0);
  CHECK(ker_eth_device_cleanup(&device) == 0);
  CHECK(ker_skb_context_cleanup(&context) == 0);
  CHECK(rte_mempool_avail_count(pool.mbufs) == 63);
  CHECK(ker_packet_pool_cleanup(&pool) == 0);
  CHECK(ker_memory_shutdown() == 0);
  CHECK(rte_eal_cleanup() == 0);
  return 0;
}
