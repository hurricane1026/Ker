#include "runtime/icmpv4-service.h"
#include "check.h"
#include "eal.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/arp-receive.h"
#include "runtime/arp-responder.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/icmp-echo-create.h"
#include "runtime/icmpv4-create.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/neighbor.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if.h>
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
static struct ker_icmpv4_service service;
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
static unsigned int replies_seen, fallback_seen, udp_seen, tcp_seen,
    arp_feedback;
static uint64_t fake_now = 1000;
static uint32_t fake_utc = 123456;
static int fake_utc_status;
static bool reentry_check;
static struct sk_buff *reentry_packet;
static int reentry_disable_result, reentry_emit_result;
static void check_reentry(void) {
  if (!reentry_check)
    return;
  CHECK(service.monitor->busy);
  reentry_disable_result = ker_icmpv4_service_disable(&service);
  reentry_emit_result =
      ker_icmpv4_service_emit_error(&service, reentry_packet, 3, 3, 0);
  CHECK(service.monitor->busy);
}
static __be32 router_ip;
static unsigned int control_events;
static unsigned int emitted_errors;
static uint8_t expected_probe_code;
static uint8_t expected_emitted_type = 3, expected_emitted_code = 3;
static uint16_t expected_emitted_mtu;
static uint8_t expected_emitted_pointer;
static uint8_t expected_control_type = 3, expected_control_code = 3,
               expected_pointer;
static uint16_t expected_mtu;
static __be32 expected_gateway;
static uint64_t monotonic_ms(void *arg) {
  (void)arg;
  check_reentry();
  return fake_now;
}
static int utc_ms(void *arg, uint32_t *out) {
  (void)arg;
  check_reentry();
  *out = fake_utc;
  return fake_utc_status;
}
static void control_event(const struct ker_icmpv4_control_event *event,
                          void *arg) {
  (void)arg;
  CHECK(event->type == expected_control_type &&
        event->code == expected_control_code && event->source == router_ip &&
        event->destination == bip);
  CHECK(event->next_hop_mtu == expected_mtu &&
        event->pointer == expected_pointer &&
        event->gateway == expected_gateway);
  CHECK(event->has_quote && event->quote.flow_available &&
        event->quote.protocol == 17);
  CHECK(!memcmp(event->quote.header + 12, &bip, 4) &&
        !memcmp(event->quote.header + 16, &aip, 4));
  CHECK(event->message.quoted_ipv4 == event->quote.header);
  ++control_events;
}
static struct ker_icmpv4_service_config service_config = {
    .ttl = 37,
    .echo_enabled = true,
    .timestamp_enabled = true,
    .probe_enabled = true,
    .burst = 32,
    .refill_ms = 100,
    .monotonic_ms = monotonic_ms,
    .utc_ms = utc_ms,
    .event = control_event,
};

static int ring_sink(struct rte_mbuf *packet, void *arg) {
  return ker_tx_ring_sink(packet, arg);
}
static int receive_echo(const struct ker_transport_message *message,
                        void *arg) {
  (void)arg;
  CHECK(message->protocol == KER_TRANSPORT_ICMP_ECHO);
  if (message->icmpv4.type == 3 || message->icmpv4.type == 11 ||
      message->icmpv4.type == 12) {
    CHECK(message->icmpv4.type == expected_emitted_type &&
          message->icmpv4.code == expected_emitted_code &&
          message->icmpv4.quoted_length >= 28);
    if (message->icmpv4.type == 3 && message->icmpv4.code == 4)
      CHECK(message->icmpv4.rest[2] ==
                (unsigned char)(expected_emitted_mtu >> 8) &&
            message->icmpv4.rest[3] == (unsigned char)expected_emitted_mtu);
    if (message->icmpv4.type == 12)
      CHECK(message->icmpv4.rest[0] == expected_emitted_pointer);
    CHECK(!memcmp(message->ipv4.header + 12, &bip, 4) &&
          !memcmp(message->ipv4.header + 16, &aip, 4));
    CHECK(!memcmp(message->icmpv4.quoted_ipv4 + 12, &aip, 4) &&
          !memcmp(message->icmpv4.quoted_ipv4 + 16, &bip, 4));
    ++emitted_errors;
    return NET_RX_SUCCESS;
  }
  if (message->icmpv4.type == 43) {
    CHECK(message->icmpv4.code == expected_probe_code &&
          message->icmpv4.payload_length == 0);
    CHECK(!memcmp(message->icmpv4.rest, &identifier, 2) &&
          message->icmpv4.rest[2] == 11);
    CHECK(message->icmpv4.rest[3] ==
          ((bdev.native->flags & IFF_UP) ? 0x06 : 0));
    CHECK(message->ipv4.header[8] == 255 && message->ipv4.header[1] == 0);
    CHECK(message->ipv4.frag_off == htons(0x4000U));
    ++replies_seen;
    return NET_RX_SUCCESS;
  }
  if (message->icmpv4.type == 14) {
    CHECK(message->icmpv4.code == 0 && message->icmpv4.payload_length == 12);
    CHECK(!memcmp(message->icmpv4.rest, &identifier, 2) &&
          message->icmpv4.rest[2] == 9);
    uint32_t original, receive, transmit;
    memcpy(&original, message->icmpv4.payload, 4);
    memcpy(&receive, message->icmpv4.payload + 4, 4);
    memcpy(&transmit, message->icmpv4.payload + 8, 4);
    CHECK(ntohl(original) == 1000 && ntohl(receive) == fake_utc &&
          ntohl(transmit) == fake_utc);
    ++replies_seen;
    return NET_RX_SUCCESS;
  }
  CHECK(message->packet.icmp_echo.type == 0 &&
        message->packet.icmp_echo.code == 0);
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
static int fallback(const struct ker_transport_message *message, void *arg) {
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
static int feedback(const struct ker_arp_message *message, void *arg) {
  (void)arg;
  CHECK(message->operation == ARPOP_REPLY && message->sender_ip == aip &&
        message->target_ip == bip && message->target_local);
  ++arp_feedback;
  return ker_arp_neighbor_feedback(&barp, &bmonitor, message,
                                   NEIGH_UPDATE_F_OVERRIDE)
             ? NET_RX_DROP
             : NET_RX_SUCCESS;
}
static void send_probe(const struct ker_neighbor_event *event, void *arg) {
  (void)arg;
  struct sk_buff *probe = NULL;
  CHECK(ker_arp_probe_create(&bmonitor, event, &probe) == 0 && probe);
  CHECK(ker_tx_export_enqueue(&btx, &probe) == 0 && !probe);
}
static int a_rx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_rx_ring_poll(&arx, budget);
}
static int b_rx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_rx_ring_poll(&brx, budget);
}
static int a_tx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_tx_export_poll(&atx, budget);
}
static int b_tx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_tx_export_poll(&btx, budget);
}
static struct ker_worker_result poll_worker(struct ker_worker *worker) {
  struct ker_worker_result result = {0};
  CHECK(ker_worker_poll(worker, worker->timers.now_ns, &result) == 0);
  return result;
}
static void inject_control_error(uint8_t type, uint8_t code,
                                 const unsigned char rest[4],
                                 const unsigned char *quote_bytes,
                                 unsigned int quote_length) {
  struct sk_buff *packet = NULL;
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, router_ip, bip, type, code,
                               rest, 64, quote_bytes, quote_length,
                               &packet) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
  struct ker_worker_result result = poll_worker(&aworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&bworker);
  CHECK(result.rx == 1 && result.tx == 0);
}
static void inject_request(struct sk_buff *packet) {
  CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
  struct ker_worker_result result = poll_worker(&aworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&bworker);
  CHECK(result.rx == 1);
}
static void send_custom_request(__be32 source, __be32 destination,
                                const unsigned char destination_mac[ETH_ALEN],
                                const void *options,
                                unsigned int options_length) {
  const struct ker_ipv4_header_fields fields = {0};
  struct sk_buff *packet = NULL;
  CHECK(ker_icmp_echo_ipv4_create_fields(
            &actx, amac, destination_mac, source, destination, identifier,
            sequence, 8, 64, &fields, options, options_length, payload,
            sizeof(payload), &packet) == 0);
  inject_request(packet);
}
static void refresh_ip_checksum(struct sk_buff *packet) {
  unsigned char *ip = skb_network_header(packet);
  ip[10] = ip[11] = 0;
  __sum16 checksum = csum_fold(csum_partial(ip, 20, 0));
  memcpy(ip + 10, &checksum, sizeof(checksum));
}
static struct sk_buff *make_borrowed(__be32 source, __be32 destination,
                                     uint8_t type) {
  struct sk_buff *packet = NULL;
  static const unsigned char rest[4] = {0};
  unsigned char quoted[28] = {0};
  quoted[0] = 0x45;
  quoted[3] = sizeof(quoted);
  quoted[8] = 64;
  quoted[9] = 17;
  memcpy(quoted + 12, &aip, 4);
  memcpy(quoted + 16, &bip, 4);
  __sum16 ip_sum = csum_fold(csum_partial(quoted, 20, 0));
  memcpy(quoted + 10, &ip_sum, 2);
  const void *body = type == 3 ? quoted : payload;
  unsigned int body_length = type == 3 ? sizeof(quoted) : sizeof(payload);
  CHECK(ker_icmpv4_ipv4_create(&bctx, amac, bmac, source, destination, type, 0,
                               rest, 64, body, body_length, &packet) == 0);
  packet->dev = bdev.native;
  packet->pkt_type = PACKET_HOST;
  CHECK(skb_pull(packet, ETH_HLEN) != NULL);
  return packet;
}
static void expect_emitted_error(uint8_t type, uint8_t code,
                                 uint32_t information) {
  struct sk_buff *packet = make_borrowed(aip, bip, 8);
  expected_emitted_type = type;
  expected_emitted_code = code;
  expected_emitted_mtu = type == 3 && code == 4 ? (uint16_t)information : 0;
  expected_emitted_pointer = type == 12 ? (uint8_t)information : 0;
  CHECK(ker_icmpv4_service_emit_error(&service, packet, type, code,
                                      information) == 0);
  BUG_ON(ker_skb_free(packet));
  struct ker_worker_result result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1);
}
static unsigned int extended_name_query(unsigned char *out, const char *name) {
  unsigned int n = (unsigned int)strlen(name), padded = (n + 3U) & ~3U;
  unsigned int length = 8 + padded;
  memset(out, 0, length);
  out[0] = 0x20;
  out[4] = 0;
  out[5] = (unsigned char)(4 + padded);
  out[6] = 3;
  out[7] = 1;
  memcpy(out + 8, name, n);
  __sum16 sum = csum_fold(csum_partial(out, (int)length, 0));
  memcpy(out + 2, &sum, 2);
  return length;
}
static unsigned int extended_object_query(unsigned char *out, uint8_t ctype,
                                          const void *identifier_data,
                                          unsigned int identifier_length) {
  unsigned int padded = (identifier_length + 3U) & ~3U;
  unsigned int length = 8 + padded;
  memset(out, 0, length);
  out[0] = 0x20;
  out[5] = (unsigned char)(4 + padded);
  out[6] = 3;
  out[7] = ctype;
  memcpy(out + 8, identifier_data, identifier_length);
  __sum16 sum = csum_fold(csum_partial(out, (int)length, 0));
  memcpy(out + 2, &sum, 2);
  return length;
}
static void send_probe_query(const unsigned char *body, unsigned int length,
                             uint8_t local) {
  unsigned char rest[4];
  memcpy(rest, &identifier, 2);
  rest[2] = 11;
  rest[3] = local;
  struct sk_buff *packet = NULL;
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 42, 0, rest, 64,
                               body, length, &packet) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &packet) == 0 && !packet);
  struct ker_worker_result result = poll_worker(&aworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&bworker);
  CHECK(result.rx == 1 && result.tx == 0);
  CHECK(service.last_error == 0);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1);
}
static void run(void) {
  CHECK(ker_packet_pool_init(&apool, "echo_svc_a", 63, 0, 2048,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_packet_pool_init(&bpool, "echo_svc_b", 63, 0, 2048,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&actx, &apool, "echo_svc_actx") == 0);
  CHECK(ker_skb_context_init(&bctx, &bpool, "echo_svc_bctx") == 0);
  aip = rte_cpu_to_be_32(0xc0000201);
  bip = rte_cpu_to_be_32(0xc0000202);
  router_ip = rte_cpu_to_be_32(0xc0000209);
  CHECK(ker_eth_device_init(&adev, &actx, "echo_svc_a", 1, amac) == 0);
  CHECK(ker_eth_device_init(&bdev, &bctx, "echo_svc_b", 2, bmac) == 0);
  adev.native->mtu = 1500;
  bdev.native->mtu = 1500;
  CHECK(ker_arp_device_setup(&adev) == 0 && ker_arp_device_setup(&bdev) == 0);
  CHECK(ker_ipv4_address_init(&aaddr, &adev, aip, 24) == 0);
  CHECK(ker_ipv4_address_init(&baddr, &bdev, bip, 24) == 0);
  CHECK(ker_receive_runtime_init(&art, &actx) == 0);
  CHECK(ker_receive_runtime_init(&brt, &bctx) == 0);
  CHECK(ker_neighbor_table_init(&bneighbors, &baddr, "echo_svc_neighbors", 4,
                                2) == 0);
  struct ker_neighbor_config ncfg = {.retrans_ticks = 20,
                                     .reachable_ticks = 100,
                                     .delay_ticks = 30,
                                     .ucast_probes = 2,
                                     .mcast_probes = 2,
                                     .mcast_reprobes = 1,
                                     .queue_bytes = 16384};
  CHECK(ker_neighbor_configure(&bneighbors, &ncfg) == 0);
  CHECK(ker_tx_ring_init(&ab, "echo_svc_ab", 4, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_ring_init(&ba, "echo_svc_ba", 4, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init(&atx, &actx, 8, 32768, ring_sink, &ab) == 0);
  CHECK(ker_tx_export_init(&btx, &bctx, 8, 32768, ring_sink, &ba) == 0);
  CHECK(ker_rx_ring_init(&arx, &ba, &adev, &art, 128) == 0);
  CHECK(ker_rx_ring_init(&brx, &ab, &bdev, &brt, 128) == 0);
  CHECK(ker_transport_receiver_register(&brx_transport, &brt, &bdev, fallback,
                                        NULL) == 0);
  CHECK(ker_transport_receiver_register(&arx_transport, &art, &adev,
                                        receive_echo, NULL) == 0);
  CHECK(ker_transport_receiver_enable_generic_icmpv4(&arx_transport) == 0);
  CHECK(ker_arp_responder_register(&aresponder, &art, &aaddr, &atx) == 0);
  CHECK(ker_arp_receiver_register(&barp, &brt, &baddr, feedback, NULL) == 0);
  struct ker_worker_config config = {
      .timer_budget = 1, .rx_budget = 1, .tx_budget = 1};
  struct ker_worker_ops aops = {.rx = a_rx, .tx = a_tx};
  struct ker_worker_ops bops = {.rx = b_rx, .tx = b_tx};
  CHECK(ker_worker_init(&aworker, &apool, &config, &aops) == 0);
  CHECK(ker_worker_init(&bworker, &bpool, &config, &bops) == 0);
  CHECK(ker_neighbor_monitor_discovery_init(&bmonitor, &bneighbors,
                                            &bworker.timers, &btx, aip,
                                            send_probe, NULL, NULL) == 0);
  CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                  &service_config) == 0);
  CHECK(ker_transport_receiver_unregister(&brx_transport) == -EBUSY);
  CHECK(ker_neighbor_monitor_cleanup(&bmonitor) == -EBUSY);
  CHECK(ker_neighbor_monitor_resolution_disable(&bmonitor) == -EBUSY);

  struct sk_buff *request = NULL;
  const struct ker_ipv4_header_fields request_fields = {
      .ds_field = 0x2e,
      .identification = rte_cpu_to_be_16(0x1234),
      .frag_off = rte_cpu_to_be_16(0x4000)};
  CHECK(ker_icmp_echo_ipv4_create_configured_fields(
            &aaddr, bmac, bip, identifier, sequence, 8, 64, &request_fields,
            NULL, 0, payload, sizeof(payload), &request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &request) == 0 && !request);
  struct ker_worker_result result = poll_worker(&aworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&bworker);
  CHECK(result.rx == 1 && result.tx == 0);
  CHECK(service.received == 1 && service.replies_submitted == 1 &&
        !service.dropped);
  CHECK(bmonitor.entry->arp_queue.qlen == 1);
  CHECK(ker_icmpv4_service_disable(&service) == 0);
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
  CHECK(result.rx == 1 &&
        result.tx == 0); /* B applies scoped native ARP feedback. */
  CHECK(arp_feedback == 1 && btx.packets == 1);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0);
  CHECK(replies_seen == 1 && !btx.packets && !atx.packets);
  CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                  &service_config) == 0);

  unsigned int old_requests = service.received;
  unsigned int old_drops = service.dropped;
  send_custom_request(rte_cpu_to_be_32(0xc0000209), bip, bmac, NULL, 0);
  CHECK(service.received == old_requests + 1 &&
        service.dropped == old_drops + 1 &&
        service.last_error == -EHOSTUNREACH);
  send_custom_request(aip, rte_cpu_to_be_32(0xc0000209), bmac, NULL, 0);
  send_custom_request(aip, bip, broadcast, NULL, 0);
  static const unsigned char option_bytes[4] = {1, 1, 1, 1};
  send_custom_request(aip, bip, bmac, option_bytes, sizeof(option_bytes));
  CHECK(service.received == old_requests + 4 &&
        service.dropped == old_drops + 4 && service.last_error == -ENOTSUP);

  struct sk_buff *bad_ttl = NULL;
  const struct ker_ipv4_header_fields zero_fields = {0};
  CHECK(ker_icmp_echo_ipv4_create_fields(
            &actx, amac, bmac, aip, bip, identifier, sequence, 8, 1,
            &zero_fields, NULL, 0, payload, sizeof(payload), &bad_ttl) == 0);
  bad_ttl->data[ETH_HLEN + 8] = 0;
  refresh_ip_checksum(bad_ttl);
  inject_request(bad_ttl);
  CHECK(service.received == old_requests + 5 &&
        service.dropped == old_drops + 5 && service.last_error == -ENOTSUP);

  struct sk_buff *reserved = NULL;
  CHECK(ker_icmp_echo_ipv4_create_fields(
            &actx, amac, bmac, aip, bip, identifier, sequence, 8, 64,
            &zero_fields, NULL, 0, payload, sizeof(payload), &reserved) == 0);
  reserved->data[ETH_HLEN + 6] = 0x80;
  refresh_ip_checksum(reserved);
  inject_request(reserved);
  CHECK(service.received == old_requests + 5 &&
        service.dropped == old_drops + 5 &&
        brx_transport.validation_error == -ENOTSUP);

  struct sk_buff *bad_checksum = NULL;
  CHECK(ker_icmp_echo_ipv4_create_fields(&actx, amac, bmac, aip, bip,
                                         identifier, sequence, 8, 64,
                                         &zero_fields, NULL, 0, payload,
                                         sizeof(payload), &bad_checksum) == 0);
  bad_checksum->data[ETH_HLEN + 20 + 8] ^= 1;
  inject_request(bad_checksum);
  CHECK(service.received == old_requests + 5 &&
        service.dropped == old_drops + 5 &&
        brx_transport.validation_error == -EBADMSG);

  struct sk_buff *pressure_request = NULL;
  CHECK(ker_icmp_echo_ipv4_create_configured(
            &aaddr, bmac, bip, identifier, sequence, 8, 64, NULL, 0, payload,
            sizeof(payload), &pressure_request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &pressure_request) == 0 &&
        !pressure_request);
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
  old_requests = service.received;
  old_drops = service.dropped;
  struct sk_buff *full_export_request = NULL;
  CHECK(ker_icmp_echo_ipv4_create_configured(
            &aaddr, bmac, bip, identifier, sequence, 8, 64, NULL, 0, payload,
            sizeof(payload), &full_export_request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &full_export_request) == 0 &&
        !full_export_request);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  CHECK(ker_rx_ring_poll(&brx, 1) == 1);
  CHECK(service.received == old_requests + 1 &&
        service.dropped == old_drops + 1 && service.last_error == -ENOSPC &&
        btx.packets == btx.packet_limit);
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

  uint64_t old_suppressed = service.suppressed;
  fake_now = 999;
  send_custom_request(aip, bip, bmac, NULL, 0);
  CHECK(service.last_error == -ERANGE &&
        service.suppressed == old_suppressed + 1);
  fake_now = 1000;

  unsigned char timestamp_rest[4];
  memcpy(timestamp_rest, &identifier, 2);
  timestamp_rest[2] = 9;
  timestamp_rest[3] = 0;
  uint32_t originate = htonl(1000);
  unsigned char timestamp_body[12] = {0};
  memcpy(timestamp_body, &originate, 4);
  struct sk_buff *timestamp_request = NULL;
  CHECK(ker_icmpv4_ipv4_create(
            &actx, amac, bmac, aip, bip, 13, 0, timestamp_rest, 64,
            timestamp_body, sizeof(timestamp_body), &timestamp_request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &timestamp_request) == 0 &&
        !timestamp_request);
  reentry_packet = make_borrowed(aip, bip, 8);
  reentry_check = true;
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.rx == 1 && pressure_result.tx == 0 &&
        service.replies_submitted == 2);
  reentry_check = false;
  CHECK(reentry_disable_result == -EBUSY && reentry_emit_result == -EBUSY &&
        service.receiver == &brx_transport && bmonitor.echo_service_refs == 1);
  BUG_ON(ker_skb_free(reentry_packet));
  reentry_packet = NULL;
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1 && replies_seen == 3);
  fake_utc_status = 1;
  timestamp_request = NULL;
  CHECK(ker_icmpv4_ipv4_create(
            &actx, amac, bmac, aip, bip, 13, 0, timestamp_rest, 64,
            timestamp_body, sizeof(timestamp_body), &timestamp_request) == 0);
  inject_request(timestamp_request);
  CHECK(service.last_error == -EINVAL && service.replies_submitted == 2);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 0 && pressure_result.rx == 0);
  fake_utc_status = 0;

  unsigned char probe_rest[4];
  memcpy(probe_rest, &identifier, 2);
  probe_rest[2] = 11;
  probe_rest[3] = 1;
  unsigned char probe_body[32];
  unsigned int probe_length = extended_name_query(probe_body, "echo_svc_b");
  struct sk_buff *probe_request = NULL;
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 42, 0, probe_rest,
                               64, probe_body, probe_length,
                               &probe_request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &probe_request) == 0 && !probe_request);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.rx == 1 && pressure_result.tx == 0 &&
        service.replies_submitted == 3);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1 && replies_seen == 4);
  unsigned char object_body[24];
  uint32_t ifindex = htonl((uint32_t)bdev.native->ifindex);
  unsigned int object_length =
      extended_object_query(object_body, 2, &ifindex, sizeof(ifindex));
  expected_probe_code = 0;
  send_probe_query(object_body, object_length, 1);
  unsigned char wrong_local_address[8] = {0, 1, 4, 0};
  memcpy(wrong_local_address + 4, &aip, 4);
  object_length = extended_object_query(object_body, 3, wrong_local_address,
                                        sizeof(wrong_local_address));
  expected_probe_code = 2;
  send_probe_query(object_body, object_length, 1);
  unsigned char malformed_probe[32];
  unsigned int malformed_length =
      extended_name_query(malformed_probe, "echo_svc_b");
  memcpy(probe_rest, &identifier, 2);
  probe_rest[2] = 11;
  probe_rest[3] = 1;
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 42, 0, probe_rest,
                               64, malformed_probe, malformed_length,
                               &probe_request) == 0);
  malformed_probe[0] = 0; /* Invalid extension version, valid outer checksum. */
  memcpy(probe_request->data + ETH_HLEN + 20 + 8, malformed_probe,
         malformed_length);
  unsigned char *icmp = probe_request->data + ETH_HLEN + 20;
  icmp[2] = icmp[3] = 0;
  __sum16 bad_probe_sum =
      csum_fold(csum_partial(icmp, 8 + malformed_length, 0));
  memcpy(icmp + 2, &bad_probe_sum, 2);
  expected_probe_code = 1;
  CHECK(ker_tx_export_enqueue(&atx, &probe_request) == 0 && !probe_request);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.tx == 1);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.rx == 1);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1);
  expected_probe_code = 0;

  unsigned char quote[28] = {0};
  quote[0] = 0x45;
  quote[2] = 0;
  quote[3] = sizeof(quote);
  quote[8] = 64;
  quote[9] = 17;
  memcpy(quote + 12, &bip, 4);
  memcpy(quote + 16, &aip, 4);
  __sum16 quote_sum = csum_fold(csum_partial(quote, 20, 0));
  memcpy(quote + 10, &quote_sum, 2);
  quote[20] = 0x12;
  quote[21] = 0x34;
  quote[22] = 0x56;
  quote[23] = 0x78;
  static const unsigned char error_rest[4] = {0};
  struct sk_buff *gateway_error = NULL;
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, router_ip, bip, 3, 3,
                               error_rest, 64, quote, sizeof(quote),
                               &gateway_error) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &gateway_error) == 0 && !gateway_error);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.rx == 1 && pressure_result.tx == 0 &&
        control_events == 1 && service.events_delivered == 1);
  unsigned char redirect_rest[4];
  memcpy(redirect_rest, &router_ip, 4);
  expected_control_type = 5;
  expected_control_code = 1;
  expected_gateway = router_ip;
  inject_control_error(5, 1, redirect_rest, quote, sizeof(quote));
  CHECK(control_events == 2 && service.events_delivered == 2);
  static const unsigned char zero_rest[4] = {0};
  expected_control_type = 11;
  expected_control_code = 0;
  expected_gateway = 0;
  inject_control_error(11, 0, zero_rest, quote, sizeof(quote));
  CHECK(control_events == 3 && service.events_delivered == 3);
  unsigned char pointer_rest[4] = {4, 0, 0, 0};
  expected_control_type = 12;
  expected_control_code = 0;
  expected_pointer = 4;
  inject_control_error(12, 0, pointer_rest, quote, sizeof(quote));
  CHECK(control_events == 4 && service.events_delivered == 4);
  expected_control_type = 3;
  expected_control_code = 3;
  expected_pointer = 0;
  expected_gateway = 0;
  unsigned char bad_quote[sizeof(quote)];
  memcpy(bad_quote, quote, sizeof(quote));
  memcpy(bad_quote + 12, &aip,
         4); /* The quote must be local -> monitored peer. */
  uint64_t suppressed_before_bad_quote = service.suppressed;
  inject_control_error(3, 3, zero_rest, bad_quote, sizeof(bad_quote));
  CHECK(control_events == 4 && service.last_error == 0 &&
        service.suppressed == suppressed_before_bad_quote + 1);
  service.config.event = NULL;
  inject_control_error(11, 0, zero_rest, quote, sizeof(quote));
  CHECK(control_events == 4 && service.last_error == -EOPNOTSUPP);
  service.config.event = control_event;

  struct sk_buff *borrowed = NULL;
  CHECK(ker_icmpv4_ipv4_create(&bctx, amac, bmac, aip, bip, 8, 0,
                               timestamp_rest, 64, payload, sizeof(payload),
                               &borrowed) == 0);
  borrowed->dev = bdev.native;
  borrowed->pkt_type = PACKET_HOST;
  CHECK(skb_pull(borrowed, ETH_HLEN) != NULL);
  unsigned char borrowed_copy[20 + 8 + sizeof(payload)];
  CHECK(borrowed->len == sizeof(borrowed_copy));
  memcpy(borrowed_copy, borrowed->data, borrowed->len);
  unsigned int owner = brx_transport.handler.runtime->lcore;
  uint64_t tokens_before_owner_check = service.tokens;
  bmonitor.busy = true;
  CHECK(ker_icmpv4_service_emit_error(&service, borrowed, 3, 3, 0) == -EBUSY);
  CHECK(bmonitor.busy && service.tokens == tokens_before_owner_check &&
        borrowed->len == sizeof(borrowed_copy) &&
        !memcmp(borrowed_copy, borrowed->data, borrowed->len));
  bmonitor.busy = false;
  brx_transport.handler.runtime->lcore = owner + 1;
  CHECK(ker_icmpv4_service_emit_error(&service, borrowed, 3, 3, 0) == -EXDEV);
  brx_transport.handler.runtime->lcore = owner;
  CHECK(service.tokens == tokens_before_owner_check &&
        borrowed->len == sizeof(borrowed_copy) &&
        !memcmp(borrowed_copy, borrowed->data, borrowed->len));
  reentry_packet = borrowed;
  reentry_check = true;
  CHECK(ker_icmpv4_service_emit_error(&service, borrowed, 3, 3, 0) == 0);
  reentry_check = false;
  CHECK(reentry_disable_result == -EBUSY && reentry_emit_result == -EBUSY &&
        bmonitor.echo_service_refs == 1);
  reentry_packet = NULL;
  CHECK(service.errors_submitted == 1 &&
        borrowed->len == sizeof(borrowed_copy) &&
        !memcmp(borrowed_copy, borrowed->data, borrowed->len));
  struct ker_ipv4_packet_view borrowed_view;
  CHECK(ker_ipv4_packet_view_init(&bctx, borrowed, &borrowed_view) == 0);
  BUG_ON(ker_skb_free(borrowed));
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1 && emitted_errors == 1);

  expect_emitted_error(3, 4, 1400);
  expect_emitted_error(11, 0, 0);
  expect_emitted_error(12, 0, 4);
  CHECK(emitted_errors == 4 && service.errors_submitted == 4);

  /* First fragments are eligible; noninitial fragments and broadcasts are not.
   */
  expected_emitted_type = 3;
  expected_emitted_code = 3;
  struct sk_buff *first_fragment = make_borrowed(aip, bip, 8);
  first_fragment->data[6] = 0x20;
  first_fragment->data[7] = 0;
  refresh_ip_checksum(first_fragment);
  CHECK(ker_icmpv4_service_emit_error(&service, first_fragment, 3, 3, 0) == 0);
  BUG_ON(ker_skb_free(first_fragment));
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1);
  struct sk_buff *suppressed = make_borrowed(aip, bip, 8);
  suppressed->data[6] = 0;
  suppressed->data[7] = 1;
  refresh_ip_checksum(suppressed);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  suppressed = make_borrowed(aip, rte_cpu_to_be_32(0xffffffff), 8);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  suppressed = make_borrowed(aip, rte_cpu_to_be_32(0xc00002ff), 8);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  uint64_t tokens_before_invalid_source = service.tokens;
  suppressed = make_borrowed(rte_cpu_to_be_32(0xffffffff), bip, 8);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  suppressed = make_borrowed(rte_cpu_to_be_32(0xc00002ff), bip, 8);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  CHECK(service.tokens == tokens_before_invalid_source);
  suppressed = make_borrowed(aip, bip, 8);
  uint64_t tokens_before_bad_l2 = service.tokens;
  memcpy(suppressed->head + suppressed->mac_header, amac, ETH_ALEN);
  unsigned char l2_reject_copy[20 + 8 + sizeof(payload)];
  memcpy(l2_reject_copy, suppressed->data, suppressed->len);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  CHECK(service.tokens == tokens_before_bad_l2 &&
        suppressed->len == sizeof(l2_reject_copy) &&
        !memcmp(l2_reject_copy, suppressed->data, sizeof(l2_reject_copy)));
  memcpy(suppressed->head + suppressed->mac_header, bmac, ETH_ALEN);
  suppressed->dev = adev.native;
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  suppressed->dev = bdev.native;
  CHECK(service.tokens == tokens_before_bad_l2 &&
        !memcmp(l2_reject_copy, suppressed->data, sizeof(l2_reject_copy)));
  BUG_ON(ker_skb_free(suppressed));
  suppressed = make_borrowed(aip, bip, 3);
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));
  suppressed = make_borrowed(aip, bip, 8);
  suppressed->data[20] = 99;
  CHECK(ker_icmpv4_service_emit_error(&service, suppressed, 3, 3, 0) ==
        -EHOSTUNREACH);
  BUG_ON(ker_skb_free(suppressed));

  service.config.burst = 1;
  service.tokens = 1;
  uint64_t replies_before_rate = service.replies_submitted;
  send_custom_request(aip, bip, bmac, NULL, 0);
  CHECK(service.last_error == 0 &&
        service.replies_submitted == replies_before_rate + 1);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1);
  fake_now = 1099;
  uint64_t rate_suppressed = service.suppressed;
  send_custom_request(aip, bip, bmac, NULL, 0);
  CHECK(service.last_error == -EAGAIN &&
        service.suppressed == rate_suppressed + 1);
  fake_now = 1050;
  send_custom_request(aip, bip, bmac, NULL, 0);
  CHECK(service.last_error == -ERANGE &&
        service.suppressed == rate_suppressed + 2);
  fake_now = 1100;
  send_custom_request(aip, bip, bmac, NULL, 0);
  CHECK(service.last_error == 0 &&
        service.replies_submitted == replies_before_rate + 2);
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1);

  struct sk_buff *fallback_packet = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(41001), rte_cpu_to_be_16(41002),
            64, NULL, 0, payload, sizeof(payload), &fallback_packet) == 0);
  inject_request(fallback_packet);
  CHECK(udp_seen == 1);
  CHECK(ker_tcp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(42001), rte_cpu_to_be_16(42002),
            rte_cpu_to_be_32(1), 0, rte_cpu_to_be_16(4096), 0x02, 64, NULL, 0,
            NULL, 0, payload, sizeof(payload), &fallback_packet) == 0);
  inject_request(fallback_packet);
  CHECK(tcp_seen == 1 && fallback_seen == 2);

  /* Type zero bypasses the service and remains visible to the app callback. */
  CHECK(ker_icmp_echo_ipv4_create_configured(&aaddr, bmac, bip, identifier,
                                             sequence, 0, 64, NULL, 0, payload,
                                             sizeof(payload), &request) == 0);
  CHECK(ker_tx_export_enqueue(&atx, &request) == 0 && !request);
  result = poll_worker(&aworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&bworker);
  CHECK(result.rx == 1 && fallback_seen == 3);

  CHECK(ker_icmpv4_service_disable(&service) == 0);
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
  CHECK(ker_receive_runtime_cleanup(&brt) == 0 &&
        ker_receive_runtime_cleanup(&art) == 0);
  CHECK(ker_ipv4_address_cleanup(&baddr) == 0 &&
        ker_ipv4_address_cleanup(&aaddr) == 0);
  CHECK(ker_eth_device_cleanup(&bdev) == 0 &&
        ker_eth_device_cleanup(&adev) == 0);
  CHECK(ker_skb_context_cleanup(&bctx) == 0 &&
        ker_skb_context_cleanup(&actx) == 0);
  CHECK(ker_packet_pool_cleanup(&bpool) == 0 &&
        ker_packet_pool_cleanup(&apool) == 0);
}
int main(void) {
  ker_test_eal_init();
  CHECK(ker_memory_init(SOCKET_ID_ANY, 64) == 0);
  run();
  CHECK(ker_memory_shutdown() == 0 && rte_eal_cleanup() == 0);
  return 0;
}
