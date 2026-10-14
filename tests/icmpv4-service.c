#include "runtime/icmpv4-service.h"
#include "check.h"
#include "eal.h"
#include "ker/linux_neighbor_update.h"
#include "runtime/arp-receive.h"
#include "runtime/arp-responder.h"
#include "runtime/arp.h"
#include "runtime/buffer.h"
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
#include "runtime/udp-endpoint.h"
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
static struct ker_protocol_handler competing_ip;
static struct ker_neighbor_table bneighbors;
static struct ker_neighbor_monitor bmonitor;
static struct ker_icmpv4_service service;
static struct ker_neighbor_table aneighbors;
static struct ker_neighbor_monitor amonitor;
static struct ker_icmpv4_service aservice;
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
static unsigned int endpoint_seen;
static unsigned int endpoint_a_seen;
static int endpoint_drop;
static int endpoint_status = NET_RX_SUCCESS;
static struct ker_udp_endpoint_table *endpoint_table_under_test;
static struct ker_udp_endpoint_handle endpoint_handle_under_test;
static int endpoint_reentrant_bind, endpoint_reentrant_disable,
    endpoint_reentrant_connect, endpoint_reentrant_disconnect,
    endpoint_reentrant_close;
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
static unsigned char expected_endpoint_quote[576];
static unsigned int expected_endpoint_quote_length;
static uint8_t expected_probe_code;
static uint8_t expected_emitted_type = 3, expected_emitted_code = 3;
static uint16_t expected_emitted_mtu;
static uint8_t expected_emitted_pointer;
static uint8_t expected_control_type = 3, expected_control_code = 3,
               expected_pointer;
static uint16_t expected_mtu;
static __be32 expected_gateway;
static int wire_checksum_valid(const unsigned char *, unsigned int);
static void refresh_ip_checksum(struct sk_buff *);
static void inject_from_b(struct sk_buff *);
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
    CHECK(csum_fold(csum_partial(message->icmpv4.header,
                                 message->icmpv4.message_length, 0)) == 0);
    CHECK(
        wire_checksum_valid(message->ipv4.header, message->ipv4.header_length));
    CHECK(wire_checksum_valid(message->icmpv4.header,
                              message->icmpv4.message_length));
    if (expected_endpoint_quote_length) {
      CHECK(message->icmpv4.quoted_length == expected_endpoint_quote_length);
      CHECK(!memcmp(message->icmpv4.quoted_ipv4, expected_endpoint_quote,
                    expected_endpoint_quote_length));
      expected_endpoint_quote_length = 0;
    }
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
static int consume_competing_ip(struct sk_buff *skb,
                               struct ker_protocol_handler *handler,
                               struct net_device *original, void *arg) {
  (void)handler;
  (void)original;
  (void)arg;
  BUG_ON(ker_skb_free(skb));
  return NET_RX_DROP;
}
static int endpoint_receive(const struct ker_transport_message *message,
                            void *arg) {
  (void)arg;
  CHECK(message->protocol == KER_TRANSPORT_UDP);
  CHECK(message->packet.udp.destination_port == rte_cpu_to_be_16(9000) ||
        message->packet.udp.destination_port == rte_cpu_to_be_16(9001));
  CHECK(message->packet.udp.payload_length == 0 ||
        message->packet.udp.payload_length == sizeof(payload));
  if (message->packet.udp.payload_length)
    CHECK(!memcmp(message->packet.udp.payload, payload, sizeof(payload)));
  ++endpoint_seen;
  if (endpoint_table_under_test) {
    endpoint_reentrant_bind =
        ker_udp_endpoint_bind(endpoint_table_under_test, rte_cpu_to_be_16(9002),
                              endpoint_receive, NULL);
    endpoint_reentrant_disable =
        ker_udp_endpoint_table_disable(endpoint_table_under_test);
    endpoint_reentrant_connect = ker_udp_endpoint_connect(
        endpoint_table_under_test, endpoint_handle_under_test, aip,
        rte_cpu_to_be_16(40000));
    endpoint_reentrant_disconnect = ker_udp_endpoint_disconnect(
        endpoint_table_under_test, endpoint_handle_under_test);
    endpoint_reentrant_close = ker_udp_endpoint_close(
        endpoint_table_under_test, endpoint_handle_under_test);
  }
  if (endpoint_status != NET_RX_SUCCESS)
    return endpoint_status;
  return endpoint_drop ? NET_RX_DROP : NET_RX_SUCCESS;
}
static int endpoint_a_receive(const struct ker_transport_message *message,
                              void *arg) {
  (void)arg;
  CHECK(message->protocol == KER_TRANSPORT_UDP);
  CHECK(message->packet.udp.destination_port == rte_cpu_to_be_16(9000));
  ++endpoint_a_seen;
  return NET_RX_SUCCESS;
}
static void no_probe(const struct ker_neighbor_event *event, void *arg) {
  (void)event;
  (void)arg;
}
static int wire_checksum_valid(const unsigned char *bytes,
                               unsigned int length) {
  uint32_t sum = 0;
  for (unsigned int i = 0; i < length; i += 2) {
    uint16_t word = (uint16_t)bytes[i] << 8;
    if (i + 1 < length)
      word |= bytes[i + 1];
    sum += word;
    sum = (sum & 0xffffU) + (sum >> 16);
  }
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return sum == 0xffffU;
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
static void inject_unknown_protocol_fields(uint8_t protocol, uint8_t ttl,
                                           uint16_t fragment,
                                           bool expect_error) {
  struct sk_buff *packet = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &packet) == 0);
  unsigned char *ip = skb_network_header(packet);
  ip[9] = protocol;
  ip[8] = ttl;
  uint16_t network_fragment = htons(fragment);
  memcpy(ip + 6, &network_fragment, sizeof(network_fragment));
  refresh_ip_checksum(packet);
  if (expect_error) {
    expected_endpoint_quote_length = packet->len - ETH_HLEN;
    memcpy(expected_endpoint_quote, ip, expected_endpoint_quote_length);
  }
  inject_request(packet);
}
static void inject_unknown_protocol(uint8_t protocol) {
  inject_unknown_protocol_fields(protocol, 64, 0, true);
}
static void inject_unknown_bad_checksum(void) {
  struct sk_buff *packet = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &packet) == 0);
  skb_network_header(packet)[9] = 253;
  inject_request(packet);
}
static void inject_unknown_options(void) {
  static const unsigned char options[4] = {1, 1, 1, 1};
  struct sk_buff *packet = NULL;
  CHECK(ker_udp_ipv4_create_ip_options(
            &actx, amac, bmac, aip, bip, rte_cpu_to_be_16(40000),
            rte_cpu_to_be_16(9000), 64, options, sizeof(options), payload,
            sizeof(payload), &packet) == 0);
  skb_network_header(packet)[9] = 253;
  refresh_ip_checksum(packet);
  inject_request(packet);
}
static void inject_empty_default_protocol(void) {
  struct sk_buff *packet = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &baddr, amac, aip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &packet) == 0);
  skb_network_header(packet)[9] = 253;
  refresh_ip_checksum(packet);
  inject_from_b(packet);
}
static void inject_from_b(struct sk_buff *packet) {
  CHECK(ker_tx_export_enqueue(&btx, &packet) == 0 && !packet);
  struct ker_worker_result result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0);
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
  unsigned int header_length = (ip[0] & 0x0fU) * 4U;
  __sum16 checksum = csum_fold(csum_partial(ip, header_length, 0));
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
  CHECK(ker_neighbor_table_init(&aneighbors, &aaddr, "echo_svc_aneighbors", 4,
                                2) == 0);
  struct ker_neighbor_config ncfg = {.retrans_ticks = 20,
                                     .reachable_ticks = 100,
                                     .delay_ticks = 30,
                                     .ucast_probes = 2,
                                     .mcast_probes = 2,
                                     .mcast_reprobes = 1,
                                     .queue_bytes = 16384};
  CHECK(ker_neighbor_configure(&bneighbors, &ncfg) == 0);
  CHECK(ker_neighbor_configure(&aneighbors, &ncfg) == 0);
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
  CHECK(ker_neighbor_monitor_discovery_init(&amonitor, &aneighbors,
                                            &aworker.timers, &atx, bip,
                                            no_probe, NULL, NULL) == 0);
  struct ker_icmpv4_service_config a_service_config = service_config;
  a_service_config.event = NULL;
  const unsigned int unavailable_known[] = {1, 6, 17};
  for (unsigned int i = 0; i < sizeof(unavailable_known) /
                                  sizeof(unavailable_known[0]); ++i) {
    struct ker_icmpv4_service_config invalid_service_config = service_config;
    invalid_service_config.unavailable_protocols[unavailable_known[i] / 8] |=
        (uint8_t)(1U << (unavailable_known[i] % 8));
    CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                    &invalid_service_config) == -EINVAL);
    CHECK(!service.receiver && !brx_transport.icmpv4_service &&
          bmonitor.echo_service_refs == 0);
  }
  service_config.unavailable_protocols[31] = 1U << 5; /* protocol 253 */
  service_config.unavailable_protocols[0] |= 1U; /* protocol 0 */
  service_config.unavailable_protocols[3] |= 1U << 7; /* protocol 31 */
  service_config.unavailable_protocols[4] |= 1U; /* protocol 32 */
  service_config.unavailable_protocols[31] |= 1U << 7; /* protocol 255 */
  unsigned int errors_before_unbound = emitted_errors;
  inject_unknown_protocol_fields(100, 64, 0, false);
  struct ker_worker_result unbound_result = poll_worker(&bworker);
  CHECK(unbound_result.rx == 0 && unbound_result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        fallback_seen == 0 && emitted_errors == errors_before_unbound);
  CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                  &service_config) == 0);
  uint8_t selected_bitmap[sizeof(service_config.unavailable_protocols)];
  memcpy(selected_bitmap, service.config.unavailable_protocols,
         sizeof(selected_bitmap));
  memset(service_config.unavailable_protocols, 0,
         sizeof(service_config.unavailable_protocols));
  CHECK(!memcmp(service.config.unavailable_protocols, selected_bitmap,
                sizeof(selected_bitmap)));
  memcpy(service_config.unavailable_protocols, selected_bitmap,
         sizeof(selected_bitmap));
  CHECK(ker_icmpv4_service_enable(&aservice, &arx_transport, &amonitor,
                                  &a_service_config) == 0);
  unsigned int empty_errors_before = emitted_errors;
  inject_empty_default_protocol();
  struct ker_worker_result empty_result = poll_worker(&aworker);
  CHECK(empty_result.rx == 0 && empty_result.tx == 0 &&
        arx_transport.validation_error == -EPROTONOSUPPORT &&
        aservice.errors_submitted == 0 &&
        emitted_errors == empty_errors_before);

  /* A fixed bounded table owns supported local UDP delivery. */
  struct ker_udp_endpoint_table endpoints = {0};
  struct ker_udp_endpoint endpoint_entries[2] = {0};
  struct ker_udp_endpoint_handle endpoint_handle;
  CHECK(ker_udp_endpoint_table_enable(&endpoints, &brx_transport, &service,
                                      endpoint_entries, 2) == 0);
  CHECK(ker_udp_endpoint_bind_ex(&endpoints, rte_cpu_to_be_16(9000),
                                 endpoint_receive, NULL,
                                 &endpoint_handle) == 0);
  endpoint_handle_under_test = endpoint_handle;
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, 0, 0) ==
        -EINVAL);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, 0,
                                 rte_cpu_to_be_16(40000)) == -EINVAL);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle,
                                 rte_cpu_to_be_32(0xe0000001),
                                 rte_cpu_to_be_16(40000)) == -EINVAL);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40000)) == 0);
  uint64_t connected_incarnation =
      endpoint_entries[endpoint_handle.slot].incarnation;
  struct ker_udp_endpoint_table aendpoints = {0};
  struct ker_udp_endpoint aendpoint_entries[1] = {0};
  CHECK(ker_udp_endpoint_table_enable(&aendpoints, &arx_transport, &aservice,
                                      aendpoint_entries, 1) == 0);
  CHECK(ker_udp_endpoint_bind(&aendpoints, rte_cpu_to_be_16(9000),
                              endpoint_a_receive, NULL) == 0);
  struct sk_buff *reverse_udp = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &baddr, amac, aip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &reverse_udp) == 0);
  inject_from_b(reverse_udp);
  CHECK(endpoint_a_seen == 1 && endpoint_seen == 0);
  struct sk_buff *forward_udp = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &forward_udp) == 0);
  inject_request(forward_udp);
  CHECK(endpoint_seen == 1 && endpoint_a_seen == 1);
  struct sk_buff *wrong_source_address = NULL;
  CHECK(ker_udp_ipv4_create(
            &actx, amac, bmac, rte_cpu_to_be_32(0xc000020a), bip,
            rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000), 64, payload,
            sizeof(payload), &wrong_source_address) == 0);
  uint64_t suppressed_peer_errors = service.errors_submitted;
  inject_request(wrong_source_address);
  CHECK(endpoint_seen == 1 && service.errors_submitted == suppressed_peer_errors);
  struct sk_buff *empty_udp = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000),
            rte_cpu_to_be_16(9000), 64, NULL, 0, NULL, 0, &empty_udp) == 0);
  inject_request(empty_udp);
  CHECK(endpoint_seen == 2);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40001)) == 0);
  CHECK(endpoint_entries[endpoint_handle.slot].incarnation !=
        connected_incarnation);
  connected_incarnation = endpoint_entries[endpoint_handle.slot].incarnation;
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle,
                                 rte_cpu_to_be_32(0xe0000001),
                                 rte_cpu_to_be_16(40000)) == -EINVAL);
  CHECK(endpoint_entries[endpoint_handle.slot].peer_address == aip &&
        endpoint_entries[endpoint_handle.slot].peer_port ==
            rte_cpu_to_be_16(40001) &&
        endpoint_entries[endpoint_handle.slot].incarnation ==
            connected_incarnation);
  CHECK(ker_udp_endpoint_disconnect(&endpoints, endpoint_handle) == 0);
  CHECK(!endpoint_entries[endpoint_handle.slot].connected &&
        endpoint_entries[endpoint_handle.slot].incarnation !=
            connected_incarnation);
  CHECK(ker_udp_endpoint_disconnect(&endpoints, endpoint_handle) ==
        -ENOTCONN);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40000)) == 0);
  CHECK(endpoint_entries[endpoint_handle.slot].connected &&
        endpoint_entries[endpoint_handle.slot].peer_port ==
            rte_cpu_to_be_16(40000) &&
        endpoint_entries[endpoint_handle.slot].incarnation !=
            connected_incarnation);
  CHECK(ker_udp_endpoint_unbind(&aendpoints, rte_cpu_to_be_16(9000)) == 0);
  CHECK(ker_udp_endpoint_table_disable(&aendpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&aservice) == 0);
  endpoint_table_under_test = &endpoints;
  CHECK(ker_icmpv4_service_disable(&service) == -EBUSY);
  service.busy = true;
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9002),
                              endpoint_receive, NULL) == -EBUSY);
  service.busy = false;
  bmonitor.busy = true;
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9002),
                              endpoint_receive, NULL) == -EBUSY);
  bmonitor.busy = false;
  CHECK(ker_udp_endpoint_bind(&endpoints, 0, endpoint_receive, NULL) ==
        -EINVAL);
  unsigned int endpoint_owner = brx_transport.handler.runtime->lcore;
  brx_transport.handler.runtime->lcore = endpoint_owner + 1;
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9002),
                              endpoint_receive, NULL) == -EXDEV);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40000)) == -EXDEV);
  CHECK(ker_udp_endpoint_disconnect(&endpoints, endpoint_handle) == -EXDEV);
  CHECK(ker_udp_endpoint_close(&endpoints, endpoint_handle) == -EXDEV);
  brx_transport.handler.runtime->lcore = endpoint_owner;
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9000),
                              endpoint_receive, NULL) == -EADDRINUSE);
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9001),
                              endpoint_receive, NULL) == 0);
  CHECK(ker_udp_endpoint_bind(&endpoints, rte_cpu_to_be_16(9002),
                              endpoint_receive, NULL) == -ENOSPC);
  struct sk_buff *udp = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == 3);
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9001),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == 4);
  endpoint_drop = 1;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == 5 && fallback_seen == 0);
  CHECK(endpoint_reentrant_bind == -EBUSY &&
        endpoint_reentrant_disable == -EBUSY &&
        endpoint_reentrant_connect == -EBUSY &&
        endpoint_reentrant_disconnect == -EBUSY &&
        endpoint_reentrant_close == -EBUSY &&
        brx_transport.validation_error == 0 && brt.callback_error == 0);
  endpoint_drop = 0;
  endpoint_table_under_test = NULL;
  endpoint_status = 19;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(brx_transport.validation_error == -EPROTO && fallback_seen == 0 &&
        brt.callback_error == -EPROTO);
  endpoint_status = NET_RX_SUCCESS;
  unsigned int seen_before_invalid = endpoint_seen;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  udp->data[ETH_HLEN + 20 + 6] ^= 1; /* Corrupt the UDP checksum. */
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid && fallback_seen == 0 &&
        brx_transport.validation_error == -EBADMSG);
  static const unsigned char udp_options[4] = {1, 1, 1, 1};
  CHECK(ker_udp_ipv4_create_ip_options(
            &actx, amac, bmac, aip, bip, rte_cpu_to_be_16(40000),
            rte_cpu_to_be_16(9000), 64, udp_options, sizeof(udp_options),
            payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid);
  CHECK(fallback_seen == 0);
  CHECK(brx_transport.validation_error == -EOPNOTSUPP);
  for (unsigned int unsupported = 0; unsupported < 3; ++unsupported) {
    CHECK(ker_udp_ipv4_create_configured(&aaddr, bmac, bip,
                                         rte_cpu_to_be_16(40000),
                                         rte_cpu_to_be_16(9000), 64, NULL, 0,
                                         payload, sizeof(payload), &udp) == 0);
    unsigned char *ip = skb_network_header(udp);
    if (unsupported == 0)
      ip[8] = 0; /* TTL zero. */
    else if (unsupported == 1)
      ip[6] |= 0x80; /* Reserved fragment flag. */
    else
      ip[6] |= 0x20; /* More fragments requires reassembly. */
    refresh_ip_checksum(udp);
    inject_request(udp);
    CHECK(endpoint_seen == seen_before_invalid && fallback_seen == 0 &&
          brx_transport.validation_error == -EOPNOTSUPP);
  }
  CHECK(ker_udp_ipv4_create(&actx, amac, bmac, rte_cpu_to_be_32(0x00010203),
                            bip, rte_cpu_to_be_16(40000),
                            rte_cpu_to_be_16(9000), 64, payload,
                            sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid && fallback_seen == 0 &&
        brx_transport.validation_error == -EOPNOTSUPP);
  CHECK(ker_udp_ipv4_create(&actx, amac, bmac, aip,
                            rte_cpu_to_be_32(0xc0000209),
                            rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000), 64,
                            payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid && fallback_seen == 0 &&
        brx_transport.validation_error == -EOPNOTSUPP);
  CHECK(ker_udp_ipv4_create(&actx, amac, broadcast, aip,
                            rte_cpu_to_be_32(0xffffffff),
                            rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000), 64,
                            payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid && fallback_seen == 0 &&
        brx_transport.validation_error == -EOPNOTSUPP);
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  unsigned char *udp_header = skb_network_header(udp) + 20;
  udp_header[6] = udp_header[7] = 0; /* IPv4 permits omitted UDP checksum. */
  inject_request(udp);
  CHECK(endpoint_seen == seen_before_invalid + 1 && fallback_seen == 0 &&
        brx_transport.validation_error == 0);
  CHECK(ker_udp_endpoint_unbind(&endpoints, rte_cpu_to_be_16(9000)) == 0);
  CHECK(ker_udp_endpoint_close(&endpoints, endpoint_handle) == -ESTALE);
  struct ker_udp_endpoint_handle rebound_handle;
  CHECK(ker_udp_endpoint_bind_ex(&endpoints, rte_cpu_to_be_16(9000),
                                 endpoint_receive, NULL,
                                 &rebound_handle) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40000)) == -ESTALE);
  CHECK(ker_udp_endpoint_close(&endpoints, endpoint_handle) == -ESTALE);
  CHECK(ker_udp_endpoint_close(&endpoints, rebound_handle) == 0);
  CHECK(ker_udp_endpoint_unbind(&endpoints, rte_cpu_to_be_16(9001)) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == 0);
  struct ker_udp_endpoint cycle_entries[2] = {0};
  CHECK(ker_udp_endpoint_table_enable(&endpoints, &brx_transport, &service,
                                      cycle_entries, 2) == 0);
  struct ker_udp_endpoint_handle cycle_handle;
  CHECK(ker_udp_endpoint_bind_ex(&endpoints, rte_cpu_to_be_16(9000),
                                 endpoint_receive, NULL, &cycle_handle) == 0);
  CHECK(ker_udp_endpoint_close(&endpoints, endpoint_handle) == -ESTALE);
  struct ker_udp_endpoint_handle overflow_out = {
      .table = &endpoints, .slot = 17, .generation = 23};
  endpoints.next_generation = UINT64_MAX;
  CHECK(ker_udp_endpoint_bind_ex(&endpoints, rte_cpu_to_be_16(9001),
                                 endpoint_receive, NULL,
                                 &overflow_out) == -EOVERFLOW);
  CHECK(endpoints.count == 1 && !cycle_entries[1].receive &&
        overflow_out.table == &endpoints && overflow_out.slot == 17 &&
        overflow_out.generation == 23);
  CHECK(ker_udp_endpoint_close(&endpoints, cycle_handle) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == 0);
  struct ker_udp_endpoint_table second_table = {0};
  struct ker_udp_endpoint second_entries[1] = {0};
  CHECK(ker_udp_endpoint_table_enable(&second_table, &brx_transport, &service,
                                      second_entries, 1) == 0);
  CHECK(ker_udp_endpoint_connect(&second_table, endpoint_handle, aip,
                                 rte_cpu_to_be_16(40000)) == -ESTALE);
  CHECK(ker_udp_endpoint_bind(&second_table, rte_cpu_to_be_16(9000),
                              endpoint_receive, NULL) == 0);
  unsigned int before_second_table = endpoint_seen;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9000),
            64, NULL, 0, payload, sizeof(payload), &udp) == 0);
  inject_request(udp);
  CHECK(endpoint_seen == before_second_table + 1 && fallback_seen == 0);
  CHECK(ker_udp_endpoint_unbind(&second_table, rte_cpu_to_be_16(9000)) == 0);
  CHECK(ker_udp_endpoint_table_disable(&second_table) == 0);
  CHECK(ker_icmpv4_service_disable(&service) == 0);
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
  struct ker_udp_endpoint_table closed_table = {0};
  struct ker_udp_endpoint closed_entries[1] = {0};
  CHECK(ker_udp_endpoint_table_enable(&closed_table, &brx_transport, &service,
                                      closed_entries, 1) == 0);
  unsigned int errors_before_closed = emitted_errors;
  struct sk_buff *closed_udp = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9001),
            64, NULL, 0, payload, sizeof(payload), &closed_udp) == 0);
  expected_endpoint_quote_length = 20 + 8 + sizeof(payload);
  memcpy(expected_endpoint_quote, skb_network_header(closed_udp),
         expected_endpoint_quote_length);
  inject_request(closed_udp);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0);
  CHECK(emitted_errors == errors_before_closed + 1 && fallback_seen == 0);
  struct ker_udp_endpoint_handle mismatch_handle;
  CHECK(ker_udp_endpoint_bind_ex(&closed_table, rte_cpu_to_be_16(9001),
                                 endpoint_receive, NULL,
                                 &mismatch_handle) == 0);
  CHECK(ker_udp_endpoint_connect(&closed_table, mismatch_handle, aip,
                                 rte_cpu_to_be_16(40000)) == 0);
  struct sk_buff *wrong_source_port = NULL;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40001),
            rte_cpu_to_be_16(9001), 64, NULL, 0, payload, sizeof(payload),
            &wrong_source_port) == 0);
  unsigned int mismatch_errors_before = emitted_errors;
  expected_endpoint_quote_length = 20 + 8 + sizeof(payload);
  memcpy(expected_endpoint_quote, skb_network_header(wrong_source_port),
         expected_endpoint_quote_length);
  inject_request(wrong_source_port);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && emitted_errors == mismatch_errors_before + 1 &&
        fallback_seen == 0);
  CHECK(ker_udp_endpoint_unbind(&closed_table, rte_cpu_to_be_16(9001)) == 0);
  unsigned int unknown_errors_before = emitted_errors;
  expected_emitted_type = 3;
  expected_emitted_code = 2;
  const uint8_t selected_protocols[] = {0, 31, 32, 253, 255};
  for (unsigned int i = 0; i < sizeof(selected_protocols); ++i) {
    inject_unknown_protocol(selected_protocols[i]);
    result = poll_worker(&bworker);
    CHECK(result.tx == 1 && result.rx == 0);
    result = poll_worker(&aworker);
    CHECK(result.rx == 1 && result.tx == 0);
    CHECK(emitted_errors == unknown_errors_before + i + 1 &&
          brx_transport.validation_error == -EPROTONOSUPPORT);
  }
  uint64_t selected_errors_submitted = service.errors_submitted;
  unsigned int selected_emitted_before_pressure = emitted_errors;
  unsigned int unknown_pool_available;
  CHECK(ker_packet_pool_available(&bpool, &unknown_pool_available) == 0);
  struct rte_mbuf *unknown_held[128];
  unsigned int unknown_held_count = 0;
  while (unknown_pool_available > 1) {
    CHECK(unknown_held_count < sizeof(unknown_held) / sizeof(unknown_held[0]));
    unknown_held[unknown_held_count] = ker_packet_alloc(&bpool);
    CHECK(unknown_held[unknown_held_count] != NULL);
    ++unknown_held_count;
    --unknown_pool_available;
  }
  inject_unknown_protocol(253);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 && service.last_error == -ENOMEM &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        service.errors_submitted == selected_errors_submitted &&
        emitted_errors == selected_emitted_before_pressure);
  expected_endpoint_quote_length = 0;
  for (unsigned int i = 0; i < unknown_held_count; ++i)
    ker_packet_free(unknown_held[i]);
  unsigned int unknown_pool_restored;
  CHECK(ker_packet_pool_available(&bpool, &unknown_pool_restored) == 0 &&
        unknown_pool_restored == unknown_pool_available + unknown_held_count);
  inject_unknown_protocol(253);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0 && service.last_error == 0 &&
        service.errors_submitted == selected_errors_submitted + 1 &&
        emitted_errors == selected_emitted_before_pressure + 1);

  unsigned int unknown_emitted_before_rate = emitted_errors;
  uint64_t unknown_errors_before_rate = service.errors_submitted;
  unsigned int tokens_before_unknown_rate = service.tokens;
  service.tokens = 0;
  inject_unknown_protocol(253);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 && service.last_error == -EAGAIN &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        service.errors_submitted == unknown_errors_before_rate &&
        emitted_errors == unknown_emitted_before_rate);
  expected_endpoint_quote_length = 0;
  service.tokens = tokens_before_unknown_rate;
  inject_unknown_protocol(253);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0 && service.last_error == 0 &&
        service.errors_submitted == unknown_errors_before_rate + 1 &&
        emitted_errors == unknown_emitted_before_rate + 1);
  unsigned int unknown_errors_after_selected = emitted_errors;
  int unknown_last_error = service.last_error;
  inject_unknown_protocol_fields(100, 64, 0, false);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        emitted_errors == unknown_errors_after_selected &&
        service.last_error == unknown_last_error);
  const uint16_t suppressed_fragments[] = {0x2000, 0x8000, 1};
  for (unsigned int i = 0; i < sizeof(suppressed_fragments) /
                                  sizeof(suppressed_fragments[0]); ++i) {
    inject_unknown_protocol_fields(253, 64, suppressed_fragments[i], false);
    result = poll_worker(&bworker);
    CHECK(result.rx == 0 && result.tx == 0 &&
          brx_transport.validation_error == -EPROTONOSUPPORT &&
          emitted_errors == unknown_errors_after_selected &&
          service.last_error == -ENOTSUP);
  }
  inject_unknown_protocol_fields(253, 0, 0, false);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        emitted_errors == unknown_errors_after_selected &&
        service.last_error == -ENOTSUP);
  inject_unknown_protocol_fields(253, 64, 0x4000, true); /* DF is allowed. */
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0 &&
        emitted_errors == unknown_errors_after_selected + 1 &&
        brx_transport.validation_error == -EPROTONOSUPPORT);
  inject_unknown_bad_checksum();
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EBADMSG &&
        emitted_errors == unknown_errors_after_selected + 1);
  inject_unknown_options();
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        service.last_error == -ENOTSUP &&
        emitted_errors == unknown_errors_after_selected + 1);
  expected_emitted_code = 3;
  unsigned int available_before_pressure;
  CHECK(ker_packet_pool_available(&bpool, &available_before_pressure) == 0);
  struct rte_mbuf *held_bpool[128];
  unsigned int endpoint_pressure_held = 0;
  unsigned int available_now = available_before_pressure;
  while (available_now > 1) {
    CHECK(endpoint_pressure_held < sizeof(held_bpool) / sizeof(held_bpool[0]));
    held_bpool[endpoint_pressure_held] = ker_packet_alloc(&bpool);
    CHECK(held_bpool[endpoint_pressure_held] != NULL);
    ++endpoint_pressure_held;
    --available_now;
  }
  uint64_t errors_before_pool_failure = service.errors_submitted;
  unsigned int emitted_before_pool_failure = emitted_errors;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000),
            rte_cpu_to_be_16(9003), 64, NULL, 0, payload, sizeof(payload),
            &closed_udp) == 0);
  inject_request(closed_udp);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0);
  CHECK(service.errors_submitted == errors_before_pool_failure &&
        service.last_error == -ENOMEM &&
        emitted_errors == emitted_before_pool_failure && fallback_seen == 0);
  for (unsigned int i = 0; i < endpoint_pressure_held; ++i)
    ker_packet_free(held_bpool[i]);
  unsigned int available_after_pressure;
  CHECK(ker_packet_pool_available(&bpool, &available_after_pressure) == 0);
  CHECK(available_after_pressure == available_before_pressure);
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000),
            rte_cpu_to_be_16(9003), 64, NULL, 0, payload, sizeof(payload),
            &closed_udp) == 0);
  expected_endpoint_quote_length = 20 + 8 + sizeof(payload);
  memcpy(expected_endpoint_quote, skb_network_header(closed_udp),
         expected_endpoint_quote_length);
  inject_request(closed_udp);
  result = poll_worker(&bworker);
  CHECK(result.tx == 1 && result.rx == 0);
  result = poll_worker(&aworker);
  CHECK(result.rx == 1 && result.tx == 0);
  CHECK(service.errors_submitted == errors_before_pool_failure + 1 &&
        emitted_errors == emitted_before_pool_failure + 1 && fallback_seen == 0);
  service.tokens = 0;
  CHECK(ker_udp_ipv4_create_configured(
            &aaddr, bmac, bip, rte_cpu_to_be_16(40000), rte_cpu_to_be_16(9002),
            64, NULL, 0, payload, sizeof(payload), &closed_udp) == 0);
  inject_request(closed_udp);
  result = poll_worker(&bworker);
  CHECK(result.tx == 0 && result.rx == 0);
  CHECK(emitted_errors == emitted_before_pool_failure + 1 &&
        fallback_seen == 0);
  service.tokens = service.config.burst;
  CHECK(ker_udp_endpoint_table_disable(&closed_table) == 0);

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
  unsigned char timestamp_body[13] = {0};
  memcpy(timestamp_body, &originate, 4);
  struct sk_buff *timestamp_request = NULL;
  const unsigned int invalid_timestamp_lengths[] = {11, 13};
  for (unsigned int i = 0; i < sizeof(invalid_timestamp_lengths) /
                                   sizeof(invalid_timestamp_lengths[0]);
       ++i) {
    unsigned int received_before = service.received;
    unsigned int dropped_before = service.dropped;
    uint64_t tokens_before = service.tokens;
    unsigned int replies_before = service.replies_submitted;
    CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 13, 0,
                                 timestamp_rest, 64, timestamp_body,
                                 sizeof(timestamp_body) - 1,
                                 &timestamp_request) == 0);
    unsigned char *timestamp_ip = timestamp_request->data + ETH_HLEN;
    unsigned char *timestamp_icmp = timestamp_ip + 20;
    if (invalid_timestamp_lengths[i] == 11)
      CHECK(ker_skb_trim(timestamp_request, timestamp_request->len - 1) == 0);
    if (invalid_timestamp_lengths[i] == 13) {
      unsigned char *extra = NULL;
      CHECK(ker_skb_put(timestamp_request, 1, &extra) == 0);
      *extra = 0;
    }
    unsigned int timestamp_wire_length = 20 + 8 + invalid_timestamp_lengths[i];
    timestamp_ip[2] = (unsigned char)(timestamp_wire_length >> 8);
    timestamp_ip[3] = (unsigned char)timestamp_wire_length;
    refresh_ip_checksum(timestamp_request);
    timestamp_icmp[2] = timestamp_icmp[3] = 0;
    __sum16 icmp_sum = csum_fold(
        csum_partial(timestamp_icmp, 8 + (int)invalid_timestamp_lengths[i], 0));
    memcpy(timestamp_icmp + 2, &icmp_sum, sizeof(icmp_sum));
    inject_request(timestamp_request);
    CHECK(service.received == received_before &&
          service.dropped == dropped_before &&
          service.tokens == tokens_before &&
          service.replies_submitted == replies_before);
  }
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 13, 0,
                               timestamp_rest, 64, timestamp_body,
                               sizeof(timestamp_body) - 1,
                               &timestamp_request) == 0);
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
  CHECK(ker_icmpv4_ipv4_create(&actx, amac, bmac, aip, bip, 13, 0,
                               timestamp_rest, 64, timestamp_body,
                               sizeof(timestamp_body) - 1,
                               &timestamp_request) == 0);
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
  uint64_t errors_before_borrowed = service.errors_submitted;
  unsigned int emitted_before_borrowed = emitted_errors;
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
  CHECK(service.errors_submitted == errors_before_borrowed + 1 &&
        borrowed->len == sizeof(borrowed_copy) &&
        !memcmp(borrowed_copy, borrowed->data, borrowed->len));
  struct ker_ipv4_packet_view borrowed_view;
  CHECK(ker_ipv4_packet_view_init(&bctx, borrowed, &borrowed_view) == 0);
  BUG_ON(ker_skb_free(borrowed));
  pressure_result = poll_worker(&bworker);
  CHECK(pressure_result.tx == 1 && pressure_result.rx == 0);
  pressure_result = poll_worker(&aworker);
  CHECK(pressure_result.rx == 1 &&
        emitted_errors == emitted_before_borrowed + 1);

  expect_emitted_error(3, 4, 1400);
  expect_emitted_error(11, 0, 0);
  expect_emitted_error(12, 0, 4);
  CHECK(emitted_errors == emitted_before_borrowed + 4 &&
        service.errors_submitted == errors_before_borrowed + 4);

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

  unsigned int errors_before_competitor = emitted_errors;
  CHECK(ker_protocol_register(&brt, &competing_ip, &bdev,
                              rte_cpu_to_be_16(ETH_P_IP),
                              consume_competing_ip, NULL) == 0);
  inject_unknown_protocol_fields(253, 64, 0, false); /* after receiver */
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        service.last_error == -EOPNOTSUPP &&
        emitted_errors == errors_before_competitor);
  CHECK(ker_protocol_unregister(&competing_ip) == 0);

  CHECK(ker_icmpv4_service_disable(&service) == 0);
  unsigned int errors_before_disabled = emitted_errors;
  inject_unknown_protocol_fields(253, 64, 0, false);
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        emitted_errors == errors_before_disabled);
  CHECK(ker_transport_receiver_unregister(&brx_transport) == 0);
  CHECK(ker_protocol_register(&brt, &competing_ip, &bdev,
                              rte_cpu_to_be_16(ETH_P_IP),
                              consume_competing_ip, NULL) == 0);
  CHECK(ker_transport_receiver_register(&brx_transport, &brt, &bdev, fallback,
                                        NULL) == 0);
  CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                  &service_config) == 0);
  inject_unknown_protocol_fields(253, 64, 0, false); /* receiver after device */
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EBUSY && service.last_error == 0 &&
        emitted_errors == errors_before_competitor);
  CHECK(ker_icmpv4_service_disable(&service) == 0);
  CHECK(ker_transport_receiver_unregister(&brx_transport) == 0);
  CHECK(ker_protocol_unregister(&competing_ip) == 0);

  CHECK(ker_protocol_register(&brt, &competing_ip, NULL,
                              rte_cpu_to_be_16(ETH_P_IP),
                              consume_competing_ip, NULL) == 0);
  CHECK(ker_transport_receiver_register(&brx_transport, &brt, &bdev, fallback,
                                        NULL) == 0);
  CHECK(ker_icmpv4_service_enable(&service, &brx_transport, &bmonitor,
                                  &service_config) == 0);
  inject_unknown_protocol_fields(253, 64, 0, false); /* receiver after global */
  result = poll_worker(&bworker);
  CHECK(result.rx == 0 && result.tx == 0 &&
        brx_transport.validation_error == -EPROTONOSUPPORT &&
        service.last_error == -EOPNOTSUPP &&
        emitted_errors == errors_before_competitor);

  CHECK(ker_icmpv4_service_disable(&service) == 0);
  CHECK(ker_transport_receiver_unregister(&brx_transport) == 0);
  CHECK(ker_protocol_unregister(&competing_ip) == 0);
  CHECK(ker_transport_receiver_register(&brx_transport, &brt, &bdev, fallback,
                                        NULL) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&bmonitor) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&amonitor) == 0);
  CHECK(ker_arp_receiver_unregister(&barp) == 0);
  CHECK(ker_arp_responder_unregister(&aresponder) == 0);
  CHECK(ker_transport_receiver_unregister(&arx_transport) == 0);
  CHECK(ker_transport_receiver_unregister(&brx_transport) == 0);
  CHECK(ker_rx_ring_cleanup(&arx) == 0 && ker_rx_ring_cleanup(&brx) == 0);
  CHECK(ker_worker_cleanup(&bworker) == 0 && ker_worker_cleanup(&aworker) == 0);
  CHECK(ker_neighbor_table_cleanup(&bneighbors) == 0);
  CHECK(ker_neighbor_table_cleanup(&aneighbors) == 0);
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
