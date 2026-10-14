#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/ethernet.h"
#include "runtime/icmpv4-service.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-io.h"
#include "runtime/worker.h"
#include <errno.h>
#include <string.h>

#define POOL_SIZE 127U
#define LOCAL_PORT 9000U

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor peer_a, peer_b;
static struct ker_receive_runtime receive_runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct ker_tx_export tx;
static struct ker_tx_ring output_ring, input_ring;
static struct ker_rx_ring rx;
static struct ker_icmpv4_service icmp;
static struct ker_udp_endpoint_table endpoints;
static struct ker_udp_endpoint endpoint_slots[2];
static struct ker_udp_io io;
static struct ker_udp_io_peer peer_slots[2];
static struct ker_udp_channel channel;
static struct ker_udp_channel_slot datagrams[2];
static unsigned char payload_slab[8];
static const unsigned char local_mac[ETH_ALEN] = {2, 0x10, 0, 0, 0, 1};
static const unsigned char mac_a[ETH_ALEN] = {2, 0x20, 0, 0, 0, 1};
static const unsigned char mac_b[ETH_ALEN] = {2, 0x30, 0, 0, 0, 1};
static const __be32 local_ip = (__be32)0x010200c0;
static const __be32 ip_a = (__be32)0x020200c0;
static const __be32 ip_b = (__be32)0x030200c0;
static const __be32 ip_unregistered = (__be32)0x040200c0;
static const __be16 source_port = (__be16)0x401f;
static const __be16 local_port = (__be16)0x2823;
static uint32_t configured_mtu;
static bool test_mtu_reentry;
static int mtu_calls, positive_mtu_call;
static int reenter_channel_close, reenter_io_cleanup, reenter_endpoint_close;

static uint64_t clock_ms(void *arg) { (void)arg; return 100; }
static void monitor_probe(const struct ker_neighbor_event *event, void *arg) {
  (void)event;
  (void)arg;
}
static int path_mtu(void *arg, uint32_t *out) {
  (void)arg;
  ++mtu_calls;
  if (test_mtu_reentry) {
    reenter_channel_close = ker_udp_channel_close(&channel);
    reenter_io_cleanup = ker_udp_io_cleanup(&io);
    reenter_endpoint_close = ker_udp_endpoint_close(&endpoints,
                                                     channel.endpoint);
  }
  *out = configured_mtu;
  return mtu_calls == positive_mtu_call ? 1 : 0;
}
static int receive_message(const struct ker_transport_message *message,
                           void *arg) {
  (void)message;
  (void)arg;
  return NET_RX_SUCCESS;
}
struct worker_context { struct ker_tx_export *tx; struct ker_rx_ring *rx; };
static int tx_poll(void *arg, unsigned int budget) {
  return ker_tx_export_poll(((struct worker_context *)arg)->tx, budget);
}
static int rx_poll(void *arg, unsigned int budget) {
  return ker_rx_ring_poll(((struct worker_context *)arg)->rx, budget);
}

static void inject_udp(__be32 peer_ip, const unsigned char peer_mac[ETH_ALEN],
                       __be16 peer_port, const unsigned char *bytes,
                       size_t length) {
  struct sk_buff *skb = NULL;
  CHECK(ker_udp_ipv4_create(&context, peer_mac, local_mac, peer_ip, local_ip,
      peer_port, local_port, 64, bytes, (unsigned int)length, &skb) == 0);
  struct rte_mbuf *frame = ker_packet_alloc(&pool);
  CHECK(frame);
  unsigned char *data = (unsigned char *)rte_pktmbuf_append(frame,
      (uint16_t)skb->len);
  CHECK(data);
  memcpy(data, skb->data, skb->len);
  CHECK(ker_skb_free(skb) == 0);
  CHECK(ker_tx_ring_sink(frame, &input_ring) == 0);
  CHECK(ker_rx_ring_poll(&rx, 1) == 1);
}

static void check_ring_frame(__be32 expected_ip,
                             const unsigned char *expected_mac,
                             const unsigned char *payload, size_t length) {
  struct rte_mbuf *frame = NULL;
  CHECK(ker_tx_ring_take(&output_ring, &frame) == 1 && frame);
  unsigned char bytes[ETH_HLEN + 20 + 8 + 32];
  CHECK(frame->pkt_len == ETH_HLEN + 20 + 8 + length && frame->pkt_len <= sizeof(bytes));
  const unsigned char *data = rte_pktmbuf_read(frame, 0, frame->pkt_len, bytes);
  CHECK(data);
  if (data != bytes)
    memcpy(bytes, data, frame->pkt_len);
  CHECK(!memcmp(bytes, expected_mac, ETH_ALEN));
  CHECK(!memcmp(bytes + ETH_HLEN + 16, &expected_ip, sizeof(expected_ip)));
  if (length)
    CHECK(!memcmp(bytes + ETH_HLEN + 20 + 8, payload, length));
  CHECK(bytes[ETH_HLEN + 6] == 0x40 && bytes[ETH_HLEN + 7] == 0);
  CHECK(bytes[ETH_HLEN + 8] == 64);
  ker_packet_free(frame);
}
static void check_output(__be32 expected_ip, const unsigned char *expected_mac,
                         const unsigned char *payload, size_t length) {
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && !tx.last_error);
  check_ring_frame(expected_ip, expected_mac, payload, length);
}

int main(void) {
  ker_test_eal_init();
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  CHECK(ker_packet_pool_init(&pool, "udp_io", POOL_SIZE, 0, 4096,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&context, &pool, "udp_io_skb") == 0);
  CHECK(ker_eth_device_init(&device, &context, "udp_io0", 30, local_mac) == 0);
  CHECK(ker_arp_device_setup(&device) == 0);
  CHECK(ker_ipv4_address_init(&address, &device, local_ip, 24) == 0);
  CHECK(ker_neighbor_table_init(&neighbors, &address, "udp_io_neigh", 4, 2) == 0);
  const struct ker_neighbor_config neighbor_config = {
      .retrans_ticks = 20, .reachable_ticks = 100, .delay_ticks = 30,
      .ucast_probes = 2, .mcast_probes = 2, .mcast_reprobes = 1,
      .queue_bytes = 8192};
  CHECK(ker_neighbor_configure(&neighbors, &neighbor_config) == 0);
  CHECK(ker_neighbor_add(&neighbors, ip_a, mac_a) == 0);
  CHECK(ker_neighbor_add(&neighbors, ip_b, mac_b) == 0);
  CHECK(ker_tx_ring_init(&output_ring, "udp_io_out", 1, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_ring_init(&input_ring, "udp_io_in", 8, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init(&tx, &context, 2, 16384, ker_tx_ring_sink,
                           &output_ring) == 0);
  CHECK(ker_receive_runtime_init(&receive_runtime, &context) == 0);
  CHECK(ker_transport_receiver_register(&receiver, &receive_runtime, &device,
                                        receive_message, NULL) == 0);
  CHECK(ker_rx_ring_init(&rx, &input_ring, &device, &receive_runtime, 128) == 0);
  struct ker_worker_config worker_config = {.timer_budget = 1, .tx_budget = 1,
      .rx_budget = 1};
  struct worker_context worker_context = {.tx = &tx, .rx = &rx};
  struct ker_worker_ops worker_ops = {.tx = tx_poll, .rx = rx_poll,
                                      .arg = &worker_context};
  CHECK(ker_worker_init(&worker, &pool, &worker_config, &worker_ops) == 0);
  CHECK(ker_neighbor_monitor_init(&peer_a, &neighbors, &worker.timers, ip_a,
                                  monitor_probe, NULL, NULL) == 0);
  CHECK(ker_neighbor_monitor_init(&peer_b, &neighbors, &worker.timers, ip_b,
                                  monitor_probe, NULL, NULL) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&peer_a, &tx) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&peer_b, &tx) == 0);
  const struct ker_icmpv4_service_config service_config = {
      .ttl = 64, .burst = 8, .refill_ms = 100,
      .monotonic_ms = clock_ms};
  CHECK(ker_icmpv4_service_enable(&icmp, &receiver, &peer_a,
                                  &service_config) == 0);
  CHECK(ker_udp_endpoint_table_enable(&endpoints, &receiver, &icmp,
                                       endpoint_slots, 2) == 0);
  CHECK(ker_udp_io_init(&io, &receiver, &icmp, &endpoints, peer_slots, 2, 64) == 0);
  CHECK(ker_udp_io_register_peer(&io, &peer_a) == 0);
  CHECK(ker_udp_io_register_peer(&io, &peer_b) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == -EBUSY);
  CHECK(ker_neighbor_monitor_resolution_disable(&peer_a) == -EBUSY);
  CHECK(ker_neighbor_monitor_cleanup(&peer_a) == -EBUSY);
  struct ker_udp_endpoint_handle untouched = {&endpoints, 7, 9};
  CHECK(ker_udp_channel_open(&channel, &io, local_port, datagrams,
      payload_slab, SIZE_MAX, 4, 4, &untouched) == -EOVERFLOW);
  CHECK(untouched.table == &endpoints && untouched.slot == 7 &&
        untouched.generation == 9);
  CHECK(ker_udp_channel_open(&channel, &io, local_port, datagrams,
      payload_slab, 2, 4, 4, &untouched) == 0);
  CHECK(ker_udp_io_cleanup(&io) == -EBUSY);

  const unsigned char send_a[] = {0xa1, 0xa2};
  const unsigned char send_b[] = {0xb1};
  CHECK(ker_udp_send(&channel, send_a, sizeof(send_a)) == -ENOTCONN);
  CHECK(ker_udp_sendto(&channel, ip_unregistered, source_port, send_a,
                       sizeof(send_a)) == -EHOSTUNREACH);
  CHECK(ker_udp_endpoint_connect(&endpoints, channel.endpoint, ip_a,
                                 source_port) == 0);
  CHECK(ker_udp_send(&channel, send_a, sizeof(send_a)) == 0);
  check_output(ip_a, mac_a, send_a, sizeof(send_a));
  /* Linux-style explicit sendto may override a connected peer for that send;
   * the endpoint's receive filter remains connected to peer A. */
  CHECK(ker_udp_sendto(&channel, ip_b, source_port, send_b,
                       sizeof(send_b)) == 0);
  check_output(ip_b, mac_b, send_b, sizeof(send_b));
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, NULL, 0) == 0);
  check_output(ip_a, mac_a, NULL, 0);
  configured_mtu = 68;
  peer_a.output_mtu = path_mtu;
  test_mtu_reentry = true;
  const unsigned char too_large[41] = {0};
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, too_large,
                       sizeof(too_large)) == -EMSGSIZE);
  CHECK(reenter_channel_close == -EBUSY && reenter_io_cleanup == -EBUSY &&
        reenter_endpoint_close == -EBUSY);
  test_mtu_reentry = false;
  peer_a.output_mtu = NULL;

  /* A positive status from the monitor's second MTU preflight must not escape
   * as a successful send when the constructed packet remains caller-owned. */
  configured_mtu = 1500;
  mtu_calls = 0;
  positive_mtu_call = 2;
  peer_a.output_mtu = path_mtu;
  size_t before_positive_mtu = context.live;
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, send_a,
                       sizeof(send_a)) == -EPROTO);
  CHECK(context.live == before_positive_mtu);
  peer_a.output_mtu = NULL;
  positive_mtu_call = 0;

  /* A full output ring keeps the exact original skb pending for retry. */
  struct rte_mbuf *filler = ker_packet_alloc(&pool);
  CHECK(filler && rte_pktmbuf_append(filler, 1));
  CHECK(ker_tx_ring_sink(filler, &output_ring) == 0);
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, send_a,
                       sizeof(send_a)) == 0);
  CHECK(ker_tx_export_poll(&tx, 1) == -EAGAIN && tx.pending &&
        tx.last_error == -EAGAIN);
  struct rte_mbuf *taken = NULL;
  CHECK(ker_tx_ring_take(&output_ring, &taken) == 1 && taken == filler);
  ker_packet_free(taken);
  CHECK(ker_tx_export_poll(&tx, 1) == 1 && !tx.pending);
  check_ring_frame(ip_a, mac_a, send_a, sizeof(send_a));

  /* The bounded export queue rejects the third skb atomically and releases
   * its constructor allocation; the two already accepted packets still drain. */
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, send_a,
                       sizeof(send_a)) == 0);
  CHECK(ker_udp_sendto(&channel, ip_b, source_port, send_b,
                       sizeof(send_b)) == 0);
  size_t queued_live = context.live;
  CHECK(ker_udp_sendto(&channel, ip_a, source_port, send_a,
                       sizeof(send_a)) == -ENOSPC);
  CHECK(context.live == queued_live && tx.packets == 2);
  check_output(ip_a, mac_a, send_a, sizeof(send_a));
  check_output(ip_b, mac_b, send_b, sizeof(send_b));

  const unsigned char input[] = {1, 2, 3, 4, 5};
  inject_udp(ip_a, mac_a, source_port, input, sizeof(input));
  inject_udp(ip_a, mac_a, source_port, NULL, 0);
  inject_udp(ip_a, mac_a, source_port, input, 1);
  CHECK(channel.count == 2 && channel.bytes == 4 && channel.dropped_full == 1);
  unsigned char out[8] = {0};
  struct ker_udp_datagram_info info = {0};
  CHECK(ker_udp_channel_recv(&channel, out, 2, KER_UDP_RECV_PEEK, &info) == 1);
  CHECK(info.local_address == local_ip && info.peer_address == ip_a &&
        info.local_port == local_port && info.peer_port == source_port &&
        info.original_length == sizeof(input) && info.copied_length == 2 &&
        info.truncated && !memcmp(out, input, 2) && channel.count == 2);
  memset(out, 0, sizeof(out));
  CHECK(ker_udp_channel_recv(&channel, out, sizeof(out), 0, &info) == 1);
  CHECK(info.original_length == sizeof(input) && info.copied_length == 4 &&
        info.truncated && !memcmp(out, input, 4));
  CHECK(ker_udp_channel_recv(&channel, out, sizeof(out), 0, &info) == 1);
  CHECK(info.original_length == 0 && info.copied_length == 0 && !info.truncated);
  CHECK(ker_udp_channel_recv(&channel, out, sizeof(out), 0, &info) == 0);
  /* A byte cap smaller than the two-slot slab rejects the second datagram
   * while one slot is still free, then admits data again after consumption. */
  inject_udp(ip_a, mac_a, source_port, input, 4);
  inject_udp(ip_a, mac_a, source_port, input, 1);
  CHECK(channel.count == 1 && channel.bytes == 4 && channel.dropped_full == 2);
  CHECK(ker_udp_channel_recv(&channel, out, sizeof(out), 0, &info) == 1);
  inject_udp(ip_a, mac_a, source_port, input, 1);
  CHECK(channel.count == 1 && channel.bytes == 1);
  CHECK(ker_udp_channel_recv(&channel, out, sizeof(out), 0, &info) == 1);

  /* An externally closed generation stops delivery; channel close still
   * releases the caller-owned inbox and io pin without closing a reused slot. */
  CHECK(ker_udp_endpoint_close(&endpoints, channel.endpoint) == 0);
  CHECK(ker_udp_channel_close(&channel) == 0);
  CHECK(ker_udp_io_unregister_peer(&io, &peer_b) == 0);
  CHECK(ker_udp_io_unregister_peer(&io, &peer_a) == 0);
  CHECK(ker_udp_io_cleanup(&io) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&icmp) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&peer_b) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&peer_a) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&peer_b) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&peer_a) == 0);
  CHECK(ker_transport_receiver_unregister(&receiver) == 0);
  CHECK(ker_rx_ring_cleanup(&rx) == 0);
  CHECK(ker_receive_runtime_cleanup(&receive_runtime) == 0);
  CHECK(ker_worker_cleanup(&worker) == 0);
  CHECK(ker_tx_export_cleanup(&tx) == 0);
  CHECK(ker_tx_ring_cleanup(&input_ring) == 0);
  CHECK(ker_tx_ring_cleanup(&output_ring) == 0);
  CHECK(ker_neighbor_remove(&neighbors, ip_b) == 0);
  CHECK(ker_neighbor_remove(&neighbors, ip_a) == 0);
  CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
  CHECK(ker_ipv4_address_cleanup(&address) == 0);
  CHECK(ker_eth_device_cleanup(&device) == 0);
  CHECK(ker_skb_context_cleanup(&context) == 0);
  CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_SIZE);
  CHECK(ker_packet_pool_cleanup(&pool) == 0);
  CHECK(ker_memory_shutdown() == 0);
  CHECK(rte_eal_cleanup() == 0);
  puts("bounded UDP channel RX and registered-peer send passed");
  return 0;
}
