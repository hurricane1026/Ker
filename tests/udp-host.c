#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-responder.h"
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

#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define POOL_SIZE 127U

static struct ker_packet_pool pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_ipv4_address address;
static struct ker_neighbor_table neighbors;
static struct ker_neighbor_monitor peer_a;
static struct ker_receive_runtime receive_runtime;
static struct ker_transport_receiver receiver;
static struct ker_worker worker;
static struct ker_tx_export tx;
static struct ker_tx_ring input_ring;
static struct ker_rx_ring rx;
static struct ker_icmpv4_service icmp;
static struct ker_udp_endpoint_table endpoints;
static struct ker_udp_endpoint endpoint_slots[2];
static struct ker_udp_io io;
static struct ker_udp_io_peer peer_slots[2];
static struct ker_udp_channel channel;
static struct ker_udp_channel_slot datagrams[2];
static unsigned char payload_slab[2 * 1472];
static const unsigned char local_mac[ETH_ALEN] = {2, 0x10, 0, 0, 0, 1};
static const unsigned char mac_a[ETH_ALEN] = {2, 0x20, 0, 0, 0, 1};
static __be32 local_ip, ip_a;
static __be16 source_port, local_port;
static int tap_fd;
static struct ker_arp_responder responder;
static uint64_t clock_ms(void *arg) {
  (void)arg;
  struct timespec t;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
  return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void monitor_probe(const struct ker_neighbor_event *event, void *arg) {
  (void)event;
  (void)arg;
}
static int receive_message(const struct ker_transport_message *message, void *arg) {
  (void)message;
  (void)arg;
  return NET_RX_SUCCESS;
}
/* TAP writes are frame atomic. Accept ownership only after the whole write. */
static int tap_sink(struct rte_mbuf *frame, void *arg) {
  (void)arg;
  unsigned char bytes[2048];
  if (frame->pkt_len > sizeof(bytes)) return -EMSGSIZE;
  const void *data = rte_pktmbuf_read(frame, 0, frame->pkt_len, bytes);
  if (!data) return -EIO;
  ssize_t n = write(tap_fd, data, frame->pkt_len);
  if (n < 0) return -errno;
  if ((size_t)n != frame->pkt_len) return -EIO;
  ker_packet_free(frame);
  return 0;
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  char *end;
  errno = 0;
  long fd = strtol(argv[1], &end, 10);
  CHECK(!errno && end != argv[1] && !*end && fd >= 0 && fd <= INT_MAX);
  tap_fd = (int)fd;
  CHECK(fcntl(tap_fd, F_SETFL, O_NONBLOCK) == 0);
  local_ip = rte_cpu_to_be_32(0xc0000201);
  ip_a = rte_cpu_to_be_32(0xc0000202);
  source_port = rte_cpu_to_be_16(8000);
  local_port = rte_cpu_to_be_16(9000);
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
  CHECK(ker_tx_ring_init(&input_ring, "udp_io_in", 8, SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init(&tx, &context, 2, 16384, tap_sink,
                           NULL) == 0);
  CHECK(ker_receive_runtime_init(&receive_runtime, &context) == 0);
  CHECK(ker_transport_receiver_register(&receiver, &receive_runtime, &device,
                                        receive_message, NULL) == 0);
  CHECK(ker_rx_ring_init(&rx, &input_ring, &device, &receive_runtime, 128) == 0);
  struct ker_worker_config worker_config = {.timer_budget = 1};
  struct ker_worker_ops worker_ops = {0};
  CHECK(ker_worker_init(&worker, &pool, &worker_config, &worker_ops) == 0);
  CHECK(ker_neighbor_monitor_init(&peer_a, &neighbors, &worker.timers, ip_a,
                                  monitor_probe, NULL, NULL) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&peer_a, &tx) == 0);
  const struct ker_icmpv4_service_config service_config = {
      .ttl = 64, .burst = 8, .refill_ms = 100,
      .monotonic_ms = clock_ms};
  CHECK(ker_icmpv4_service_enable(&icmp, &receiver, &peer_a,
                                  &service_config) == 0);
  CHECK(ker_udp_endpoint_table_enable(&endpoints, &receiver, &icmp,
                                       endpoint_slots, 2) == 0);
  CHECK(ker_udp_io_init(&io, &receiver, &icmp, &endpoints, peer_slots, 2, 64) == 0);
  CHECK(ker_udp_io_register_peer(&io, &peer_a) == 0);
  CHECK(ker_arp_responder_register(&responder, &receive_runtime, &address, &tx) == 0);
  struct ker_udp_endpoint_handle handle;
  CHECK(ker_udp_channel_open(&channel, &io, local_port, datagrams,
      payload_slab, 2, 1472, sizeof(payload_slab), &handle) == 0);
  CHECK(ker_udp_endpoint_connect(&endpoints, handle, ip_a, source_port) == 0);
  unsigned char oversized[1473] = {0};
  CHECK(ker_udp_send(&channel, oversized, sizeof(oversized)) == -EMSGSIZE);
  const char greeting[] = "ker-ready";
  CHECK(ker_udp_send(&channel, greeting, sizeof(greeting) - 1) == 0);
  unsigned int echoed = 0;
  uint64_t deadline = clock_ms(NULL) + 10000;
  while (echoed < 5 || tx.packets) {
    CHECK(clock_ms(NULL) < deadline);
    int sent = ker_tx_export_poll(&tx, 8);
    CHECK(sent >= 0 || sent == -EAGAIN);
    unsigned char frame[2048];
    ssize_t n = read(tap_fd, frame, sizeof(frame));
    if (n < 0) CHECK(errno == EAGAIN || errno == EINTR);
    if (n > 0) {
      struct rte_mbuf *m = ker_packet_alloc(&pool);
      CHECK(m);
      void *data = rte_pktmbuf_append(m, (uint16_t)n);
      CHECK(data);
      memcpy(data, frame, (size_t)n);
      CHECK(ker_tx_ring_sink(m, &input_ring) == 0);
      CHECK(ker_rx_ring_poll(&rx, 1) == 1 && !rx.last_error);
    }
    unsigned char payload[1472];
    struct ker_udp_datagram_info info;
    int received = ker_udp_channel_recv(&channel, payload, sizeof(payload), 0, &info);
    CHECK(received >= 0);
    if (received) {
      CHECK(!info.truncated && info.peer_address == ip_a && info.peer_port == source_port);
      CHECK(ker_udp_send(&channel, payload, info.copied_length) == 0);
      ++echoed;
    }
    struct pollfd event = {.fd = tap_fd, .events = POLLIN};
    CHECK(poll(&event, 1, 1) >= 0 || errno == EINTR);
  }
  CHECK(responder.replies_enqueued > 0);
  CHECK(ker_arp_responder_unregister(&responder) == 0);
  CHECK(ker_udp_channel_close(&channel) == 0);
  CHECK(ker_udp_io_unregister_peer(&io, &peer_a) == 0);
  CHECK(ker_udp_io_cleanup(&io) == 0);
  CHECK(ker_udp_endpoint_table_disable(&endpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&icmp) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&peer_a) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&peer_a) == 0);
  CHECK(ker_transport_receiver_unregister(&receiver) == 0);
  CHECK(ker_rx_ring_cleanup(&rx) == 0);
  CHECK(ker_receive_runtime_cleanup(&receive_runtime) == 0);
  CHECK(ker_worker_cleanup(&worker) == 0);
  CHECK(ker_tx_export_cleanup(&tx) == 0);
  CHECK(ker_tx_ring_cleanup(&input_ring) == 0);
  CHECK(ker_neighbor_remove(&neighbors, ip_a) == 0);
  CHECK(ker_neighbor_table_cleanup(&neighbors) == 0);
  CHECK(ker_ipv4_address_cleanup(&address) == 0);
  CHECK(ker_eth_device_cleanup(&device) == 0);
  CHECK(ker_skb_context_cleanup(&context) == 0);
  CHECK(rte_mempool_avail_count(pool.mbufs) == POOL_SIZE);
  CHECK(ker_packet_pool_cleanup(&pool) == 0);
  CHECK(ker_memory_shutdown() == 0);
  CHECK(rte_eal_cleanup() == 0);
  puts("Linux TAP UDP interoperability passed");
  return 0;
}
