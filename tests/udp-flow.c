#include "check.h"
#include "eal.h"
#include "runtime/arp.h"
#include "runtime/arp-receive.h"
#include "runtime/arp-responder.h"
#include "runtime/ethernet.h"
#include "runtime/flow.h"
#include "runtime/icmpv4-service.h"
#include "runtime/icmpv4-create.h"
#include "runtime/ipv4-address.h"
#include "runtime/memory.h"
#include "runtime/neighbor-timer.h"
#include "runtime/receive.h"
#include "runtime/rx-ring.h"
#include "runtime/skb.h"
#include "runtime/transport-receive.h"
#include "runtime/tx-export.h"
#include "runtime/tx-ring.h"
#include "runtime/udp-create.h"
#include "runtime/udp-flow.h"
#include "runtime/udp-io.h"
#include "runtime/worker.h"
#include <arpa/inet.h>
#include <errno.h>
#include "ker/linux_neighbor_update.h"
#include <pthread.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define DOMAIN UINT64_C(0x554450505258)
#define POOL_COUNT 511U
#define CLIENT_PORT_A 51001U
#define CLIENT_PORT_B 51002U
#define SERVICE_PORT 9000U
#define SERVER_PORT 8000U
#define EPHEMERAL_FIRST 44000U
#define EPHEMERAL_LAST 44100U
#define SPECIAL_PORT 43000U
#define MAX_PAYLOAD 1024U
#define CHANNEL_MAX_DATAGRAM 1400U
struct probe_context {
  struct ker_neighbor_monitor *monitor;
  struct ker_tx_export *tx;
};
struct fixture {
  cpu_set_t allowed;
  int proxy_cpu;
  pthread_t proxy_thread;
  atomic_bool proxy_ready, proxy_stop, proxy_pause, proxy_paused;
  atomic_bool proxy_cleaned, allow_proxy_memory_shutdown;
  atomic_uint proxy_lcore;
  atomic_uint forwarded_upstream, forwarded_clients, pressure_drops;
  atomic_uint proxy_poll_errors, proxy_receive_drops;
  atomic_uint error_events;
  atomic_int pmtu_send_status;
  struct ker_udp_error_event received_error;
  unsigned char upstream_quote[28];
  bool quote_captured;

  struct ker_flow_fabric fabric;
  struct ker_worker client_worker;
  struct ker_flow_context client_flow;
  struct ker_packet_pool client_pool;
  struct ker_skb_context client_skb;
  struct ker_eth_device client_device;
  struct ker_ipv4_address client_address;
  struct ker_neighbor_table client_neighbors;
  struct ker_neighbor_monitor proxy_peer;
  struct ker_receive_runtime client_runtime;
  struct ker_transport_receiver client_receiver;
  struct ker_worker client_io_worker;
  struct ker_tx_ring client_output, client_input;
  struct ker_tx_export client_tx;
  struct ker_rx_ring client_rx;
  struct ker_icmpv4_service client_icmp;
  struct ker_udp_endpoint_table client_endpoints;
  struct ker_udp_endpoint client_endpoint_slots[4];
  struct ker_udp_io client_io;
  struct ker_udp_io_peer client_peer_slots[1];
  struct ker_udp_channel client_a, client_b, upstream_server;
  struct ker_udp_channel_slot client_a_slots[2], client_b_slots[2], server_slots[4];
  unsigned char client_a_payloads[2 * MAX_PAYLOAD];
  unsigned char client_b_payloads[2 * MAX_PAYLOAD];
  unsigned char server_payloads[4 * MAX_PAYLOAD];
  struct ker_arp_responder responder;

  struct ker_packet_pool proxy_pool;
  struct ker_skb_context proxy_skb;
  struct ker_eth_device proxy_device;
  struct ker_ipv4_address proxy_address;
  struct ker_neighbor_table proxy_neighbors;
  struct ker_neighbor_monitor upstream_peer;
  struct ker_receive_runtime proxy_runtime;
  struct ker_transport_receiver proxy_receiver;
  struct ker_arp_receiver proxy_arp_receiver;
  struct ker_worker proxy_worker;
  struct ker_flow_context proxy_flow;
  struct ker_tx_ring proxy_output, proxy_input;
  struct ker_tx_export proxy_tx;
  struct ker_rx_ring proxy_rx;
  struct ker_icmpv4_service proxy_icmp;
  struct ker_udp_endpoint_table proxy_endpoints;
  struct ker_udp_endpoint proxy_endpoint_slots[8];
  struct ker_udp_io proxy_io;
  struct ker_udp_io_peer proxy_peer_slots[1];
  struct ker_udp_error_tracker error_tracker;
  struct ker_udp_error_record error_records[16];
  struct ker_udp_error_peer error_peers[1];
  struct ker_udp_error_event upstream_a_errors[2], upstream_b_errors[2];
  struct ker_udp_error_event listener_errors[2];
  struct ker_udp_channel listener, upstream_a, upstream_b;
  struct ker_udp_channel_slot listener_slots[8], upstream_a_slots[2], upstream_b_slots[2];
  unsigned char listener_payloads[8 * MAX_PAYLOAD];
  unsigned char upstream_a_payloads[2 * CHANNEL_MAX_DATAGRAM];
  unsigned char upstream_b_payloads[2 * CHANNEL_MAX_DATAGRAM];
  struct ker_udp_channel boundary_channel, exhausted_channel, override_channel;
  struct ker_udp_channel_slot boundary_slots[1], exhausted_slots[1], override_slots[1];
  unsigned char boundary_payloads[MAX_PAYLOAD], exhausted_payloads[MAX_PAYLOAD], override_payloads[MAX_PAYLOAD];

  __be32 clients[2];
  __be16 client_ports[2];
  __be16 upstream_ports[2];
  uint64_t now_ns;
  uint64_t error_now_ms;
  struct probe_context probe;
};
static struct fixture f;

static const unsigned char client_mac[6] = {2, 0x10, 0, 0, 0, 10};
static const unsigned char proxy_mac[6] = {2, 0x20, 0, 0, 0, 20};
static const __be32 client_ip = (__be32)0x0a0200c0;
static const __be32 proxy_ip = (__be32)0x140200c0;
static const __be32 upstream_ip = (__be32)0x0a0200c0;
static const __be32 client_b_ip = (__be32)0x0a0200c0;
static const __be16 client_a_port = (__be16)0x39c7;
static const __be16 client_b_port = (__be16)0x3ac7;
static const __be16 service_port = (__be16)0x2823;
static const __be16 server_port = (__be16)0x401f;
static const uint8_t payload_a[600] = {'A', 'q'};
static const uint8_t payload_b[] = {'B', 'q'};
static const uint8_t reply_a[] = {'A', 'r'};
static const uint8_t reply_b[] = {'B', 'r'};
static const uint8_t pressure_b[] = {'B', 'x'};

static uint64_t deadline(void) {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec +
         UINT64_C(30000000000);
}
static void alive(uint64_t end) {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  CHECK((uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec < end);
}
static void set_cpu(int cpu) {
  cpu_set_t one;
  CPU_ZERO(&one);
  CPU_SET(cpu, &one);
  CHECK(pthread_setaffinity_np(pthread_self(), sizeof(one), &one) == 0);
}
static void wait_atomic(atomic_bool *flag, uint64_t end) {
  while (!atomic_load_explicit(flag, memory_order_acquire)) {
    alive(end);
    sched_yield();
  }
}
static void wait_uint(atomic_uint *value, unsigned int expected, uint64_t end) {
  while (atomic_load_explicit(value, memory_order_acquire) < expected) {
    alive(end);
    sched_yield();
  }
}
static uint64_t monotonic_ms(void *arg) { (void)arg; return 100; }
static uint64_t error_clock_ms(void *arg) {
  return ((struct fixture *)arg)->error_now_ms;
}
static void no_probe(const struct ker_neighbor_event *event, void *arg) {
  (void)event; (void)arg;
}
static int transport_message(const struct ker_transport_message *message, void *arg) {
  (void)message;
  (void)arg;
  return NET_RX_SUCCESS;
}
static void enqueue_probe(const struct ker_neighbor_event *event, void *arg) {
  struct probe_context *ctx = arg;
  struct sk_buff *skb = NULL;
  CHECK(ker_arp_probe_create(ctx->monitor, event, &skb) == 0 && skb);
  CHECK(ker_tx_export_enqueue(ctx->tx, &skb) == 0 && !skb);
}
static int learn_proxy_neighbor(const struct ker_arp_message *message, void *arg) {
  struct fixture *x = arg;
  if (message->operation == ARPOP_REPLY && message->sender_ip == upstream_ip)
    return ker_arp_neighbor_feedback(&x->proxy_arp_receiver, &x->upstream_peer,
                                     message, NEIGH_UPDATE_F_OVERRIDE) == 0
               ? NET_RX_SUCCESS : NET_RX_DROP;
  return NET_RX_DROP;
}
static int proxy_service(void *arg, unsigned int budget) {
  struct fixture *x = arg;
  CHECK(arg == &f && rte_lcore_id() == atomic_load(&x->proxy_lcore));
  unsigned int done = 0;
  while (done < budget) {
    unsigned char payload[MAX_PAYLOAD];
    struct ker_udp_datagram_info info;
    int received = ker_udp_channel_recv(&x->listener, payload, sizeof(payload), 0,
                                        &info);
    if (received < 0)
      return received;
    if (!received)
      break;
    unsigned int index = info.peer_port == client_a_port ? 0U : 1U;
    CHECK(info.peer_port == client_a_port || info.peer_port == client_b_port);
    x->clients[index] = info.peer_address;
    x->client_ports[index] = info.peer_port;
    struct ker_udp_channel *upstream = index ? &x->upstream_b : &x->upstream_a;
    CHECK(ker_udp_send(upstream, payload, info.copied_length) == 0);
    atomic_fetch_add_explicit(&x->forwarded_upstream, 1, memory_order_release);
    ++done;
  }
  if (done < budget) {
    struct ker_udp_error_event event;
    int received = ker_udp_channel_recv_error(&x->upstream_a, &event);
    if (received < 0)
      return received;
    if (received) {
      x->received_error = event;
      unsigned char oversized[600] = {0};
      int status = ker_udp_send(&x->upstream_a, oversized, sizeof(oversized));
      atomic_store_explicit(&x->pmtu_send_status, status, memory_order_release);
      atomic_fetch_add_explicit(&x->error_events, 1, memory_order_release);
      ++done;
    }
  }
  for (unsigned int i = 0; i < 2 && done < budget; ++i) {
    struct ker_udp_channel *upstream = i ? &x->upstream_b : &x->upstream_a;
    unsigned char bytes[MAX_PAYLOAD];
    struct ker_udp_datagram_info info;
    int received = ker_udp_channel_recv(upstream, bytes, sizeof(bytes), 0, &info);
    if (received < 0)
      return received;
    if (!received)
      continue;
    CHECK(info.peer_address == upstream_ip && info.peer_port == server_port);
    CHECK(x->clients[i] && x->client_ports[i]);
    CHECK(ker_udp_sendto(&x->listener, x->clients[i], x->client_ports[i],
                         bytes, info.copied_length) == 0);
    atomic_fetch_add_explicit(&x->forwarded_clients, 1, memory_order_release);
    if (i == 1)
      atomic_store_explicit(&x->pressure_drops, (unsigned)x->upstream_b.dropped_full,
                            memory_order_release);
    ++done;
  }
  return (int)done;
}
static int proxy_tx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_tx_export_poll(&f.proxy_tx, budget);
}
static int proxy_rx(void *arg, unsigned int budget) {
  (void)arg;
  return ker_rx_ring_poll(&f.proxy_rx, budget);
}
static void proxy_flow_receive(void *arg, const struct ker_flow_key *key,
                               struct rte_mbuf *packet) {
  struct fixture *x = arg;
  CHECK(arg == &f && key->domain == DOMAIN && rte_lcore_id() == x->proxy_flow.lcore);
  struct sk_buff *skb = NULL;
  CHECK(ker_eth_receive_copy_chain(&x->proxy_device, packet, 128, &skb) == 0);
  ker_packet_free(packet);
  struct ker_receive_result result = {0};
  CHECK(ker_receive_dispatch(&x->proxy_runtime, &x->proxy_device, &skb,
                             &result) == 0);
  CHECK(!skb);
  if (result.status == NET_RX_DROP)
    atomic_fetch_add_explicit(&x->proxy_receive_drops, 1, memory_order_release);
  else
    CHECK(result.status == NET_RX_SUCCESS);
}
static void *proxy_main(void *arg) {
  struct fixture *x = arg;
  set_cpu(x->proxy_cpu);
  CHECK(rte_thread_register() == 0);
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  CHECK(ker_packet_pool_init(&x->proxy_pool, "udp_flow_proxy_pool", POOL_COUNT,
                             0, 4096, SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&x->proxy_skb, &x->proxy_pool,
                             "udp_flow_proxy_skb") == 0);
  CHECK(ker_eth_device_init(&x->proxy_device, &x->proxy_skb, "udp_flow_proxy",
                            40, proxy_mac) == 0);
  CHECK(ker_arp_device_setup(&x->proxy_device) == 0);
  CHECK(ker_ipv4_address_init(&x->proxy_address, &x->proxy_device, proxy_ip, 24) == 0);
  CHECK(ker_neighbor_table_init(&x->proxy_neighbors, &x->proxy_address,
                               "udp_flow_proxy_neigh", 8, 2) == 0);
  const struct ker_neighbor_config nc = {
      .retrans_ticks = 20, .reachable_ticks = 100, .delay_ticks = 30,
      .ucast_probes = 2, .mcast_probes = 2, .mcast_reprobes = 1,
      .queue_bytes = 32768};
  CHECK(ker_neighbor_configure(&x->proxy_neighbors, &nc) == 0);
  CHECK(ker_tx_ring_init(&x->proxy_output, "udp_flow_proxy_out", 32,
                         SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_ring_init(&x->proxy_input, "udp_flow_proxy_in", 32,
                         SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init(&x->proxy_tx, &x->proxy_skb, 16, 65536,
                           ker_tx_ring_sink, &x->proxy_output) == 0);
  CHECK(ker_receive_runtime_init(&x->proxy_runtime, &x->proxy_skb) == 0);
  CHECK(ker_transport_receiver_register(&x->proxy_receiver, &x->proxy_runtime,
      &x->proxy_device, transport_message, NULL) == 0);
  struct ker_worker_config wc = {.timer_budget = 8, .service_budget = 8,
      .tx_budget = 16, .handoff_budget = 16, .rx_budget = 16};
  struct ker_worker_ops wo = {.service = proxy_service, .tx = proxy_tx,
                              .rx = proxy_rx, .arg = x};
  CHECK(ker_worker_init(&x->proxy_worker, &x->proxy_pool, &wc, &wo) == 0);
  CHECK(ker_flow_attach(&x->proxy_flow, &x->fabric, &x->proxy_worker, 1,
                        proxy_flow_receive, x) == 0);
  atomic_store_explicit(&x->proxy_lcore, rte_lcore_id(), memory_order_release);
  CHECK(ker_rx_ring_init(&x->proxy_rx, &x->proxy_input, &x->proxy_device,
                        &x->proxy_runtime, 128) == 0);
  CHECK(ker_arp_receiver_register(&x->proxy_arp_receiver, &x->proxy_runtime,
                                  &x->proxy_address, learn_proxy_neighbor, x) == 0);
  x->probe = (struct probe_context){.monitor = &x->upstream_peer, .tx = &x->proxy_tx};
  CHECK(ker_neighbor_monitor_discovery_init(&x->upstream_peer,
      &x->proxy_neighbors, &x->proxy_worker.timers, &x->proxy_tx, upstream_ip,
      enqueue_probe, NULL, &x->probe) == 0);
  CHECK(ker_icmpv4_service_enable(&x->proxy_icmp, &x->proxy_receiver,
      &x->upstream_peer, &(struct ker_icmpv4_service_config){
        .ttl = 64, .burst = 8, .refill_ms = 100, .monotonic_ms = monotonic_ms}) == 0);
  CHECK(ker_udp_endpoint_table_enable(&x->proxy_endpoints, &x->proxy_receiver,
      &x->proxy_icmp, x->proxy_endpoint_slots, 8) == 0);
  CHECK(ker_udp_io_init(&x->proxy_io, &x->proxy_receiver, &x->proxy_icmp,
      &x->proxy_endpoints, x->proxy_peer_slots, 1, 64) == 0);
  CHECK(ker_udp_error_tracker_init(&x->error_tracker, &x->proxy_icmp,
      &x->proxy_endpoints, x->error_records, 16, x->error_peers, 1, 4,
      error_clock_ms, x, 10000) == 0);
  CHECK(ker_udp_io_attach_error_tracker(&x->proxy_io, &x->error_tracker) == 0);
  CHECK(ker_udp_io_register_peer(&x->proxy_io, &x->upstream_peer) == 0);
  CHECK(ker_udp_channel_open(&x->listener, &x->proxy_io, service_port,
      x->listener_slots, x->listener_payloads, 8, MAX_PAYLOAD,
      sizeof(x->listener_payloads), &(struct ker_udp_endpoint_handle){0}) == 0);
  struct ker_udp_flow_open_config config = {
      .domain = DOMAIN, .peer_address = upstream_ip, .peer_port = server_port,
      .first_port = EPHEMERAL_FIRST, .last_port = EPHEMERAL_LAST,
      .slots = x->upstream_a_slots, .payloads = x->upstream_a_payloads,
      .capacity = 2, .max_datagram = CHANNEL_MAX_DATAGRAM,
      .byte_limit = sizeof(x->upstream_a_payloads)};
  struct ker_udp_endpoint_handle handle_a, handle_b;
  CHECK(ker_udp_channel_open_owned(&x->upstream_a, &x->proxy_io,
      &x->proxy_flow, &config, &handle_a) == 0);
  config.slots = x->upstream_b_slots;
  config.payloads = x->upstream_b_payloads;
  config.capacity = 1;
  config.byte_limit = CHANNEL_MAX_DATAGRAM;
  CHECK(ker_udp_channel_open_owned(&x->upstream_b, &x->proxy_io,
      &x->proxy_flow, &config, &handle_b) == 0);
  CHECK(ker_udp_channel_attach_errors(&x->upstream_a,
      x->upstream_a_errors, 2) == 0);
  CHECK(ker_udp_channel_attach_errors(&x->upstream_b,
      x->upstream_b_errors, 2) == 0);
  CHECK(ker_udp_channel_attach_errors(&x->listener, x->listener_errors, 2) == 0);
  struct ker_udp_endpoint_snapshot snap_a, snap_b;
  CHECK(ker_udp_endpoint_snapshot(&x->proxy_endpoints, handle_a, &snap_a) == 0);
  CHECK(ker_udp_endpoint_snapshot(&x->proxy_endpoints, handle_b, &snap_b) == 0);
  CHECK(snap_a.local_port != snap_b.local_port && snap_a.connected && snap_b.connected);
  x->upstream_ports[0] = snap_a.local_port;
  x->upstream_ports[1] = snap_b.local_port;

  /* Exact flow override to the other worker makes this one-port range
   * unavailable to the proxy owner, even though the fallback buckets belong
   * to this worker. */
  /* The live fabric is immutable after setup; its special entry is installed
   * by the caller before either worker attaches. */
  struct ker_udp_flow_open_config unavailable = config;
  unavailable.first_port = SPECIAL_PORT; unavailable.last_port = SPECIAL_PORT;
  unavailable.slots = x->override_slots; unavailable.payloads = x->override_payloads;
  unavailable.capacity = 1; unavailable.byte_limit = MAX_PAYLOAD;
  struct ker_udp_endpoint_handle sentinel = {&x->proxy_endpoints, 19, 23};
  CHECK(ker_udp_channel_open_owned(&x->override_channel, &x->proxy_io,
      &x->proxy_flow, &unavailable, &sentinel) == -EADDRNOTAVAIL);
  CHECK(sentinel.slot == 19 && sentinel.generation == 23 &&
        !x->override_channel.open);
  struct ker_udp_flow_open_config exhausted = config;
  exhausted.first_port = ntohs(snap_a.local_port);
  exhausted.last_port = exhausted.first_port;
  exhausted.slots = x->exhausted_slots; exhausted.payloads = x->exhausted_payloads;
  exhausted.capacity = 1; exhausted.byte_limit = MAX_PAYLOAD;
  CHECK(ker_udp_channel_open_owned(&x->exhausted_channel, &x->proxy_io,
      &x->proxy_flow, &exhausted, &sentinel) == -EADDRINUSE);
  CHECK(!x->exhausted_channel.open && sentinel.slot == 19);
  struct ker_udp_flow_open_config boundary = config;
  boundary.first_port = UINT16_MAX; boundary.last_port = UINT16_MAX;
  boundary.slots = x->boundary_slots; boundary.payloads = x->boundary_payloads;
  boundary.capacity = 1; boundary.byte_limit = MAX_PAYLOAD;
  struct ker_udp_endpoint_handle boundary_handle;
  CHECK(ker_udp_channel_open_owned(&x->boundary_channel, &x->proxy_io,
      &x->proxy_flow, &boundary, &boundary_handle) == 0);
  struct ker_udp_endpoint_snapshot boundary_snapshot;
  CHECK(ker_udp_endpoint_snapshot(&x->proxy_endpoints, boundary_handle,
      &boundary_snapshot) == 0 && boundary_snapshot.local_port == htons(UINT16_MAX));
  CHECK(ker_udp_channel_close(&x->boundary_channel) == 0);

  atomic_store_explicit(&x->proxy_ready, true, memory_order_release);
  while (!atomic_load_explicit(&x->proxy_stop, memory_order_acquire)) {
    if (atomic_load_explicit(&x->proxy_pause, memory_order_acquire)) {
      atomic_store_explicit(&x->proxy_paused, true, memory_order_release);
      sched_yield();
      continue;
    }
    atomic_store_explicit(&x->proxy_paused, false, memory_order_release);
    struct ker_worker_result result = {0};
    int rc = ker_worker_poll(&x->proxy_worker, (int64_t)++x->now_ns, &result);
    if (rc < 0 && rc != -EAGAIN)
      atomic_fetch_add_explicit(&x->proxy_poll_errors, 1, memory_order_relaxed);
    sched_yield();
  }
  CHECK(!x->proxy_input.ring || rte_ring_empty(x->proxy_input.ring));
  x->error_now_ms = 20000; /* Expire bounded SENT quote records for teardown. */
  CHECK(ker_udp_channel_close(&x->upstream_b) == 0);
  CHECK(ker_udp_channel_close(&x->upstream_a) == 0);
  CHECK(ker_udp_channel_close(&x->listener) == 0);
  CHECK(ker_udp_io_unregister_peer(&x->proxy_io, &x->upstream_peer) == 0);
  CHECK(ker_udp_io_detach_error_tracker(&x->proxy_io) == 0);
  CHECK(ker_udp_error_tracker_cleanup(&x->error_tracker) == 0);
  CHECK(ker_udp_io_cleanup(&x->proxy_io) == 0);
  CHECK(ker_udp_endpoint_table_disable(&x->proxy_endpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&x->proxy_icmp) == 0);
  CHECK(ker_arp_receiver_unregister(&x->proxy_arp_receiver) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&x->upstream_peer) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&x->upstream_peer) == 0);
  CHECK(ker_transport_receiver_unregister(&x->proxy_receiver) == 0);
  CHECK(ker_rx_ring_cleanup(&x->proxy_rx) == 0);
  CHECK(ker_receive_runtime_cleanup(&x->proxy_runtime) == 0);
  CHECK(ker_flow_detach(&x->proxy_flow) == 0);
  CHECK(ker_worker_cleanup(&x->proxy_worker) == 0);
  CHECK(ker_tx_export_cleanup(&x->proxy_tx) == 0);
  CHECK(ker_tx_ring_cleanup(&x->proxy_input) == 0);
  CHECK(rte_ring_empty(x->proxy_output.ring));
  CHECK(ker_tx_ring_cleanup(&x->proxy_output) == 0);
  CHECK(ker_neighbor_table_cleanup(&x->proxy_neighbors) == 0);
  CHECK(ker_ipv4_address_cleanup(&x->proxy_address) == 0);
  CHECK(ker_eth_device_cleanup(&x->proxy_device) == 0);
  CHECK(ker_skb_context_cleanup(&x->proxy_skb) == 0);
  CHECK(ker_packet_pool_cleanup(&x->proxy_pool) == 0);
  atomic_store_explicit(&x->proxy_cleaned, true, memory_order_release);
  wait_atomic(&x->allow_proxy_memory_shutdown, deadline());
  CHECK(ker_memory_shutdown() == 0);
  rte_thread_unregister();
  return NULL;
}

static int main_tx_poll(void *arg, unsigned int budget) {
  struct fixture *x = arg;
  return ker_tx_export_poll(&x->client_tx, budget);
}
static int main_rx_poll(void *arg, unsigned int budget) {
  struct fixture *x = arg;
  return ker_rx_ring_poll(&x->client_rx, budget);
}
static void main_flow_receive(void *arg, const struct ker_flow_key *key,
                              struct rte_mbuf *packet) {
  (void)arg; (void)key;
  ker_packet_free(packet);
}
static void init_main_side(void) {
  CHECK(ker_packet_pool_init(&f.client_pool, "udp_flow_main_pool", POOL_COUNT,
                             0, 4096, SOCKET_ID_ANY) == 0);
  CHECK(ker_skb_context_init(&f.client_skb, &f.client_pool,
                             "udp_flow_main_skb") == 0);
  CHECK(ker_eth_device_init(&f.client_device, &f.client_skb, "udp_flow_main",
                            41, client_mac) == 0);
  CHECK(ker_arp_device_setup(&f.client_device) == 0);
  CHECK(ker_ipv4_address_init(&f.client_address, &f.client_device, client_ip, 24) == 0);
  CHECK(ker_neighbor_table_init(&f.client_neighbors, &f.client_address,
                                "udp_flow_main_neigh", 4, 2) == 0);
  const struct ker_neighbor_config nc = {
      .retrans_ticks = 20, .reachable_ticks = 100, .delay_ticks = 30,
      .ucast_probes = 2, .mcast_probes = 2, .mcast_reprobes = 1,
      .queue_bytes = 32768};
  CHECK(ker_neighbor_configure(&f.client_neighbors, &nc) == 0);
  CHECK(ker_neighbor_add(&f.client_neighbors, proxy_ip, proxy_mac) == 0);
  CHECK(ker_tx_ring_init(&f.client_output, "udp_flow_main_out", 32,
                         SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_ring_init(&f.client_input, "udp_flow_main_in", 32,
                         SOCKET_ID_ANY) == 0);
  CHECK(ker_tx_export_init(&f.client_tx, &f.client_skb, 16, 65536,
                           ker_tx_ring_sink, &f.client_output) == 0);
  CHECK(ker_receive_runtime_init(&f.client_runtime, &f.client_skb) == 0);
  CHECK(ker_transport_receiver_register(&f.client_receiver, &f.client_runtime,
      &f.client_device, transport_message, NULL) == 0);
  CHECK(ker_rx_ring_init(&f.client_rx, &f.client_input, &f.client_device,
                         &f.client_runtime, 128) == 0);
  struct ker_worker_config wc = {.timer_budget = 8, .tx_budget = 16,
      .handoff_budget = 8, .rx_budget = 8};
  struct ker_worker_ops wo = {.tx = main_tx_poll, .rx = main_rx_poll, .arg = &f};
  CHECK(ker_worker_init(&f.client_worker, &f.client_pool, &wc, &wo) == 0);
  CHECK(ker_flow_attach(&f.client_flow, &f.fabric, &f.client_worker, 0,
                        main_flow_receive, &f) == 0);
  CHECK(ker_neighbor_monitor_init(&f.proxy_peer, &f.client_neighbors,
      &f.client_worker.timers, proxy_ip, no_probe, NULL, NULL) == 0);
  CHECK(ker_neighbor_monitor_resolution_enable(&f.proxy_peer, &f.client_tx) == 0);
  CHECK(ker_arp_responder_register(&f.responder, &f.client_runtime,
      &f.client_address, &f.client_tx) == 0);
  CHECK(ker_icmpv4_service_enable(&f.client_icmp, &f.client_receiver,
      &f.proxy_peer, &(struct ker_icmpv4_service_config){
        .ttl = 64, .burst = 8, .refill_ms = 100, .monotonic_ms = monotonic_ms}) == 0);
  CHECK(ker_udp_endpoint_table_enable(&f.client_endpoints, &f.client_receiver,
      &f.client_icmp, f.client_endpoint_slots, 4) == 0);
  CHECK(ker_udp_io_init(&f.client_io, &f.client_receiver, &f.client_icmp,
      &f.client_endpoints, f.client_peer_slots, 1, 64) == 0);
  CHECK(ker_udp_io_register_peer(&f.client_io, &f.proxy_peer) == 0);
  CHECK(ker_udp_channel_open(&f.client_a, &f.client_io, htons(CLIENT_PORT_A),
      f.client_a_slots, f.client_a_payloads, 2, MAX_PAYLOAD,
      sizeof(f.client_a_payloads), &(struct ker_udp_endpoint_handle){0}) == 0);
  CHECK(ker_udp_endpoint_connect(&f.client_endpoints, f.client_a.endpoint,
      proxy_ip, service_port) == 0);
  CHECK(ker_udp_channel_open(&f.client_b, &f.client_io, htons(CLIENT_PORT_B),
      f.client_b_slots, f.client_b_payloads, 2, MAX_PAYLOAD,
      sizeof(f.client_b_payloads), &(struct ker_udp_endpoint_handle){0}) == 0);
  CHECK(ker_udp_endpoint_connect(&f.client_endpoints, f.client_b.endpoint,
      proxy_ip, service_port) == 0);
  CHECK(ker_udp_channel_open(&f.upstream_server, &f.client_io,
      server_port, f.server_slots, f.server_payloads, 4, MAX_PAYLOAD,
      sizeof(f.server_payloads), &(struct ker_udp_endpoint_handle){0}) == 0);
}
static void cleanup_main_side(void) {
  CHECK(ker_udp_channel_close(&f.upstream_server) == 0);
  CHECK(ker_udp_channel_close(&f.client_b) == 0);
  CHECK(ker_udp_channel_close(&f.client_a) == 0);
  CHECK(ker_udp_io_unregister_peer(&f.client_io, &f.proxy_peer) == 0);
  CHECK(ker_udp_io_cleanup(&f.client_io) == 0);
  CHECK(ker_udp_endpoint_table_disable(&f.client_endpoints) == 0);
  CHECK(ker_icmpv4_service_disable(&f.client_icmp) == 0);
  CHECK(ker_arp_responder_unregister(&f.responder) == 0);
  CHECK(ker_neighbor_monitor_resolution_disable(&f.proxy_peer) == 0);
  CHECK(ker_neighbor_monitor_cleanup(&f.proxy_peer) == 0);
  CHECK(ker_rx_ring_cleanup(&f.client_rx) == 0);
  CHECK(ker_transport_receiver_unregister(&f.client_receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&f.client_runtime) == 0);
  CHECK(ker_flow_detach(&f.client_flow) == 0);
  CHECK(ker_worker_cleanup(&f.client_worker) == 0);
  CHECK(ker_tx_export_cleanup(&f.client_tx) == 0);
  CHECK(ker_tx_ring_cleanup(&f.client_input) == 0);
  CHECK(ker_tx_ring_cleanup(&f.client_output) == 0);
  CHECK(ker_neighbor_remove(&f.client_neighbors, proxy_ip) == 0);
  CHECK(ker_neighbor_table_cleanup(&f.client_neighbors) == 0);
  CHECK(ker_ipv4_address_cleanup(&f.client_address) == 0);
  CHECK(ker_eth_device_cleanup(&f.client_device) == 0);
  CHECK(ker_skb_context_cleanup(&f.client_skb) == 0);
  CHECK(ker_packet_pool_cleanup(&f.client_pool) == 0);
}
static struct rte_mbuf *main_tx_take(void) {
  CHECK(ker_tx_export_poll(&f.client_tx, 16) >= 0);
  struct rte_mbuf *packet = NULL;
  CHECK(ker_tx_ring_take(&f.client_output, &packet) == 1 && packet);
  return packet;
}
static struct rte_mbuf *proxy_tx_take(uint64_t end) {
  void *packet = NULL;
  while (rte_ring_sc_dequeue(f.proxy_output.ring, &packet) == -ENOENT) {
    alive(end);
    sched_yield();
  }
  CHECK(packet);
  return packet;
}
static const unsigned char *packet_bytes(struct rte_mbuf *packet,
                                         unsigned char *storage) {
  const unsigned char *bytes = rte_pktmbuf_read(packet, 0, packet->pkt_len, storage);
  CHECK(bytes);
  if (bytes != storage) {
    memcpy(storage, bytes, packet->pkt_len);
    bytes = storage;
  }
  return bytes;
}
static void check_udp_frame(struct rte_mbuf *packet, const unsigned char *src_mac,
                            const unsigned char *dst_mac, __be32 src_ip,
                            __be32 dst_ip, __be16 src_port, __be16 dst_port,
                            const unsigned char *payload, size_t length) {
  unsigned char storage[ETH_HLEN + 20 + 8 + MAX_PAYLOAD];
  CHECK(packet->pkt_len == ETH_HLEN + 20 + 8 + length &&
        packet->pkt_len <= sizeof(storage));
  const unsigned char *bytes = packet_bytes(packet, storage);
  CHECK(!memcmp(bytes, dst_mac, ETH_ALEN) &&
        !memcmp(bytes + ETH_ALEN, src_mac, ETH_ALEN));
  CHECK(bytes[12] == 0x08 && bytes[13] == 0x00);
  const unsigned char *ip = bytes + ETH_HLEN;
  CHECK(ip[0] == 0x45 && ip[9] == IPPROTO_UDP &&
        !memcmp(ip + 12, &src_ip, 4) && !memcmp(ip + 16, &dst_ip, 4));
  const unsigned char *udp = ip + 20;
  CHECK(!memcmp(udp, &src_port, 2) && !memcmp(udp + 2, &dst_port, 2));
  CHECK(!memcmp(udp + 8, payload, length));
}
static void submit_to_proxy(struct rte_mbuf *packet) {
  CHECK(ker_flow_submit(&f.client_flow, DOMAIN, KER_FLOW_INGRESS, &packet) == 0);
  CHECK(!packet);
}
static void inject_main_rx(struct rte_mbuf *packet) {
  CHECK(ker_tx_ring_sink(packet, &f.client_input) == 0);
  CHECK(ker_rx_ring_poll(&f.client_rx, 1) == 1);
}
static void handle_first_arp(uint64_t end) {
  struct rte_mbuf *request = proxy_tx_take(end);
  unsigned char storage[64];
  const unsigned char *bytes = packet_bytes(request, storage);
  CHECK(request->pkt_len == 42 && bytes[12] == 0x08 && bytes[13] == 0x06);
  CHECK(!memcmp(bytes, (unsigned char[]){255,255,255,255,255,255}, ETH_ALEN));
  CHECK(!memcmp(bytes + 6, proxy_mac, ETH_ALEN));
  CHECK(bytes[20] == 0 && bytes[21] == ARPOP_REQUEST);
  CHECK(!memcmp(bytes + 28, &proxy_ip, 4) &&
        !memcmp(bytes + 38, &upstream_ip, 4));
  inject_main_rx(request);
  CHECK(f.responder.requests == 1 && f.responder.replies_enqueued == 1);
  CHECK(ker_tx_export_poll(&f.client_tx, 16) == 1);
  struct rte_mbuf *reply = NULL;
  CHECK(ker_tx_ring_take(&f.client_output, &reply) == 1 && reply);
  const unsigned char *arp = packet_bytes(reply, storage);
  CHECK(reply->pkt_len == 42 && arp[20] == 0 && arp[21] == ARPOP_REPLY);
  CHECK(!memcmp(arp + 28, &upstream_ip, 4) &&
        !memcmp(arp + 38, &proxy_ip, 4));
  CHECK(rte_ring_sp_enqueue(f.proxy_input.ring, reply) == 0);
  /* Wait until the native reply updates the resolving entry and flushes both
   * bounded queued UDP datagrams to the proxy output ring. */
  wait_uint(&f.forwarded_upstream, 2, end);
}
static void process_upstream_request(struct rte_mbuf *packet,
                                     unsigned int *which) {
  unsigned char storage[ETH_HLEN + 20 + 8 + CHANNEL_MAX_DATAGRAM];
  const unsigned char *bytes = packet_bytes(packet, storage);
  const unsigned char *ip = bytes + ETH_HLEN;
  const unsigned char *udp = ip + 20;
  CHECK(bytes[12] == 0x08 && bytes[13] == 0x00);
  CHECK(!memcmp(ip + 12, &proxy_ip, 4) && !memcmp(ip + 16, &upstream_ip, 4));
  CHECK(!memcmp(udp + 2, &server_port, 2));
  size_t length = packet->pkt_len - ETH_HLEN - 20 - 8;
  if (length == sizeof(payload_a) && !memcmp(udp + 8, payload_a, length)) {
    *which = 0;
  } else {
    CHECK(length == sizeof(payload_b) && !memcmp(udp + 8, payload_b, length));
    *which = 1;
  }
  if (*which == 0 && !f.quote_captured) {
    memcpy(f.upstream_quote, ip, sizeof(f.upstream_quote));
    f.quote_captured = true;
  }
  __be16 source_port;
  memcpy(&source_port, udp, 2);
  CHECK(source_port == f.upstream_ports[*which]);
  inject_main_rx(packet);
}
static void send_upstream_reply(__be16 target_port,
                                const unsigned char *payload, size_t length) {
  CHECK(ker_udp_sendto(&f.upstream_server, proxy_ip, target_port,
                       payload, length) == 0);
  struct rte_mbuf *packet = main_tx_take();
  submit_to_proxy(packet);
}
static void send_frag_needed(uint64_t end) {
  CHECK(f.quote_captured);
  unsigned char rest[4] = {0, 0, 2, 0x40}; /* advertised MTU 576 */
  struct sk_buff *skb = NULL;
  CHECK(ker_icmpv4_ipv4_create(&f.client_skb, client_mac, proxy_mac,
      upstream_ip, proxy_ip, 3, 4, rest, 64, f.upstream_quote,
      sizeof(f.upstream_quote), &skb) == 0);
  struct rte_mbuf *wire = NULL;
  CHECK(ker_skb_to_mbuf(skb, &wire) == 0);
  CHECK(ker_skb_free(skb) == 0);
  CHECK(ker_flow_submit(&f.client_flow, DOMAIN, KER_FLOW_INGRESS, &wire) == 0);
  CHECK(!wire);
  wait_uint(&f.error_events, 1, end);
  __be16 quoted_source;
  memcpy(&quoted_source, f.upstream_quote + 20, sizeof(quoted_source));
  CHECK(f.received_error.error == EMSGSIZE && f.received_error.type == 3 &&
        f.received_error.code == 4 && f.received_error.next_hop_mtu == 576 &&
        f.received_error.pmtu_status == 1 &&
        f.received_error.local_address == proxy_ip &&
        f.received_error.peer_address == upstream_ip &&
        f.received_error.local_port == quoted_source &&
        f.received_error.peer_port == server_port);
  CHECK(atomic_load_explicit(&f.pmtu_send_status, memory_order_acquire) ==
        -EMSGSIZE);
}
static void receive_client_reply(unsigned int index,
                                 const unsigned char *expected, size_t length,
                                 uint64_t end) {
  struct rte_mbuf *packet = proxy_tx_take(end);
  check_udp_frame(packet, proxy_mac, client_mac, proxy_ip, client_ip,
      service_port, index ? htons(CLIENT_PORT_B) : htons(CLIENT_PORT_A),
      expected, length);
  inject_main_rx(packet);
  unsigned char output[MAX_PAYLOAD];
  struct ker_udp_datagram_info info;
  struct ker_udp_channel *channel = index ? &f.client_b : &f.client_a;
  CHECK(ker_udp_channel_recv(channel, output, sizeof(output), 0, &info) == 1);
  CHECK(info.peer_address == proxy_ip && info.peer_port == service_port &&
        info.local_port == htons(index ? CLIENT_PORT_B : CLIENT_PORT_A) &&
        info.copied_length == length && !memcmp(output, expected, length));
}

int main(void) {
  CHECK(sched_getaffinity(0, sizeof(f.allowed), &f.allowed) == 0);
  int cpus[2], count = 0;
  for (int i = 0; i < CPU_SETSIZE && count < 2; ++i)
    if (CPU_ISSET(i, &f.allowed)) cpus[count++] = i;
  if (count < 2) {
    puts("SKIP: fewer than two CPUs in the process affinity mask");
    return 77;
  }
  f.proxy_cpu = cpus[1];
  set_cpu(cpus[0]);
  atomic_init(&f.proxy_ready, false); atomic_init(&f.proxy_stop, false);
  atomic_init(&f.proxy_pause, false); atomic_init(&f.proxy_paused, false);
  atomic_init(&f.proxy_cleaned, false); atomic_init(&f.allow_proxy_memory_shutdown, false);
  atomic_init(&f.proxy_lcore, UINT_MAX); atomic_init(&f.forwarded_upstream, 0);
  atomic_init(&f.forwarded_clients, 0); atomic_init(&f.pressure_drops, 0);
  atomic_init(&f.proxy_poll_errors, 0); atomic_init(&f.proxy_receive_drops, 0);
  atomic_init(&f.error_events, 0); atomic_init(&f.pmtu_send_status, 0);
  f.clients[0] = client_ip; f.clients[1] = client_b_ip;
  f.client_ports[0] = client_a_port; f.client_ports[1] = client_b_port;
  f.now_ns = 1;
  f.error_now_ms = 100;
  ker_test_eal_init();
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  uint16_t owners[KER_FLOW_BUCKETS];
  for (unsigned int i = 0; i < KER_FLOW_BUCKETS; ++i) owners[i] = 1;
  struct ker_flow_special special = {0};
  special.key.domain = DOMAIN; special.key.family = 4; special.key.protocol = 17;
  memcpy(special.key.local + 12, &proxy_ip, 4);
  memcpy(special.key.remote + 12, &upstream_ip, 4);
  special.key.local_port = SPECIAL_PORT;
  special.key.remote_port = ntohs(server_port);
  special.owner = 0;
  struct ker_flow_config fc = {.worker_count = 2, .bucket_owner = owners,
      .special = &special, .special_count = 1, .seed = UINT64_C(0x12345678),
      .inbox_capacity = 16, .name = "udp_flow_fabric", .socket_id = SOCKET_ID_ANY};
  CHECK(ker_flow_fabric_init(&f.fabric, &fc) == 0);
  init_main_side();
  CHECK(pthread_create(&f.proxy_thread, NULL, proxy_main, &f) == 0);
  uint64_t end = deadline(); wait_atomic(&f.proxy_ready, end);
  CHECK(atomic_load(&f.proxy_lcore) != f.client_flow.lcore);

  /* Main client datagrams are serialized by the actual flow fabric into the
   * second worker's bounded inbox; no direct callback or synthetic socket path. */
  CHECK(ker_udp_send(&f.client_a, payload_a, sizeof(payload_a)) == 0);
  submit_to_proxy(main_tx_take());
  CHECK(ker_udp_send(&f.client_b, payload_b, sizeof(payload_b)) == 0);
  submit_to_proxy(main_tx_take());
  handle_first_arp(end);

  unsigned int seen = 0;
  while (seen != 3) {
    struct rte_mbuf *packet = proxy_tx_take(end);
    unsigned int index = UINT_MAX;
    process_upstream_request(packet, &index);
    CHECK(index < 2 && !(seen & (1U << index)));
    seen |= 1U << index;
  }
  CHECK(seen == 3);
  unsigned char data[MAX_PAYLOAD];
  __be16 port_a = 0, port_b = 0;
  for (unsigned int i = 0; i < 2; ++i) {
    struct ker_udp_datagram_info info;
    CHECK(ker_udp_channel_recv(&f.upstream_server, data, sizeof(data), 0,
                               &info) == 1);
    CHECK(info.local_port == server_port && info.peer_address == proxy_ip);
    if (info.copied_length == sizeof(payload_a) &&
        !memcmp(data, payload_a, sizeof(payload_a))) {
      port_a = info.peer_port;
      CHECK(port_a == f.upstream_ports[0]);
    } else {
      CHECK(info.copied_length == sizeof(payload_b) &&
            !memcmp(data, payload_b, sizeof(payload_b)));
      port_b = info.peer_port;
      CHECK(port_b == f.upstream_ports[1]);
    }
  }
  CHECK(port_a && port_b);
  send_frag_needed(end);

  /* Complete B before A. Each response is steered on its reversed UDP tuple
   * to the proxy owner and delivered to the matching client channel. */
  send_upstream_reply(port_b, reply_b, sizeof(reply_b));
  wait_uint(&f.forwarded_clients, 1, end);
  receive_client_reply(1, reply_b, sizeof(reply_b), end);
  send_upstream_reply(port_a, reply_a, sizeof(reply_a));
  wait_uint(&f.forwarded_clients, 2, end);
  receive_client_reply(0, reply_a, sizeof(reply_a), end);

  /* Pause proxy polling, enqueue two returns to B through flow_submit, then
   * release one worker handoff batch. The one-slot B inbox admits one and
   * drops exactly one while A remains unaffected. */
  atomic_store_explicit(&f.proxy_pause, true, memory_order_release);
  while (!atomic_load_explicit(&f.proxy_paused, memory_order_acquire)) {
    alive(end); sched_yield();
  }
  send_upstream_reply(port_b, reply_b, sizeof(reply_b));
  send_upstream_reply(port_b, pressure_b, sizeof(pressure_b));
  atomic_store_explicit(&f.proxy_pause, false, memory_order_release);
  wait_uint(&f.forwarded_clients, 3, end);
  wait_uint(&f.pressure_drops, 1, end);
  wait_uint(&f.proxy_receive_drops, 1, end);
  receive_client_reply(1, reply_b, sizeof(reply_b), end);
  CHECK(atomic_load(&f.proxy_poll_errors) == 0);

  atomic_store_explicit(&f.proxy_stop, true, memory_order_release);
  wait_atomic(&f.proxy_cleaned, end);
  cleanup_main_side();
  atomic_store_explicit(&f.allow_proxy_memory_shutdown, true, memory_order_release);
  CHECK(pthread_join(f.proxy_thread, NULL) == 0);
  CHECK(ker_flow_fabric_cleanup(&f.fabric) == 0);
  CHECK(ker_memory_shutdown() == 0);
  CHECK(rte_eal_cleanup() == 0);
  return 0;
}
