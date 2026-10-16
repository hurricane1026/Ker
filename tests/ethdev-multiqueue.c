#include "check.h"
#include "runtime/ethdev-rx.h"
#include "runtime/ethdev-tx.h"
#include "runtime/memory.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <net/checksum.h>
#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NMSG 3U
#define PAYLOAD 512U
#define POOL_SIZE 127U
#define QUEUE_SIZE 1U

struct endpoint;
struct endpoint_arg {
  struct endpoint *endpoint;
};
struct endpoint {
  unsigned int index, owner_lcore;
  int cpu;
  struct ker_packet_pool pool;
  struct ker_skb_context skb;
  struct ker_eth_device device;
  struct ker_receive_runtime runtime;
  struct ker_transport_receiver receiver;
  struct ker_ethdev_tx tx;
  struct ker_ethdev_rx rx;
  struct ker_worker worker;
  struct endpoint_arg arg;
  struct rte_ring *ring;
  atomic_bool ready, done, processed;
  atomic_uint delivered;
  bool hold_rx;
  uint8_t ids[NMSG];
};

static struct endpoint endpoints[2];
static struct rte_mempool *pools[2];
static uint16_t port_id;
static atomic_bool start_queue1, queue0_cleaned;
static int cpus[2];
static const uint8_t macs[2][6] = {{2, 0, 1, 2, 3, 4}, {2, 0, 5, 6, 7, 8}};
static __be32 ips[2];

static uint16_t checksum(const uint8_t *p, size_t n, uint32_t sum) {
  while (n >= 2) {
    sum += ((uint32_t)p[0] << 8) | p[1];
    p += 2;
    n -= 2;
  }
  if (n)
    sum += (uint32_t)p[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)~sum;
}

static void verify_checksum(const struct ker_transport_message *m) {
  size_t length = m->ipv4.payload_length;
  uint8_t pseudo[12];
  memcpy(pseudo, m->ipv4.header + 12, 8);
  pseudo[8] = 0;
  pseudo[9] = (uint8_t)m->protocol;
  pseudo[10] = (uint8_t)(length >> 8);
  pseudo[11] = (uint8_t)length;
  uint32_t sum = 0;
  for (size_t i = 0; i < sizeof(pseudo); i += 2)
    sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
  const uint8_t *l4 = m->protocol == KER_TRANSPORT_TCP ? m->packet.tcp.header
                                                       : m->packet.udp.header;
  CHECK(checksum(l4, length, sum) == 0);
}

static int receive_packet(const struct ker_transport_message *m, void *arg) {
  struct endpoint *e = arg;
  CHECK(e && rte_lcore_id() == e->owner_lcore && e->worker.polling);
  unsigned int n = atomic_load_explicit(&e->delivered, memory_order_relaxed);
  CHECK(n < NMSG);
  uint8_t id = (uint8_t)(e->index * 16 + n);
  CHECK(e->ids[n] == id);
  CHECK(!memcmp(m->ipv4.header + 12, &ips[e->index], 4));
  CHECK(!memcmp(m->ipv4.header + 16, &ips[e->index], 4));
  CHECK(m->protocol == ((n & 1U) ? KER_TRANSPORT_UDP : KER_TRANSPORT_TCP));
  verify_checksum(m);
  const uint8_t *data;
  size_t length;
  if (m->protocol == KER_TRANSPORT_TCP) {
    CHECK(m->packet.tcp.source_port == rte_cpu_to_be_16(40000 + e->index));
    CHECK(m->packet.tcp.destination_port == rte_cpu_to_be_16(41000 + e->index));
    CHECK(m->packet.tcp.sequence == 0xabc00000U + id);
    CHECK(m->packet.tcp.flags == (KER_TCP_ACK | KER_TCP_PSH));
    data = m->packet.tcp.payload;
    length = m->packet.tcp.payload_length;
  } else {
    CHECK(m->packet.udp.source_port == rte_cpu_to_be_16(42000 + e->index));
    CHECK(m->packet.udp.destination_port == rte_cpu_to_be_16(43000 + e->index));
    data = m->packet.udp.payload;
    length = m->packet.udp.payload_length;
  }
  CHECK(length == PAYLOAD);
  CHECK(data[0] == id);
  for (size_t i = 0; i < length; ++i)
    CHECK(data[i] == (uint8_t)(id + i * 13U));
  atomic_store_explicit(&e->delivered, n + 1, memory_order_release);
  return NET_RX_SUCCESS;
}

static int tx_poll(void *arg, unsigned int budget) {
  struct endpoint *e = ((struct endpoint_arg *)arg)->endpoint;
  CHECK(rte_lcore_id() == e->owner_lcore);
  int rc = ker_ethdev_tx_poll(&e->tx, budget);
  /* This test wrapper keeps polling RX when its independent TX queue is full.
   */
  return rc == -EAGAIN ? 0 : rc;
}

static int rx_poll(void *arg, unsigned int budget) {
  struct endpoint *e = ((struct endpoint_arg *)arg)->endpoint;
  CHECK(rte_lcore_id() == e->owner_lcore);
  return e->hold_rx ? 0 : ker_ethdev_rx_poll(&e->rx, budget);
}

static struct sk_buff *make_packet(struct endpoint *e, unsigned int n) {
  uint8_t id = (uint8_t)(e->index * 16 + n);
  uint8_t payload[PAYLOAD];
  for (size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = (uint8_t)(id + i * 13U);
  struct sk_buff *skb = NULL;
  bool tcp = !(n & 1U);
  __be16 sport = rte_cpu_to_be_16((tcp ? 40000 : 42000) + e->index);
  __be16 dport = rte_cpu_to_be_16((tcp ? 41000 : 43000) + e->index);
  if (tcp)
    CHECK(ker_tcp_ipv4_create(&e->skb, macs[e->index], macs[e->index],
                              ips[e->index], ips[e->index], sport, dport,
                              rte_cpu_to_be_32(0xabc00000U + id), 0,
                              rte_cpu_to_be_16(4096), KER_TCP_ACK | KER_TCP_PSH,
                              64, payload, sizeof(payload), &skb) == 0);
  else
    CHECK(ker_udp_ipv4_create(&e->skb, macs[e->index], macs[e->index],
                              ips[e->index], ips[e->index], sport, dport, 64,
                              payload, sizeof(payload), &skb) == 0);
  unsigned int start = ETH_HLEN + 20;
  unsigned int field = tcp ? 16 : 6;
  skb->data[start + field] = skb->data[start + field + 1] = 0;
  unsigned int l4len = skb->len - start;
  __wsum pseudo = csum_tcpudp_nofold(ips[e->index], ips[e->index], l4len,
                                     tcp ? IPPROTO_TCP : IPPROTO_UDP, 0);
  __sum16 seed = (__sum16)~csum_fold(pseudo);
  memcpy(skb->data + start + field, &seed, sizeof(seed));
  skb->ip_summed = CHECKSUM_PARTIAL;
  skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
  skb->csum_offset = (uint16_t)field;
  return skb;
}

static uint64_t deadline_ns(void) {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec + 20000000000ULL;
}

static void wait_flag(atomic_bool *flag, uint64_t deadline, const char *name) {
  struct timespec ts;
  while (!atomic_load_explicit(flag, memory_order_acquire)) {
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    if ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec >= deadline) {
      fprintf(stderr, "timed out waiting for %s\n", name);
      CHECK(false);
    }
    sched_yield();
  }
}

static int endpoint_init(struct endpoint *e) {
  CHECK(rte_lcore_id() != LCORE_ID_ANY);
  CHECK(ker_memory_init(SOCKET_ID_ANY, 127) == 0);
  e->owner_lcore = rte_lcore_id();
  CHECK(e->cpu == sched_getcpu());
  char pool_name[16];
  snprintf(pool_name, sizeof(pool_name), "mq_skb_pool%u", e->index);
  CHECK(ker_packet_pool_init(&e->pool, pool_name, POOL_SIZE, 0, 8192,
                             SOCKET_ID_ANY) == 0);
  for (unsigned int i = 0; i < NMSG; ++i)
    e->ids[i] = (uint8_t)(e->index * 16 + i);
  char skb_name[16];
  snprintf(skb_name, sizeof(skb_name), "mq_skb%u", e->index);
  CHECK(ker_skb_context_init(&e->skb, &e->pool, skb_name) == 0);
  char devname[16];
  snprintf(devname, sizeof(devname), "mq%u", e->index);
  CHECK(ker_eth_device_init(&e->device, &e->skb, devname, e->index + 1,
                            macs[e->index]) == 0);
  CHECK(ker_receive_runtime_init(&e->runtime, &e->skb) == 0);
  CHECK(ker_transport_receiver_register(&e->receiver, &e->runtime, &e->device,
                                        receive_packet, e) == 0);
  CHECK(ker_ethdev_rx_init(&e->rx, &e->device, &e->runtime, port_id,
                           (uint16_t)e->index, 0) == 0);
  CHECK(ker_ethdev_tx_init_mode(&e->tx, &e->skb, port_id, (uint16_t)e->index, 8,
                                1U << 20, 256,
                                KER_ETHDEV_TX_CHECKSUM_SOFTWARE) == 0);
  e->arg.endpoint = e;
  struct ker_worker_config cfg = {
      .timer_budget = 1, .tx_budget = 8, .rx_budget = 8, .rx_margin = 0};
  struct ker_worker_ops ops = {.tx = tx_poll, .rx = rx_poll, .arg = &e->arg};
  CHECK(ker_worker_init(&e->worker, &e->pool, &cfg, &ops) == 0);
  atomic_store_explicit(&e->ready, true, memory_order_release);
  return 0;
}

static void endpoint_cleanup(struct endpoint *e) {
  CHECK(ker_worker_cleanup(&e->worker) == 0);
  CHECK(ker_ethdev_tx_cleanup(&e->tx) == 0);
  CHECK(ker_ethdev_rx_cleanup(&e->rx) == 0);
  CHECK(ker_transport_receiver_unregister(&e->receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&e->runtime) == 0);
  CHECK(ker_eth_device_cleanup(&e->device) == 0);
  CHECK(ker_skb_context_cleanup(&e->skb) == 0);
  CHECK(ker_packet_pool_cleanup(&e->pool) == 0);
}

static int owner1(void *arg) {
  struct endpoint *e = arg;
  if (endpoint_init(e))
    return -1;
  uint64_t end = deadline_ns();
  wait_flag(&start_queue1, end, "queue 1 start");
  for (unsigned int i = 0; i < NMSG; ++i) {
    struct sk_buff *skb = make_packet(e, i);
    CHECK(ker_tx_export_enqueue(&e->tx.exporter, &skb) == 0 && !skb);
  }
  while (atomic_load_explicit(&e->delivered, memory_order_acquire) < NMSG) {
    struct ker_worker_result result = {0};
    int rc = ker_worker_poll(&e->worker, e->worker.timers.now_ns, &result);
    CHECK(rc == 0 || rc == -EAGAIN);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    CHECK((uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec < end);
    sched_yield();
  }
  CHECK(e->tx.exporter.packets == 0);
  atomic_store_explicit(&e->processed, true, memory_order_release);
  wait_flag(&queue0_cleaned, deadline_ns(), "queue 0 cleanup");
  endpoint_cleanup(e);
  CHECK(ker_memory_shutdown() == 0);
  atomic_store_explicit(&e->done, true, memory_order_release);
  return 0;
}

static void main_owner_run(struct endpoint *e) {
  CHECK(endpoint_init(e) == 0);
  for (unsigned int i = 0; i < NMSG; ++i) {
    struct sk_buff *skb = make_packet(e, i);
    CHECK(ker_tx_export_enqueue(&e->tx.exporter, &skb) == 0 && !skb);
  }
  e->hold_rx = true;
  struct ker_worker_result result = {0};
  CHECK(ker_worker_poll(&e->worker, 0, &result) == 0);
  CHECK(result.tx == 1 && result.rx == 0 && e->tx.exporter.packets == 2);
  CHECK(e->tx.exporter.last_error == -EAGAIN);
  CHECK(rte_ring_count(e->ring) == QUEUE_SIZE);
  atomic_store_explicit(&start_queue1, true, memory_order_release);

  uint64_t end = deadline_ns();
  wait_flag(&endpoints[1].processed, end, "queue 1 progress");
  /* Queue 1 completed while queue 0's actual PMD ring remained full and RX was
   * intentionally paused; queue pressure and progress are independent. */
  CHECK(rte_ring_count(e->ring) == QUEUE_SIZE);
  e->hold_rx = false;
  while (atomic_load_explicit(&e->delivered, memory_order_acquire) < NMSG) {
    struct ker_worker_result progress = {0};
    int rc =
        ker_worker_poll(&e->worker, e->worker.timers.now_ns + 1, &progress);
    CHECK(rc == 0 || rc == -EAGAIN);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    if ((uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec >= end) {
      fprintf(stderr, "q0 timeout delivered=%u ring=%u pending=%u\n",
              atomic_load_explicit(&e->delivered, memory_order_relaxed),
              rte_ring_count(e->ring), e->tx.exporter.packets);
      CHECK(false);
    }
    sched_yield();
  }
  CHECK(e->tx.exporter.packets == 0 && rte_ring_count(e->ring) == 0);
  endpoint_cleanup(e);
  atomic_store_explicit(&queue0_cleaned, true, memory_order_release);
}

int main(void) {
  cpu_set_t allowed;
  CHECK(sched_getaffinity(0, sizeof(allowed), &allowed) == 0);
  int found = 0;
  for (int cpu = 0; cpu < CPU_SETSIZE && found < 2; ++cpu)
    if (CPU_ISSET(cpu, &allowed))
      cpus[found++] = cpu;
  if (found < 2) {
    puts("SKIP: fewer than two allowed CPUs for real EAL workers");
    return 77;
  }
  char lcores[64], prefix[64];
  snprintf(lcores, sizeof(lcores), "--lcores=0@%d,1@%d", cpus[0], cpus[1]);
  snprintf(prefix, sizeof(prefix), "--file-prefix=ker-mq-%ld", (long)getpid());
  char *argv[] = {"ker-ethdev-multiqueue-test",
                  lcores,
                  prefix,
                  "--main-lcore=0",
                  "--no-huge",
                  "--no-pci",
                  "--no-shconf",
                  "--iova-mode=va",
                  "--no-telemetry",
                  "-m",
                  "256"};
  CHECK(rte_eal_init((int)(sizeof(argv) / sizeof(argv[0])), argv) >= 0);
  CHECK(rte_lcore_id() == 0 && rte_lcore_is_enabled(1));
  ips[0] = rte_cpu_to_be_32(0xc0000201U);
  ips[1] = rte_cpu_to_be_32(0xc0000202U);
  atomic_init(&start_queue1, false);
  atomic_init(&queue0_cleaned, false);
  for (unsigned int i = 0; i < 2; ++i) {
    endpoints[i].index = i;
    endpoints[i].cpu = cpus[i];
    atomic_init(&endpoints[i].ready, false);
    atomic_init(&endpoints[i].done, false);
    atomic_init(&endpoints[i].processed, false);
    atomic_init(&endpoints[i].delivered, 0);
    pools[i] = rte_pktmbuf_pool_create(i ? "mq_pool1" : "mq_pool0", POOL_SIZE,
                                       0, 0, 8192, rte_socket_id());
    CHECK(pools[i]);
    endpoints[i].ring = rte_ring_create(i ? "mq_ring1" : "mq_ring0", QUEUE_SIZE,
                                        rte_socket_id(), RING_F_EXACT_SZ);
    CHECK(endpoints[i].ring);
  }
  struct rte_ring *rxq[2] = {endpoints[0].ring, endpoints[1].ring};
  struct rte_ring *txq[2] = {endpoints[0].ring, endpoints[1].ring};
  int p = rte_eth_from_rings("ker_mq_ethdev", rxq, 2, txq, 2, rte_socket_id());
  CHECK(p >= 0);
  port_id = (uint16_t)p;
  struct rte_eth_conf conf = {0};
  conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
  CHECK(rte_eth_dev_configure(port_id, 2, 2, &conf) == 0);
  for (uint16_t q = 0; q < 2; ++q) {
    CHECK(rte_eth_rx_queue_setup(port_id, q, 64, rte_socket_id(), NULL,
                                 pools[q]) == 0);
    CHECK(rte_eth_tx_queue_setup(port_id, q, 64, rte_socket_id(), NULL) == 0);
  }
  CHECK(rte_eth_dev_start(port_id) == 0);
  CHECK(rte_eal_remote_launch(owner1, &endpoints[1], 1) == 0);
  uint64_t end = deadline_ns();
  wait_flag(&endpoints[1].ready, end, "queue 1 ready");
  unsigned int q1_packets = endpoints[1].tx.exporter.packets;
  size_t q1_bytes = endpoints[1].tx.exporter.bytes;
  unsigned int q1_completed = endpoints[1].tx.exporter.last_completed;
  int q1_error = endpoints[1].tx.exporter.last_error;
  int q1_cleanup_error = endpoints[1].tx.last_cleanup_error;
  struct rte_mbuf *q1_pending = endpoints[1].rx.pending;
  unsigned int q1_rx_completed = endpoints[1].rx.last_completed;
  unsigned int q1_rx_dropped = endpoints[1].rx.last_dropped;
  int q1_rx_error = endpoints[1].rx.last_error;
  unsigned int q1_ring_count = rte_ring_count(endpoints[1].ring);
  CHECK(ker_ethdev_tx_poll(&endpoints[1].tx, 1) == -EXDEV);
  CHECK(ker_ethdev_rx_poll(&endpoints[1].rx, 1) == -EXDEV);
  CHECK(endpoints[1].tx.exporter.packets == q1_packets &&
        endpoints[1].tx.exporter.bytes == q1_bytes &&
        endpoints[1].tx.exporter.last_completed == q1_completed &&
        endpoints[1].tx.exporter.last_error == q1_error &&
        endpoints[1].tx.last_cleanup_error == q1_cleanup_error &&
        endpoints[1].rx.pending == q1_pending &&
        endpoints[1].rx.last_completed == q1_rx_completed &&
        endpoints[1].rx.last_dropped == q1_rx_dropped &&
        endpoints[1].rx.last_error == q1_rx_error &&
        rte_ring_count(endpoints[1].ring) == q1_ring_count &&
        atomic_load_explicit(&endpoints[1].delivered, memory_order_acquire) ==
            0);
  main_owner_run(&endpoints[0]);
  wait_flag(&endpoints[1].done, deadline_ns(), "queue 1 cleanup");
  CHECK(rte_eal_wait_lcore(1) == 0);
  CHECK(ker_memory_shutdown() == 0);
  struct rte_eth_stats stats = {0};
  CHECK(rte_eth_stats_get(port_id, &stats) == 0);
  CHECK(stats.opackets == 2 * NMSG && stats.ipackets == 2 * NMSG);
  CHECK(rte_eth_dev_stop(port_id) == 0 && rte_eth_dev_close(port_id) == 0);
  for (unsigned int i = 0; i < 2; ++i) {
    CHECK(rte_mempool_in_use_count(pools[i]) == 0);
    rte_mempool_free(pools[i]);
    rte_ring_free(endpoints[i].ring);
  }
  CHECK(rte_eal_cleanup() == 0);
  puts("ethdev-multiqueue: OK");
  return 0;
}
