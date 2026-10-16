#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/ethdev-tx.h"
#include "runtime/memory.h"
#include "runtime/tcp-create.h"
#include "runtime/transport-receive.h"
#include "runtime/udp-create.h"
#include "runtime/worker.h"
#include <linux/if_ether.h>
#include <net/checksum.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define POOL_COUNT 255
#define HOLD_MAX (POOL_COUNT + 8)
#define PAYLOAD_SIZE 1300

struct side;
struct worker_arg {
  struct side *side;
};
struct side {
  const char *name;
  struct ker_packet_pool pool;
  struct ker_skb_context context;
  struct ker_eth_device device;
  struct ker_receive_runtime runtime;
  struct ker_transport_receiver receiver;
  struct ker_ethdev_tx tx;
  struct ker_ethdev_rx rx;
  struct ker_worker worker;
  struct worker_arg arg;
  unsigned int callbacks, drops, tcp, udp;
  uint8_t delivered[4];
  unsigned int delivered_count;
  uint8_t expected_ids[2];
  enum ker_transport_protocol expected_protocols[2];
  unsigned int expected_count;
  bool inject_pressure;
  bool release_pressure;
  struct rte_mbuf *held[HOLD_MAX];
  unsigned int held_count;
  __be32 source_ip, destination_ip;
};

static struct side a, b;
static uint16_t port_a, port_b;
static const uint8_t mac_a[6] = {2, 0x10, 0x11, 0x12, 0x13, 0x14};
static const uint8_t mac_b[6] = {2, 0x20, 0x21, 0x22, 0x23, 0x24};
static __be32 ip_a, ip_b;

static uint16_t oracle(const uint8_t *p, size_t n, uint32_t sum) {
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

static void verify_transport(const struct ker_transport_message *m) {
  const uint8_t *ip = m->ipv4.header;
  size_t l4len = m->ipv4.payload_length;
  uint8_t pseudo[12];
  memcpy(pseudo, ip + 12, 8);
  pseudo[8] = 0;
  pseudo[9] = (uint8_t)m->protocol;
  pseudo[10] = (uint8_t)(l4len >> 8);
  pseudo[11] = (uint8_t)l4len;
  uint32_t sum = 0;
  for (size_t i = 0; i < sizeof(pseudo); i += 2)
    sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
  const uint8_t *l4 = m->protocol == KER_TRANSPORT_TCP ? m->packet.tcp.header
                                                       : m->packet.udp.header;
  CHECK(oracle(l4, l4len, sum) == 0);
}

static int received(const struct ker_transport_message *m, void *arg) {
  struct side *s = arg;
  CHECK(s && m &&
        (m->protocol == KER_TRANSPORT_TCP || m->protocol == KER_TRANSPORT_UDP));
  verify_transport(m);
  CHECK(!memcmp(m->ipv4.header + 12, &s->destination_ip, 4));
  CHECK(!memcmp(m->ipv4.header + 16, &s->source_ip, 4));
  const uint8_t *payload;
  size_t length;
  if (m->protocol == KER_TRANSPORT_TCP) {
    s->tcp++;
    CHECK(m->packet.tcp.source_port == rte_cpu_to_be_16(41001));
    CHECK(m->packet.tcp.destination_port == rte_cpu_to_be_16(41002));
    CHECK(m->packet.tcp.sequence == 0x12345678 &&
          m->packet.tcp.flags == (KER_TCP_ACK | KER_TCP_PSH) &&
          m->packet.tcp.window == 4096);
    payload = m->packet.tcp.payload;
    length = m->packet.tcp.payload_length;
  } else {
    s->udp++;
    CHECK(m->packet.udp.source_port == rte_cpu_to_be_16(42001));
    CHECK(m->packet.udp.destination_port == rte_cpu_to_be_16(42002));
    payload = m->packet.udp.payload;
    length = m->packet.udp.payload_length;
  }
  CHECK(length == PAYLOAD_SIZE);
  unsigned int id = payload[0];
  CHECK(s->delivered_count < s->expected_count);
  CHECK(id == s->expected_ids[s->delivered_count]);
  CHECK(m->protocol == s->expected_protocols[s->delivered_count]);
  for (size_t i = 0; i < length; ++i)
    CHECK(payload[i] == (uint8_t)(id + i * 17U));
  CHECK(s->delivered_count < sizeof(s->delivered));
  s->delivered[s->delivered_count++] = (uint8_t)id;
  s->callbacks++;
  if (id == 0xee) {
    s->drops++;
    return NET_RX_DROP;
  }
  return NET_RX_SUCCESS;
}

static int side_tx(void *arg, unsigned int budget) {
  struct side *s = ((struct worker_arg *)arg)->side;
  return ker_ethdev_tx_poll(&s->tx, budget);
}

static int side_rx(void *arg, unsigned int budget) {
  struct side *s = ((struct worker_arg *)arg)->side;
  if (s->release_pressure && s->held_count) {
    rte_pktmbuf_free(s->held[--s->held_count]);
    s->held[s->held_count] = NULL;
    s->release_pressure = false;
  }
  if (s->inject_pressure) {
    s->inject_pressure = false;
    while (s->held_count < HOLD_MAX &&
           (s->held[s->held_count] = rte_pktmbuf_alloc(s->pool.mbufs)))
      s->held_count++;
  }
  return ker_ethdev_rx_poll(&s->rx, budget);
}

static void init_side(struct side *s, const char *name, const uint8_t mac[6],
                      uint16_t port, __be32 source, __be32 destination) {
  s->name = name;
  s->source_ip = source;
  s->destination_ip = destination;
  CHECK(ker_skb_context_init(&s->context, &s->pool, name) == 0);
  CHECK(ker_eth_device_init(&s->device, &s->context, name, 1, mac) == 0);
  CHECK(ker_receive_runtime_init(&s->runtime, &s->context) == 0);
  CHECK(ker_transport_receiver_register(&s->receiver, &s->runtime, &s->device,
                                        received, s) == 0);
  CHECK(ker_ethdev_rx_init(&s->rx, &s->device, &s->runtime, port, 0, 0) == 0);
  CHECK(ker_ethdev_tx_init_mode(&s->tx, &s->context, port, 0, 32, 1U << 20, 512,
                                KER_ETHDEV_TX_CHECKSUM_SOFTWARE) == 0);
  s->arg.side = s;
  struct ker_worker_config config = {
      .timer_budget = 1, .tx_budget = 8, .rx_budget = 8, .rx_margin = 0};
  struct ker_worker_ops ops = {.tx = side_tx, .rx = side_rx, .arg = &s->arg};
  CHECK(ker_worker_init(&s->worker, &s->pool, &config, &ops) == 0);
}

static struct sk_buff *make_partial(struct side *s, bool tcp, uint8_t id,
                                    const uint8_t source_mac[6],
                                    const uint8_t dest_mac[6], __be32 source,
                                    __be32 destination) {
  uint8_t data[PAYLOAD_SIZE];
  for (size_t i = 0; i < sizeof(data); ++i)
    data[i] = (uint8_t)(id + i * 17U);
  data[0] = id;
  struct sk_buff *skb = NULL;
  __be16 sport = rte_cpu_to_be_16(tcp ? 41001 : 42001);
  __be16 dport = rte_cpu_to_be_16(tcp ? 41002 : 42002);
  if (tcp)
    CHECK(ker_tcp_ipv4_create(
              &s->context, source_mac, dest_mac, source, destination, sport,
              dport, rte_cpu_to_be_32(0x12345678), 0, rte_cpu_to_be_16(4096),
              0x18, 64, data, sizeof(data), &skb) == 0);
  else
    CHECK(ker_udp_ipv4_create(&s->context, source_mac, dest_mac, source,
                              destination, sport, dport, 64, data, sizeof(data),
                              &skb) == 0);
  unsigned int start = ETH_HLEN + 20;
  unsigned int field = tcp ? 16 : 6;
  skb->data[start + field] = skb->data[start + field + 1] = 0;
  unsigned int l4len = skb->len - start;
  __wsum pseudo = csum_tcpudp_nofold(source, destination, l4len,
                                     tcp ? IPPROTO_TCP : IPPROTO_UDP, 0);
  __sum16 seed = (__sum16)~csum_fold(pseudo);
  memcpy(skb->data + start + field, &seed, sizeof(seed));
  skb->ip_summed = CHECKSUM_PARTIAL;
  skb->csum_start = (uint16_t)(skb_headroom(skb) + start);
  skb->csum_offset = (uint16_t)field;
  return skb;
}

static struct sk_buff *enqueue(struct side *s, bool tcp, uint8_t id,
                               const uint8_t srcmac[6], const uint8_t dstmac[6],
                               __be32 src, __be32 dst) {
  struct sk_buff *skb = make_partial(s, tcp, id, srcmac, dstmac, src, dst);
  struct sk_buff *queued = skb;
  CHECK(ker_tx_export_enqueue(&s->tx.exporter, &skb) == 0 && !skb);
  return queued;
}

static void poll_worker(struct side *s) {
  struct ker_worker_result result = {0};
  int rc = ker_worker_poll(&s->worker, s->worker.timers.now_ns, &result);
  CHECK(rc == 0 || rc == -EAGAIN || rc == -ENOMEM);
}

int main(void) {
  ker_test_eal_init();
  ip_a = rte_cpu_to_be_32(0xc0000201U);
  ip_b = rte_cpu_to_be_32(0xc6336402U);
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  struct rte_ring *ab =
      rte_ring_create("ker_duplex_ab", 1, rte_socket_id(), RING_F_EXACT_SZ);
  struct rte_ring *ba =
      rte_ring_create("ker_duplex_ba", 1, rte_socket_id(), RING_F_EXACT_SZ);
  CHECK(ab && ba);
  struct rte_ring *a_rx[] = {ba}, *a_tx[] = {ab};
  struct rte_ring *b_rx[] = {ab}, *b_tx[] = {ba};
  int pa =
      rte_eth_from_rings("ker_duplex_a", a_rx, 1, a_tx, 1, rte_socket_id());
  int pb =
      rte_eth_from_rings("ker_duplex_b", b_rx, 1, b_tx, 1, rte_socket_id());
  CHECK(pa >= 0 && pb >= 0 && pa != pb);
  port_a = (uint16_t)pa;
  port_b = (uint16_t)pb;
  struct rte_eth_conf conf = {0};
  conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
  CHECK(rte_eth_dev_configure(port_a, 1, 1, &conf) == 0);
  CHECK(rte_eth_dev_configure(port_b, 1, 1, &conf) == 0);

  a.name = "duplex_pool_a";
  b.name = "duplex_pool_b";
  CHECK(ker_packet_pool_init(&a.pool, a.name, POOL_COUNT, 0, 8192,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_packet_pool_init(&b.pool, b.name, POOL_COUNT, 0, 8192,
                             SOCKET_ID_ANY) == 0);
  CHECK(rte_eth_rx_queue_setup(port_a, 0, 64, rte_socket_id(), NULL,
                               a.pool.mbufs) == 0);
  CHECK(rte_eth_tx_queue_setup(port_a, 0, 64, rte_socket_id(), NULL) == 0);
  CHECK(rte_eth_rx_queue_setup(port_b, 0, 64, rte_socket_id(), NULL,
                               b.pool.mbufs) == 0);
  CHECK(rte_eth_tx_queue_setup(port_b, 0, 64, rte_socket_id(), NULL) == 0);
  CHECK(rte_eth_dev_start(port_a) == 0 && rte_eth_dev_start(port_b) == 0);

  init_side(&a, "duplex_a", mac_a, port_a, ip_a, ip_b);
  init_side(&b, "duplex_b", mac_b, port_b, ip_b, ip_a);
  CHECK(ker_eth_device_cleanup(&a.device) == -EBUSY);
  CHECK(ker_receive_runtime_cleanup(&a.runtime) == -EBUSY);
  a.expected_ids[0] = 0xee;
  a.expected_ids[1] = 4;
  a.expected_protocols[0] = KER_TRANSPORT_TCP;
  a.expected_protocols[1] = KER_TRANSPORT_UDP;
  a.expected_count = 2;
  b.expected_ids[0] = 1;
  b.expected_ids[1] = 2;
  b.expected_protocols[0] = KER_TRANSPORT_TCP;
  b.expected_protocols[1] = KER_TRANSPORT_UDP;
  b.expected_count = 2;
  (void)enqueue(&a, true, 1, mac_a, mac_b, ip_a, ip_b);
  struct sk_buff *backpressured =
      enqueue(&a, false, 2, mac_a, mac_b, ip_a, ip_b);
  (void)enqueue(&b, true, 0xee, mac_b, mac_a, ip_b, ip_a);
  (void)enqueue(&b, false, 4, mac_b, mac_a, ip_b, ip_a);
  uint8_t preserved[ETH_HLEN + 20 + 8 + PAYLOAD_SIZE];
  CHECK(backpressured && backpressured->len == sizeof(preserved));
  memcpy(preserved, backpressured->data, sizeof(preserved));
  uint8_t checksum_state = backpressured->ip_summed;
  uint16_t checksum_start = backpressured->csum_start;
  uint16_t checksum_offset = backpressured->csum_offset;

  /* The one-entry actual PMD backing ring forces TX backpressure. On B's
   * first worker RX callback, exhaust B's distinct destination pool after
   * worker admission but before the adapter copies the already-received
   * chain. The adapter must retain that chain while the next frame remains
   * in the ring. */
  poll_worker(&a);
  CHECK(a.tx.exporter.packets == 1 && rte_ring_count(ab) == 1);
  CHECK(a.tx.exporter.last_error == -EAGAIN);
  CHECK(backpressured->len == sizeof(preserved) &&
        backpressured->ip_summed == checksum_state &&
        backpressured->csum_start == checksum_start &&
        backpressured->csum_offset == checksum_offset &&
        !memcmp(backpressured->data, preserved, sizeof(preserved)));
  b.inject_pressure = true;
  poll_worker(&b);
  CHECK(b.rx.pending && b.rx.last_error == -ENOMEM && rte_ring_count(ab) == 0);
  CHECK(b.rx.pending->pkt_len > 512 && b.rx.pending->nb_segs > 1);
  CHECK(b.rx.pending->ol_flags == 0 && b.rx.pending->tx_offload == 0);
  CHECK(ker_ethdev_rx_cleanup(&b.rx) == -EBUSY);
  CHECK(a.tx.exporter.packets == 1);
  CHECK(b.callbacks == 0);

  poll_worker(&a);
  CHECK(a.tx.exporter.packets == 0 && rte_ring_count(ab) == 1);
  CHECK(a.callbacks == 1 &&
        a.drops == 1); /* B's first packet was consumed as NET_RX_DROP. */

  b.release_pressure = true;
  poll_worker(&b);
  CHECK(!b.rx.pending && rte_ring_count(ab) == 1);
  CHECK(b.callbacks == 1 && b.tcp == 1 && b.udp == 0);
  CHECK(a.callbacks == 1 && a.drops == 1);

  poll_worker(&b);
  CHECK(b.callbacks == 2 && b.tcp == 1 && b.udp == 1 &&
        rte_ring_count(ab) == 0);

  poll_worker(&a);
  CHECK(a.callbacks == 2 && a.drops == 1 && a.tcp == 1 && a.udp == 1);
  CHECK(b.delivered_count == 2 && b.delivered[0] == 1 && b.delivered[1] == 2);
  CHECK(a.delivered_count == 2 && a.delivered[0] == 0xee &&
        a.delivered[1] == 4);
  CHECK(a.tx.exporter.packets == 0 && b.tx.exporter.packets == 0);
  CHECK(rte_ring_count(ab) == 0 && rte_ring_count(ba) == 0);

  struct rte_eth_stats as = {0}, bs = {0};
  CHECK(rte_eth_stats_get(port_a, &as) == 0 &&
        rte_eth_stats_get(port_b, &bs) == 0);
  CHECK(as.opackets == 2 && as.ipackets == 2 && bs.opackets == 2 &&
        bs.ipackets == 2);
  CHECK(a.tx.exporter.ethdev_refs == 1 && b.tx.exporter.ethdev_refs == 1);
  CHECK(ker_worker_cleanup(&a.worker) == 0 &&
        ker_worker_cleanup(&b.worker) == 0);
  CHECK(ker_ethdev_tx_cleanup(&a.tx) == 0 && ker_ethdev_tx_cleanup(&b.tx) == 0);
  CHECK(ker_ethdev_rx_cleanup(&a.rx) == 0 && ker_ethdev_rx_cleanup(&b.rx) == 0);
  CHECK(ker_transport_receiver_unregister(&a.receiver) == 0);
  CHECK(ker_transport_receiver_unregister(&b.receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&a.runtime) == 0);
  CHECK(ker_receive_runtime_cleanup(&b.runtime) == 0);
  CHECK(ker_eth_device_cleanup(&a.device) == 0 &&
        ker_eth_device_cleanup(&b.device) == 0);
  CHECK(ker_skb_context_cleanup(&a.context) == 0 &&
        ker_skb_context_cleanup(&b.context) == 0);
  while (b.held_count)
    rte_pktmbuf_free(b.held[--b.held_count]);
  CHECK(ker_packet_pool_cleanup(&a.pool) == 0 &&
        ker_packet_pool_cleanup(&b.pool) == 0);
  CHECK(rte_eth_dev_stop(port_a) == 0 && rte_eth_dev_stop(port_b) == 0);
  CHECK(rte_eth_dev_close(port_a) == 0 && rte_eth_dev_close(port_b) == 0);
  rte_ring_free(ab);
  rte_ring_free(ba);
  CHECK(ker_memory_shutdown() == 0);
  puts("ethdev-duplex: OK");
  return 0;
}
