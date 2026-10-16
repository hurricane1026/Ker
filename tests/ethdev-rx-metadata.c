#include "check.h"
#include "eal.h"
#include "runtime/ethdev-rx.h"
#include "runtime/memory.h"
#include "runtime/transport-receive.h"
#include "runtime/worker.h"
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <string.h>

#define PACKETS 63
#define FRAME_MAX 96
#define PAYLOAD_LEN 5
static struct ker_packet_pool source_pool, destination_pool;
static struct ker_skb_context context;
static struct ker_eth_device device;
static struct ker_receive_runtime runtime;
static struct ker_transport_receiver receiver;
static struct ker_ethdev_rx input;
static struct ker_worker worker;
static struct rte_ring *rx_ring;
static unsigned int callbacks, callback_ids[16], expected_ids[16],
    expected_count;
static enum ker_transport_protocol expected_protocols[16];
static const uint16_t tcp_source = 0x1234, tcp_destination = 0x5678;
static const uint16_t udp_source = 0x1235, udp_destination = 0x5679;

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

static uint16_t transport_checksum(const uint8_t *ip, const uint8_t *l4,
                                   size_t length, uint8_t protocol) {
  uint32_t sum = 0;
  for (unsigned int i = 12; i < 20; i += 2)
    sum += ((uint32_t)ip[i] << 8) | ip[i + 1];
  sum += protocol + (uint32_t)length;
  return checksum(l4, length, sum);
}

static size_t make_frame(uint8_t *frame, bool tcp, unsigned int id) {
  const size_t l4len = (tcp ? 20U : 8U) + PAYLOAD_LEN;
  const size_t iplen = 20 + l4len;
  const size_t length = ETH_HLEN + iplen;
  memset(frame, 0, length);
  frame[0] = 2;
  frame[6] = 4;
  frame[12] = 0x08;
  frame[13] = 0x00;
  uint8_t *ip = frame + ETH_HLEN;
  ip[0] = 0x45;
  ip[2] = (uint8_t)(iplen >> 8);
  ip[3] = (uint8_t)iplen;
  ip[8] = 64;
  ip[9] = tcp ? IPPROTO_TCP : IPPROTO_UDP;
  ip[12] = 192;
  ip[13] = 0;
  ip[14] = 2;
  ip[15] = 1;
  ip[16] = 198;
  ip[17] = 51;
  ip[18] = 100;
  ip[19] = 2;
  uint8_t *l4 = ip + 20;
  uint16_t sport = tcp ? tcp_source : udp_source;
  uint16_t dport = tcp ? tcp_destination : udp_destination;
  l4[0] = (uint8_t)(sport >> 8);
  l4[1] = (uint8_t)sport;
  l4[2] = (uint8_t)(dport >> 8);
  l4[3] = (uint8_t)dport;
  uint8_t data[PAYLOAD_LEN];
  for (size_t i = 0; i < sizeof(data); ++i)
    data[i] = (uint8_t)(id + i * 13U);
  if (tcp) {
    l4[4] = (uint8_t)(id >> 24);
    l4[5] = (uint8_t)(id >> 16);
    l4[6] = (uint8_t)(id >> 8);
    l4[7] = (uint8_t)id;
    l4[12] = 0x50;
    l4[13] = 0x18;
    l4[14] = 0x10;
    l4[15] = 0;
    memcpy(l4 + 20, data, sizeof(data));
    uint16_t sum = transport_checksum(ip, l4, l4len, IPPROTO_TCP);
    l4[16] = (uint8_t)(sum >> 8);
    l4[17] = (uint8_t)sum;
  } else {
    l4[4] = (uint8_t)(l4len >> 8);
    l4[5] = (uint8_t)l4len;
    memcpy(l4 + 8, data, sizeof(data));
    uint16_t sum = transport_checksum(ip, l4, l4len, IPPROTO_UDP);
    if (!sum)
      sum = 0xffff; /* A computed UDP zero is mangled on wire. */
    l4[6] = (uint8_t)(sum >> 8);
    l4[7] = (uint8_t)sum;
  }
  uint16_t ip_sum = checksum(ip, 20, 0);
  ip[10] = (uint8_t)(ip_sum >> 8);
  ip[11] = (uint8_t)ip_sum;
  return length;
}

static int receive_message(const struct ker_transport_message *m, void *arg) {
  CHECK(arg == &receiver && callbacks < expected_count);
  unsigned int id = expected_ids[callbacks];
  enum ker_transport_protocol protocol = expected_protocols[callbacks];
  CHECK(m->protocol == protocol);
  CHECK(m->ipv4.header[12] == 192 && m->ipv4.header[15] == 1 &&
        m->ipv4.header[16] == 198 && m->ipv4.header[19] == 2);
  CHECK(checksum(m->ipv4.header, m->ipv4.header_length, 0) == 0);
  const uint8_t *data;
  size_t length;
  const uint8_t *l4;
  if (protocol == KER_TRANSPORT_TCP) {
    CHECK(m->packet.tcp.source_port == rte_cpu_to_be_16(tcp_source) &&
          m->packet.tcp.destination_port == rte_cpu_to_be_16(tcp_destination));
    CHECK(m->packet.tcp.sequence == id && m->packet.tcp.flags == 0x18);
    data = m->packet.tcp.payload;
    length = m->packet.tcp.payload_length;
    l4 = m->packet.tcp.header;
  } else {
    CHECK(m->packet.udp.source_port == rte_cpu_to_be_16(udp_source) &&
          m->packet.udp.destination_port == rte_cpu_to_be_16(udp_destination));
    data = m->packet.udp.payload;
    length = m->packet.udp.payload_length;
    l4 = m->packet.udp.header;
  }
  CHECK(transport_checksum(m->ipv4.header, l4, m->ipv4.payload_length,
                           (uint8_t)protocol) == 0);
  CHECK(length == PAYLOAD_LEN);
  for (size_t i = 0; i < length; ++i)
    CHECK(data[i] == (uint8_t)(id + i * 13U));
  callback_ids[callbacks++] = id;
  return NET_RX_SUCCESS;
}

static int rx_callback(void *arg, unsigned int budget) {
  CHECK(arg == &input);
  return ker_ethdev_rx_poll(&input, budget);
}

static void expect(unsigned int id, enum ker_transport_protocol protocol) {
  CHECK(expected_count < sizeof(expected_ids) / sizeof(expected_ids[0]));
  expected_ids[expected_count] = id;
  expected_protocols[expected_count++] = protocol;
}

static void inject(bool tcp, unsigned int id, uint64_t flags, int corrupt_ip,
                   int corrupt_l4, bool split_checksum) {
  uint8_t frame[FRAME_MAX];
  size_t length = make_frame(frame, tcp, id);
  if (corrupt_ip >= 0)
    frame[ETH_HLEN + (unsigned int)corrupt_ip] ^= 1;
  if (corrupt_l4 >= 0)
    frame[ETH_HLEN + 20 + (unsigned int)corrupt_l4] ^= 1;
  struct rte_mbuf *packet = rte_pktmbuf_alloc(source_pool.mbufs);
  CHECK(packet);
  if (split_checksum) {
    size_t checksum_end = ETH_HLEN + 20 + (tcp ? 17U : 7U);
    uint8_t *head =
        (uint8_t *)rte_pktmbuf_append(packet, (uint16_t)checksum_end);
    struct rte_mbuf *tail = rte_pktmbuf_alloc(source_pool.mbufs);
    CHECK(head && tail);
    uint8_t *rest =
        (uint8_t *)rte_pktmbuf_append(tail, (uint16_t)(length - checksum_end));
    CHECK(rest);
    memcpy(head, frame, checksum_end);
    memcpy(rest, frame + checksum_end, length - checksum_end);
    CHECK(rte_pktmbuf_chain(packet, tail) == 0);
  } else {
    uint8_t *data = (uint8_t *)rte_pktmbuf_append(packet, (uint16_t)length);
    CHECK(data);
    memcpy(data, frame, length);
  }
  packet->ol_flags |= flags;
  CHECK(rte_ring_enqueue(rx_ring, packet) == 0);
}

static void poll_one(int expected_error, int validation_error,
                     unsigned int dropped) {
  struct ker_worker_result progress = {0};
  CHECK(ker_worker_poll(&worker, worker.timers.now_ns, &progress) == 0);
  CHECK(progress.rx == 1 && input.last_completed == 1 &&
        input.last_dropped == dropped && input.last_error == expected_error);
  unsigned int available;
  CHECK(ker_packet_pool_available(&source_pool, &available) == 0 &&
        available == PACKETS - rte_ring_count(rx_ring));
  CHECK(ker_packet_pool_available(&destination_pool, &available) == 0 &&
        available == PACKETS);
  CHECK(receiver.validation_error == validation_error);
}

int main(void) {
  ker_test_eal_init();
  CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
  CHECK(ker_packet_pool_init(&source_pool, "rxmeta_src", PACKETS, 0, 2048,
                             SOCKET_ID_ANY) == 0);
  CHECK(ker_packet_pool_init(&destination_pool, "rxmeta_dst", PACKETS, 0, 2048,
                             SOCKET_ID_ANY) == 0);
  rx_ring =
      rte_ring_create("ker_rxmeta_ring", 16, rte_socket_id(), RING_F_EXACT_SZ);
  struct rte_ring *tx_ring =
      rte_ring_create("ker_rxmeta_tx", 16, rte_socket_id(), RING_F_EXACT_SZ);
  CHECK(rx_ring && tx_ring);
  struct rte_ring *rxq[] = {rx_ring}, *txq[] = {tx_ring};
  int port =
      rte_eth_from_rings("ker_rxmeta_port", rxq, 1, txq, 1, rte_socket_id());
  CHECK(port >= 0);
  CHECK(rte_eth_dev_configure((uint16_t)port, 1, 1,
                              &(struct rte_eth_conf){0}) == 0);
  CHECK(rte_eth_rx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL,
                               source_pool.mbufs) == 0);
  CHECK(rte_eth_tx_queue_setup((uint16_t)port, 0, 64, rte_socket_id(), NULL) ==
        0);
  CHECK(rte_eth_dev_start((uint16_t)port) == 0);
  CHECK(ker_skb_context_init(&context, &destination_pool, "rxmeta_context") ==
        0);
  static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
  CHECK(ker_eth_device_init(&device, &context, "rxmeta0", 1, mac) == 0);
  CHECK(ker_receive_runtime_init(&runtime, &context) == 0);
  CHECK(ker_transport_receiver_register(&receiver, &runtime, &device,
                                        receive_message, &receiver) == 0);
  CHECK(ker_ethdev_rx_init(&input, &device, &runtime, (uint16_t)port, 0, 0) ==
        0);
  struct ker_worker_config config = {.timer_budget = 1, .rx_budget = 1};
  struct ker_worker_ops ops = {.rx = rx_callback, .arg = &input};
  CHECK(ker_worker_init(&worker, &destination_pool, &config, &ops) == 0);

  /* Good, bad and unknown checksum hints never replace software wire checks. */
  expect(1, KER_TRANSPORT_TCP);
  inject(true, 1, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD, -1,
         -1, true);
  poll_one(0, 0, 0);
  CHECK(callbacks == 1 && callback_ids[0] == 1);
  inject(true, 2, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD, 10,
         -1, false);
  expect(3, KER_TRANSPORT_TCP);
  inject(true, 3, 0, -1, -1, false); /* Valid successor already queued. */
  poll_one(0, -EBADMSG, 1);
  CHECK(callbacks == 1 && rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 2 && callback_ids[1] == 3);
  expect(4, KER_TRANSPORT_TCP);
  inject(true, 4, RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD, -1,
         -1, false);
  expect(5, KER_TRANSPORT_UDP);
  inject(false, 5, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
         -1, -1, false);
  poll_one(0, 0, 0); /* BAD hint does not reject valid TCP wire bytes. */
  CHECK(callbacks == 3 && callback_ids[2] == 4 && rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 4 && callback_ids[3] == 5);

  inject(false, 6, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
         -1, 6, false);
  expect(7, KER_TRANSPORT_TCP);
  inject(true, 7, 0, -1, -1, false);
  poll_one(0, -EBADMSG, 1);
  CHECK(callbacks == 4 && rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 5 && callback_ids[4] == 7);

  inject(true, 8, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD, -1,
         16, false);
  expect(9, KER_TRANSPORT_UDP);
  inject(false, 9, 0, -1, -1, false);
  poll_one(0, -EBADMSG, 1);
  CHECK(callbacks == 5 && rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 6 && callback_ids[5] == 9);

  expect(10, KER_TRANSPORT_UDP);
  inject(false, 10, RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD, -1,
         -1, true);
  poll_one(0, 0,
           0); /* BAD hint is ignored; valid bytes pass software checks. */
  CHECK(callbacks == 7 && callback_ids[6] == 10);

  inject(true, 11, RTE_MBUF_F_RX_IP_CKSUM_NONE, -1, -1, false);
  expect(12, KER_TRANSPORT_UDP);
  inject(false, 12, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
         -1, -1, false);
  poll_one(-ENOTSUP, 0, 1);
  CHECK(rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 8 && callback_ids[7] == 12);

  inject(false, 13, RTE_MBUF_F_RX_L4_CKSUM_NONE, -1, -1, false);
  expect(14, KER_TRANSPORT_UDP);
  inject(false, 14, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
         -1, -1, false);
  poll_one(-ENOTSUP, 0, 1);
  CHECK(rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 9 && callback_ids[8] == 14);

  inject(false, 15, RTE_MBUF_F_RX_VLAN_STRIPPED, -1, -1, false);
  expect(16, KER_TRANSPORT_TCP);
  inject(true, 16, RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
         -1, -1, false);
  poll_one(-ENOTSUP, 0, 1);
  CHECK(rte_ring_count(rx_ring) == 1);
  poll_one(0, 0, 0);
  CHECK(callbacks == 10 && callback_ids[9] == 16 &&
        rte_ring_count(rx_ring) == 0);

  const uint64_t transformed[] = {RTE_MBUF_F_RX_LRO, RTE_MBUF_F_RX_SEC_OFFLOAD,
                                  RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED};
  for (size_t i = 0; i < sizeof(transformed) / sizeof(transformed[0]); ++i) {
    unsigned int bad_id = 17 + (unsigned int)i * 2;
    unsigned int good_id = bad_id + 1;
    inject(true, bad_id, transformed[i], -1, -1, false);
    expect(good_id, KER_TRANSPORT_TCP);
    inject(true, good_id,
           RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD, -1, -1,
           false);
    poll_one(-ENOTSUP, 0, 1);
    CHECK(rte_ring_count(rx_ring) == 1);
    poll_one(0, 0, 0);
    CHECK(callbacks == 11 + i && callback_ids[10 + i] == good_id);
  }
  CHECK(rte_ring_count(rx_ring) == 0);

  CHECK(ker_worker_cleanup(&worker) == 0);
  CHECK(ker_ethdev_rx_cleanup(&input) == 0);
  CHECK(ker_transport_receiver_unregister(&receiver) == 0);
  CHECK(ker_receive_runtime_cleanup(&runtime) == 0);
  CHECK(ker_eth_device_cleanup(&device) == 0);
  CHECK(ker_skb_context_cleanup(&context) == 0);
  unsigned int available;
  CHECK(ker_packet_pool_available(&source_pool, &available) == 0 &&
        available == PACKETS);
  CHECK(ker_packet_pool_available(&destination_pool, &available) == 0 &&
        available == PACKETS);
  CHECK(rte_eth_dev_stop((uint16_t)port) == 0);
  CHECK(rte_eth_dev_close((uint16_t)port) == 0);
  rte_ring_free(rx_ring);
  rte_ring_free(tx_ring);
  CHECK(ker_packet_pool_cleanup(&destination_pool) == 0);
  CHECK(ker_packet_pool_cleanup(&source_pool) == 0);
  CHECK(ker_memory_shutdown() == 0);
  CHECK(rte_eal_cleanup() == 0);
  return 0;
}
